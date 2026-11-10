//! The QUIC listener bounds authenticated sessions and dispatches one operation per connection.

use super::{
    client::ConnectionGuard,
    tls::Identity,
    wire::{self, Operation, Request, Response},
};
use crate::{
    datagram::{DirectDatagram, PACKET_CAPACITY},
    server::Config,
};
use anyhow::{Context, ensure};
use fast_socks5::{ReplyError, util::target_addr::TargetAddr};
use quinn::{Connection, Endpoint};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, copy_bidirectional, join},
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;

/// A tunnel server owns its authenticated QUIC listener and resource limits.
pub struct TunnelServer {
    endpoint: Endpoint,
    config: Config,
    password: Option<super::auth::Password>,
}

/// Tunnel server operations supervise connections without exposing unauthenticated egress.
impl TunnelServer {
    /// Bind a QUIC endpoint that requires a trusted client certificate.
    pub fn bind(listen: SocketAddr, identity: Identity, config: Config) -> anyhow::Result<Self> {
        Self::bind_with_password(listen, identity, config, None)
    }

    /// Bind a TLS server that requires a password, trusted client certificates, or both.
    pub fn bind_with_password(
        listen: SocketAddr,
        identity: Identity,
        config: Config,
        password: Option<super::auth::Password>,
    ) -> anyhow::Result<Self> {
        ensure!(
            password.is_some() || identity.verifies_clients(),
            "configure a password or client CA"
        );
        Ok(Self {
            endpoint: super::socket::server_endpoint(listen, identity.server()?)?,
            config,
            password,
        })
    }

    /// Return the listener address selected by the operating system.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Accept bounded handshakes until cancellation and release all active connections.
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let mut tasks = JoinSet::new();
        tracing::info!(listen = %self.local_addr()?, "authenticated QUIC tunnel listening");
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result { tracing::warn!(%error, "tunnel task failed"); }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    if tasks.len() >= self.config.max_connections.get() { incoming.refuse(); continue; }
                    let config = self.config.clone();
                    let password = self.password.clone();
                    tasks.spawn(async move {
                        let result = async {
                            let connection = timeout(config.handshake_timeout, incoming).await
                                .context("QUIC handshake deadline exceeded")?
                                .context("QUIC TLS handshake failed")?;
                            tracing::debug!(peer = %connection.remote_address(), "QUIC TLS handshake completed");
                            serve(connection, config, password.as_ref()).await
                        }.await;
                        if let Err(error) = result { tracing::debug!(error = %format_args!("{error:#}"), "tunnel session ended"); }
                    });
                }
            }
        }
        self.endpoint.close(0u8.into(), b"server shutdown");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        timeout(self.config.shutdown_grace, self.endpoint.wait_idle())
            .await
            .ok();
        Ok(())
    }
}

/// Validate the initial request before establishing its requested outbound transport.
async fn serve(
    connection: Connection,
    config: Config,
    password: Option<&super::auth::Password>,
) -> anyhow::Result<()> {
    let guard = ConnectionGuard(connection);
    let (send, receive) = timeout(config.handshake_timeout, guard.0.accept_bi()).await??;
    let mut io = join(receive, send);
    let request: Request = timeout(config.handshake_timeout, wire::read(&mut io)).await??;
    request.validate()?;
    let authenticated = match password {
        Some(password) => password.verify(&guard.0, &request),
        None if request.auth.is_none() => Ok(()),
        None => Err(anyhow::anyhow!("password authentication is not configured")),
    };
    if let Err(error) = authenticated {
        guard.0.close(16u8.into(), b"authentication failed");
        return Err(error);
    }
    tracing::debug!(peer = %guard.0.remote_address(), "proxy client authenticated");
    match request.operation {
        Operation::Tcp { host, port } => {
            let target = match host.parse() {
                Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
                Err(_) => TargetAddr::Domain(host, port),
            };
            relay_tcp(&mut io, target, &config).await?;
            // The client closes only after consuming the response stream and forwarding its bytes.
            timeout(config.shutdown_grace, guard.0.closed())
                .await
                .context("client did not close the drained TCP tunnel")?;
            Ok(())
        }
        Operation::Udp => relay_udp(&guard.0, &mut io, &config).await,
    }
}

/// Report outbound connection status before forwarding a reliable TCP byte stream.
async fn relay_tcp(
    io: &mut tokio::io::Join<quinn::RecvStream, quinn::SendStream>,
    target: TargetAddr,
    config: &Config,
) -> anyhow::Result<()> {
    let mut outbound = match crate::outbound::connect_with(
        &config.resolver,
        &target,
        config.connect_timeout,
    )
    .await
    {
        Ok(socket) => socket,
        Err(error) => {
            let status = if error.kind() == std::io::ErrorKind::ConnectionRefused {
                ReplyError::ConnectionRefused
            } else {
                ReplyError::HostUnreachable
            };
            wire::write(
                io,
                &Response {
                    status: status as u8,
                    bound: "0.0.0.0:0".parse()?,
                },
            )
            .await?;
            io.writer_mut().finish()?;
            super::finish::acknowledged(io.writer(), Duration::from_secs(5)).await?;
            return Err(error.into());
        }
    };
    wire::write(
        io,
        &Response {
            status: 0,
            bound: outbound.local_addr()?,
        },
    )
    .await?;
    let (sent, received) = copy_bidirectional(io, &mut outbound).await?;
    super::finish::acknowledged(io.writer(), Duration::from_secs(5)).await?;
    tracing::debug!(sent, received, "tunneled TCP relay completed");
    Ok(())
}

/// Relay independent QUIC datagrams until their control stream closes or expires.
async fn relay_udp(
    connection: &Connection,
    control: &mut tokio::io::Join<quinn::RecvStream, quinn::SendStream>,
    config: &Config,
) -> anyhow::Result<()> {
    ensure!(
        connection.max_datagram_size().is_some(),
        "peer does not support QUIC datagrams"
    );
    let mut outbound = DirectDatagram::bind_with(config.resolver.clone()).await?;
    wire::write(
        control,
        &Response {
            status: 0,
            bound: "0.0.0.0:0".parse()?,
        },
    )
    .await?;
    let mut buffer = vec![0; PACKET_CAPACITY];
    let mut control_byte = [0];
    let mut expires = Instant::now() + config.udp_idle_timeout;
    loop {
        let activity = tokio::select! {
            biased;
            _ = control.read(&mut control_byte) => return Ok(()),
            _ = sleep_until(expires) => return Ok(()),
            packet = connection.read_datagram() => outbound.send(&packet?, config.connect_timeout).await.record("remote outbound"),
            response = outbound.receive(&mut buffer) => {
                let response = response?;
                crate::datagram::send_quic(connection, response)?.record("remote QUIC response")
            }
        };
        if activity {
            expires = Instant::now() + config.udp_idle_timeout;
        }
    }
}
