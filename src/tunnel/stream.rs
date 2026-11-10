//! TCP/TLS carries the same authenticated operations with length-framed UDP envelopes.

use super::{
    Session,
    auth::Password,
    framed,
    session::SessionIo,
    tls::Identity,
    wire::{self, Operation, Request, Response},
};
use crate::{datagram::DirectDatagram, server::Config};
use anyhow::{Context, ensure};
use fast_socks5::{ReplyError, util::target_addr::TargetAddr};
use futures_util::{SinkExt, StreamExt};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

/// A distinct ALPN prevents interpreting ordinary HTTPS or QUIC control streams as a TLS carrier.
pub(super) const ALPN: &[u8] = b"zion-tls/1";

/// A TLS client stores verified identity policy and bounded address candidates without opening UDP sockets.
#[derive(Debug)]
pub(super) struct TlsClient {
    addresses: Vec<SocketAddr>,
    name: String,
    config: Arc<rustls::ClientConfig>,
    interface: Option<String>,
    password: Option<Password>,
}

/// TLS client operations authenticate only the selected verified connection before requesting egress.
impl TlsClient {
    /// Prepare TLS policy without contacting a server or weakening the selected interface.
    pub(super) fn new(
        addresses: Vec<SocketAddr>,
        name: String,
        identity: Identity,
        interface: Option<&str>,
        password: Option<Password>,
    ) -> anyhow::Result<Self> {
        let addresses = crate::network::candidates(addresses);
        ensure!(!addresses.is_empty(), "server DNS returned no addresses");
        rustls::pki_types::ServerName::try_from(name.clone())
            .context("invalid server certificate name")?;
        Ok(Self {
            addresses,
            name,
            config: Arc::new(identity.client_tls(ALPN)?),
            interface: interface.map(str::to_owned),
            password,
        })
    }

    /// Race verified TCP/TLS handshakes, then send the operation exactly once on the winning stream.
    pub(super) async fn open(
        &self,
        mut request: Request,
        deadline: Duration,
    ) -> anyhow::Result<Session> {
        timeout(deadline, async {
            request.validate()?;
            let name = self.name.clone();
            let config = self.config.clone();
            let interface = self.interface.clone();
            let mut stream = crate::network::race(self.addresses.clone(), move |address| {
                let name = name.clone();
                let config = config.clone();
                let interface = interface.clone();
                async move {
                    let stream = super::socket::client_tcp(address, interface.as_deref()).await?;
                    let name = rustls::pki_types::ServerName::try_from(name)
                        .map_err(std::io::Error::other)?;
                    let stream = TlsConnector::from(config).connect(name, stream).await?;
                    if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
                        return Err(std::io::Error::other("TLS carrier ALPN mismatch"));
                    }
                    Ok(stream)
                }
            })
            .await
            .context("all TCP/TLS handshake attempts failed")?;
            if let Some(password) = &self.password {
                let context = serde_json::to_vec(&(request.version, &request.operation))?;
                let binding = stream.get_ref().1.export_keying_material(
                    [0u8; 32],
                    b"EXPORTER-zion-password-v1",
                    Some(&context),
                )?;
                request.auth = Some(password.sign_binding(&binding));
            }
            wire::write(&mut stream, &request).await?;
            let response: Response = wire::read(&mut stream)
                .await
                .context("reading authenticated TLS response")?;
            if response.status != 0 {
                return Err(ReplyError::from_u8(response.status).into());
            }
            let (io, datagrams) = match request.operation {
                Operation::Tcp { .. } => (SessionIo::Tls(Box::new(stream)), None),
                Operation::Udp => (
                    SessionIo::Datagrams,
                    Some(framed::Datagrams::start(stream, deadline)),
                ),
            };
            Ok(Session {
                guard: None,
                io,
                bound: response.bound,
                datagrams,
            })
        })
        .await
        .context("TCP/TLS establishment deadline exceeded")?
    }
}

/// A TLS listener supervises bounded handshakes and authenticated sessions on one TCP port.
pub struct TlsServer {
    listener: std::net::TcpListener,
    acceptor: TlsAcceptor,
    config: Config,
    password: Option<Password>,
    budget: Arc<tokio::sync::Semaphore>,
}

/// TLS listener operations preserve the same client-authentication requirements as QUIC.
impl TlsServer {
    /// Bind a nonblocking TCP listener while requiring a password, client CA, or both.
    pub fn bind(
        listen: SocketAddr,
        identity: Identity,
        config: Config,
        password: Option<Password>,
    ) -> anyhow::Result<Self> {
        let budget = Arc::new(tokio::sync::Semaphore::new(config.max_connections.get()));
        Self::bind_budget(listen, identity, config, password, budget)
    }

    /// Share one admission budget when both TCP and UDP listeners serve the same configuration.
    pub(super) fn bind_budget(
        listen: SocketAddr,
        identity: Identity,
        config: Config,
        password: Option<Password>,
        budget: Arc<tokio::sync::Semaphore>,
    ) -> anyhow::Result<Self> {
        ensure!(
            password.is_some() || identity.verifies_clients(),
            "configure a password or client CA"
        );
        Ok(Self {
            listener: super::socket::tcp_listener(listen)?,
            acceptor: TlsAcceptor::from(Arc::new(identity.server_tls(ALPN)?)),
            config,
            password,
            budget,
        })
    }

    /// Return the actual bound TCP address for configuration and test fixtures.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Limit pending handshakes and active sessions together and join all tasks on shutdown.
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let listener = TcpListener::from_std(self.listener)?;
        let mut tasks = JoinSet::new();
        tracing::info!(listen = %listener.local_addr()?, "authenticated TCP/TLS tunnel listening");
        let result = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok(Err(error))) = result { tracing::debug!(error = %format_args!("{error:#}"), "TLS session ended"); }
                }
                accepted = listener.accept() => {
                    let (stream, _) = match accepted { Ok(stream) => stream, Err(error) => break Err(error.into()) };
                    if tasks.len() >= self.config.max_connections.get() { drop(stream); continue; }
                    let Ok(permit) = self.budget.clone().try_acquire_owned() else { drop(stream); continue; };
                    let acceptor = self.acceptor.clone(); let config = self.config.clone(); let password = self.password.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        super::socket::configure_tcp(&stream)?;
                        let stream = timeout(config.handshake_timeout, acceptor.accept(stream)).await.context("TLS handshake timed out")??;
                        serve(stream, config, password).await
                    });
                }
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}

/// Verify the bounded request and connection-bound proof before opening any destination socket.
async fn serve(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    config: Config,
    password: Option<Password>,
) -> anyhow::Result<()> {
    ensure!(
        stream.get_ref().1.alpn_protocol() == Some(ALPN),
        "TLS carrier ALPN mismatch"
    );
    let request: Request = timeout(config.handshake_timeout, wire::read(&mut stream)).await??;
    request.validate()?;
    if let Some(password) = password {
        let context = serde_json::to_vec(&(request.version, &request.operation))?;
        let binding = stream.get_ref().1.export_keying_material(
            [0u8; 32],
            b"EXPORTER-zion-password-v1",
            Some(&context),
        )?;
        password.verify_binding(&binding, &request)?;
    } else {
        ensure!(
            request.auth.is_none(),
            "password authentication is not configured"
        );
    }
    match request.operation {
        Operation::Tcp { host, port } => relay_tcp(stream, host, port, &config).await,
        Operation::Udp => relay_udp(stream, &config).await,
    }
}

/// Forward a TCP destination with full-duplex copy and TLS close-notify half-close semantics.
async fn relay_tcp(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    host: String,
    port: u16,
    config: &Config,
) -> anyhow::Result<()> {
    let target = match host.parse() {
        Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::Domain(host, port),
    };
    let mut socket = match crate::outbound::connect_with(
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
                &mut stream,
                &Response {
                    status: status as u8,
                    bound: "0.0.0.0:0".parse()?,
                },
            )
            .await?;
            stream.shutdown().await?;
            return Err(error.into());
        }
    };
    wire::write(
        &mut stream,
        &Response {
            status: 0,
            bound: socket.local_addr()?,
        },
    )
    .await?;
    copy_bidirectional(&mut stream, &mut socket).await?;
    Ok(())
}

/// Frame UDP envelopes over TLS while retaining source validation, target limits, and idle expiry.
async fn relay_udp(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    config: &Config,
) -> anyhow::Result<()> {
    let mut stream = stream;
    let mut outbound = DirectDatagram::bind_with(config.resolver.clone()).await?;
    wire::write(
        &mut stream,
        &Response {
            status: 0,
            bound: "0.0.0.0:0".parse()?,
        },
    )
    .await?;
    let (mut writer, mut reader) = framed::codec(stream).split();
    let mut buffer = vec![0; crate::datagram::PACKET_CAPACITY];
    let mut expires = Instant::now() + config.udp_idle_timeout;
    loop {
        let activity = tokio::select! {
            _ = sleep_until(expires) => return Ok(()),
            packet = reader.next() => {
                let Some(packet) = packet else { return Ok(()); };
                let packet = packet?;
                ensure!(!packet.is_empty(), "empty TLS datagram envelope");
                outbound.send(&packet, config.connect_timeout).await.record("TLS remote outbound")
            }
            packet = outbound.receive(&mut buffer) => {
                let packet = packet?;
                if packet.len() > crate::datagram::PACKET_CAPACITY { false } else {
                    timeout(config.connect_timeout, writer.send(packet)).await.context("TLS UDP response timed out")??;
                    true
                }
            }
        };
        if activity {
            expires = Instant::now() + config.udp_idle_timeout;
        }
    }
}
