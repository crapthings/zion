//! Client sessions verify peer identities before exchanging bounded tunnel requests.

use super::{
    tls::Identity,
    wire::{self, Request, Response},
};
use anyhow::{Context, ensure};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{Join, join},
    time::timeout,
};

/// A client shares one UDP endpoint while opening isolated authenticated sessions.
#[derive(Debug)]
pub struct Client {
    targets: Vec<(SocketAddr, Endpoint)>,
    server_name: String,
    password: Option<super::auth::Password>,
}

/// A connection guard closes its session when the owning relay is released.
pub struct ConnectionGuard(pub Connection);

/// Dropping a connection guard releases the corresponding remote association.
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(0u8.into(), b"session finished");
    }
}

/// A session owns an authenticated connection and its single bidirectional stream.
pub struct Session {
    pub guard: ConnectionGuard,
    pub io: Join<RecvStream, SendStream>,
    pub bound: SocketAddr,
}

/// Session operations finish TCP delivery before releasing their connection.
impl Session {
    /// Send a datagram while distinguishing a dropped packet from a failed connection.
    pub fn send_datagram(
        &self,
        packet: bytes::Bytes,
    ) -> anyhow::Result<crate::datagram::SendOutcome> {
        crate::datagram::send_quic(&self.guard.0, packet)
    }

    /// Wait for previously finished stream data to be acknowledged within a deadline.
    pub async fn acknowledged(&mut self) -> anyhow::Result<()> {
        super::finish::acknowledged(self.io.writer(), Duration::from_secs(5)).await
    }
}

/// Client operations perform mutual TLS and validate the server's command response.
impl Client {
    /// Create an endpoint with explicit trust and a client certificate.
    pub fn new(
        remote: SocketAddr,
        server_name: String,
        identity: Identity,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_with_interface(remote, server_name, identity, None)
    }

    /// Create a client with an optional explicit egress interface and no route fallback.
    pub fn new_with_interface(
        remote: SocketAddr,
        server_name: String,
        identity: Identity,
        interface: Option<&str>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::with_authentication(remote, server_name, identity, interface, None)
    }

    /// Create a verified client with a password, a certificate, or both authentication factors.
    pub fn with_authentication(
        remote: SocketAddr,
        server_name: String,
        identity: Identity,
        interface: Option<&str>,
        password: Option<super::auth::Password>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::with_addresses(vec![remote], server_name, identity, interface, password)
    }

    /// Prepare both address families while retaining verified TLS and the explicit interface policy.
    pub fn with_addresses(
        remotes: Vec<SocketAddr>,
        server_name: String,
        identity: Identity,
        interface: Option<&str>,
        password: Option<super::auth::Password>,
    ) -> anyhow::Result<Arc<Self>> {
        ensure!(
            password.is_some() || identity.has_certificate(),
            "configure a password or client certificate"
        );
        let remotes = crate::network::candidates(remotes);
        ensure!(!remotes.is_empty(), "server DNS returned no addresses");
        let tls = identity.client()?;
        let mut targets = Vec::new();
        let mut v4: Option<Endpoint> = None;
        let mut v6: Option<Endpoint> = None;
        let mut failed_v4 = false;
        let mut failed_v6 = false;
        let mut last_error = None;
        for remote in remotes {
            let (endpoint, failed) = if remote.is_ipv4() {
                (&mut v4, &mut failed_v4)
            } else {
                (&mut v6, &mut failed_v6)
            };
            if *failed {
                continue;
            }
            if endpoint.is_none() {
                match super::socket::client_endpoint(remote, interface) {
                    Ok(mut value) => {
                        value.set_default_client_config(tls.clone());
                        *endpoint = Some(value);
                    }
                    Err(error) => {
                        tracing::debug!(%remote, %error, "address family unavailable for QUIC egress");
                        last_error = Some(error);
                        *failed = true;
                        continue;
                    }
                }
            }
            targets.push((remote, endpoint.as_ref().unwrap().clone()));
        }
        if targets.is_empty() {
            return Err(
                last_error.unwrap_or_else(|| anyhow::anyhow!("no usable QUIC address families"))
            );
        }
        Ok(Arc::new(Self {
            targets,
            server_name,
            password,
        }))
    }

    /// Open and acknowledge a TCP tunnel without resolving its destination locally.
    pub async fn tcp(
        &self,
        target: &fast_socks5::util::target_addr::TargetAddr,
        deadline: Duration,
    ) -> anyhow::Result<Session> {
        self.open(Request::tcp(target), deadline).await
    }

    /// Open an isolated UDP association with an authenticated lifetime control stream.
    pub async fn udp(&self, deadline: Duration) -> anyhow::Result<Session> {
        self.open(
            Request {
                version: wire::VERSION,
                operation: wire::Operation::Udp,
                auth: None,
            },
            deadline,
        )
        .await
    }

    /// Race verified TLS handshakes before sending exactly one authenticated proxy operation.
    async fn connect(&self) -> anyhow::Result<ConnectionGuard> {
        let targets = self.targets.clone();
        let name = self.server_name.clone();
        let addresses = targets.iter().map(|(address, _)| *address).collect();
        crate::network::race(addresses, move |remote| {
            let endpoint = targets
                .iter()
                .find(|(address, _)| *address == remote)
                .unwrap()
                .1
                .clone();
            let name = name.clone();
            async move {
                tracing::debug!(%remote, server_name = %name, "starting QUIC handshake");
                let connection = endpoint
                    .connect(remote, &name)
                    .map_err(std::io::Error::other)?
                    .await
                    .map_err(std::io::Error::other)?;
                tracing::debug!(%remote, "QUIC TLS handshake completed");
                Ok(ConnectionGuard(connection))
            }
        })
        .await
        .context("all QUIC TLS handshake attempts failed")
    }

    /// Establish TLS and exchange one validated control request within a shared deadline.
    async fn open(&self, mut request: Request, deadline: Duration) -> anyhow::Result<Session> {
        timeout(deadline, async {
            request.validate()?;
            let guard = self.connect().await?;
            let (send, receive) = guard
                .0
                .open_bi()
                .await
                .context("opening QUIC control stream")?;
            let mut io = join(receive, send);
            if let Some(password) = &self.password {
                request.auth = Some(password.prove(&guard.0, &request)?);
            }
            wire::write(&mut io, &request)
                .await
                .context("sending tunnel request")?;
            let response: Response = wire::read(&mut io)
                .await
                .context("reading tunnel response")?;
            if response.status != 0 {
                return Err(fast_socks5::ReplyError::from_u8(response.status).into());
            }
            ensure!(
                guard.0.max_datagram_size().is_some(),
                "peer does not support QUIC datagrams"
            );
            Ok(Session {
                guard,
                io,
                bound: response.bound,
            })
        })
        .await
        .context("tunnel establishment deadline exceeded")?
    }
}
