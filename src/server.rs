//! Connection admission bounds the number of active SOCKS5 sessions.

use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};
use tokio::{net::TcpListener, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

/// Server settings define listener, capacity, and operation deadlines.
#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub routing: crate::routing::Routing,
    pub traffic_events: bool,
    pub max_connections: NonZeroUsize,
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub shutdown_grace: Duration,
    pub resolver: crate::dns::Resolver,
    pub tunnel: Option<std::sync::Arc<crate::tunnel::Client>>,
}

/// Default settings expose an unauthenticated proxy only on IPv4 loopback.
impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".parse().expect("valid literal"),
            max_connections: NonZeroUsize::new(256).expect("nonzero literal"),
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            udp_idle_timeout: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(5),
            resolver: crate::dns::Resolver::default(),
            tunnel: None,
            routing: crate::routing::Routing::default(),
            traffic_events: false,
        }
    }
}

/// A server owns its bound listener and immutable session settings.
pub struct Server {
    listener: TcpListener,
    config: Config,
}

/// Server operations bind listeners and supervise their sessions.
impl Server {
    /// Bind a loopback listener for the initial unauthenticated local proxy.
    pub async fn bind(config: Config) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.listen.ip().is_loopback(),
            "the unauthenticated listener must use a loopback address"
        );
        anyhow::ensure!(
            !config.handshake_timeout.is_zero()
                && !config.connect_timeout.is_zero()
                && !config.udp_idle_timeout.is_zero(),
            "operation timeouts must be positive"
        );
        config.routing.validate()?;
        Ok(Self {
            listener: TcpListener::bind(config.listen).await?,
            config,
        })
    }

    /// Return the actual listener address, including an OS-assigned port.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept bounded sessions until cancellation and drain them within the grace period.
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let mut tasks = JoinSet::new();
        info!(listen = %self.local_addr()?, "SOCKS5 proxy listening");
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result { warn!(%error, "session task failed"); }
                }
                incoming = self.listener.accept(), if tasks.len() < self.config.max_connections.get() => {
                    let (socket, peer) = incoming?;
                    let config = self.config.clone();
                    tasks.spawn(async move {
                        if let Err(error) = crate::socks::serve(socket, config).await {
                            debug!(error = %format_args!("{error:#}"), "session ended");
                        }
                    }.instrument(tracing::info_span!("session", %peer)));
                }
            }
        }
        drop(self.listener);
        if timeout(self.config.shutdown_grace, async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    warn!(%error, "session task failed during shutdown");
                }
            }
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        Ok(())
    }
}
