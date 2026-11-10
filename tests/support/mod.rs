//! Shared fixtures issue isolated credentials and supervise local QUIC listeners.

use std::{net::SocketAddr, path::Path, sync::Arc};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zion::{
    server::Config,
    tunnel::{
        Client, TunnelServer,
        tls::{self, Identity},
    },
};

/// A test tunnel owns its credentials and aborts its listener when released.
pub struct Tunnel {
    pub address: SocketAddr,
    pub credentials: TempDir,
    shutdown: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}

/// Tunnel fixture operations create independently trusted local servers and clients.
impl Tunnel {
    /// Start a server using freshly issued role-specific test credentials.
    pub fn start(config: Config) -> Self {
        Self::start_on(config, "127.0.0.1:0".parse().unwrap())
    }

    /// Start a server on an explicit IPv4, IPv6, or dual-stack test listener.
    pub fn start_on(config: Config, listen: SocketAddr) -> Self {
        Self::start_named(config, listen, "localhost")
    }

    /// Issue an isolated server certificate for the explicit DNS name or IP SAN under test.
    pub fn start_named(config: Config, listen: SocketAddr, name: &str) -> Self {
        let credentials = tempfile::tempdir().unwrap();
        let directory = credentials.path().join("identity");
        tls::generate(&directory, name).unwrap();
        let identity = Identity::load(&directory, "server").unwrap();
        let server = TunnelServer::bind(listen, identity, config).unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server.run(shutdown.clone()));
        Self {
            address,
            credentials,
            shutdown,
            task,
        }
    }

    /// Return the directory containing this fixture's trusted identities.
    pub fn directory(&self) -> std::path::PathBuf {
        self.credentials.path().join("identity")
    }

    /// Build a client with this server's trust roots and the requested identity directory.
    pub fn client(&self, directory: &Path, server_name: &str) -> Arc<Client> {
        Client::new(
            self.address,
            server_name.into(),
            Identity::load(directory, "client").unwrap(),
        )
        .unwrap()
    }
}

/// Releasing a fixture cancels its server and deletes its temporary credentials.
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}
