//! Server configuration accepts a shared password, trusted client certificates, or both.

use crate::{
    server::Config,
    tunnel::{TunnelServer, auth::Password, tls::Identity},
};
use anyhow::{Context, ensure};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

/// A server file supplies its TLS certificate and the required client authentication.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default)]
    pub transport: crate::tunnel::ServerTransport,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub password: Option<Password>,
    pub ca: Option<PathBuf>,
    pub dns: Option<Vec<String>>,
    #[serde(default = "super::server_listen")]
    pub listen: SocketAddr,
}

/// Server file operations prevent accidental unauthenticated proxy startup.
impl ServerConfig {
    /// Load a strict file and resolve certificate paths relative to its directory.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut config: Self = super::read(path)?;
        config.validate()?;
        let path = std::path::absolute(path)?;
        let base = path.parent().context("configuration has no directory")?;
        super::resolve(&mut config.cert, base);
        super::resolve(&mut config.key, base);
        super::resolve_optional(&mut config.ca, base);
        Ok(config)
    }

    /// Require at least one explicit authentication factor before binding a public listener.
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.password.is_some() || self.ca.is_some(),
            "set password or ca for client certificate authentication"
        );
        if let Some(dns) = &self.dns {
            crate::dns::parse_servers(dns)?;
        }
        Ok(())
    }

    /// Build the selected authenticated listeners with a shared resolver and admission policy.
    pub fn build(self) -> anyhow::Result<TunnelServer> {
        self.validate()?;
        let identity = Identity::server_from_files(&self.cert, &self.key, self.ca.as_deref())?;
        let config = Config {
            listen: self.listen,
            resolver: self
                .dns
                .as_ref()
                .map(|dns| crate::dns::Resolver::custom(dns))
                .transpose()?
                .unwrap_or_default(),
            ..Config::default()
        };
        TunnelServer::bind_transport(self.listen, identity, config, self.password, self.transport)
    }
}
