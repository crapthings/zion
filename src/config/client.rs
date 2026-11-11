//! Client configuration derives sensible network defaults from a flat file.

use crate::{
    server::Config,
    tunnel::{Client, auth::Password, tls::Identity},
};
use anyhow::{Context, ensure};
use http::uri::Authority;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::{net::lookup_host, time::timeout};

/// A client file selects one server and a password, a certificate pair, or both.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub server: String,
    #[serde(default)]
    pub routing: crate::routing::Routing,
    #[serde(default)]
    pub transport: crate::tunnel::Transport,
    pub password: Option<Password>,
    pub ca: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(default = "super::client_listen")]
    pub listen: SocketAddr,
    pub server_name: Option<String>,
    pub interface: Option<String>,
}

/// Client file operations validate the schema before creating network endpoints.
impl ClientConfig {
    /// Load a strict file and resolve its credential paths relative to that file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut config: Self = super::read(path)?;
        config.validate()?;
        let path = std::path::absolute(path)?;
        let base = path.parent().context("configuration has no directory")?;
        for entry in [&mut config.ca, &mut config.cert, &mut config.key] {
            super::resolve_optional(entry, base);
        }
        Ok(config)
    }

    /// Validate local binding, remote authority, and the required authentication material.
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.listen.ip().is_loopback(),
            "client listen must use a loopback address"
        );
        ensure!(
            self.cert.is_some() == self.key.is_some(),
            "cert and key must be supplied together"
        );
        ensure!(
            self.password.is_some() || self.cert.is_some(),
            "set password or both cert and key"
        );
        ensure!(
            self.server_name
                .as_ref()
                .is_none_or(|name| !name.is_empty()),
            "server_name cannot be empty"
        );
        self.routing.validate()?;
        authority(&self.server)?;
        Ok(())
    }

    /// Build the SOCKS5 runtime with verified TLS and no implicit direct fallback.
    pub async fn build(self) -> anyhow::Result<Config> {
        self.validate()?;
        let identity = Identity::client_from_files(
            self.ca.as_deref(),
            self.cert.as_deref(),
            self.key.as_deref(),
        )?;
        self.build_with_identity(identity).await
    }

    /// Assemble a verified client with credentials already loaded from a native secure transport.
    pub async fn build_with_identity(self, identity: Identity) -> anyhow::Result<Config> {
        self.validate()?;
        let (host, port) = authority(&self.server)?;
        let config = Config {
            listen: self.listen,
            routing: self.routing,
            ..Config::default()
        };
        let remotes = timeout(config.connect_timeout, lookup_host((host.as_str(), port)))
            .await
            .context("server DNS lookup timed out")??
            .collect::<Vec<_>>();
        let tunnel = Client::with_transport(
            remotes,
            self.server_name.unwrap_or(host),
            identity,
            self.interface.as_deref(),
            self.password,
            self.transport,
        )?;
        Ok(Config {
            tunnel: Some(tunnel),
            ..config
        })
    }
}

/// Parse a host and explicit port without accepting embedded credentials or URL paths.
fn authority(value: &str) -> anyhow::Result<(String, u16)> {
    ensure!(
        !value.contains('@'),
        "server must be host:port without a username or password"
    );
    let parsed: Authority = value
        .parse()
        .map_err(|_| anyhow::anyhow!("server must be a host:port address"))?;
    let host = parsed.host().trim_start_matches('[').trim_end_matches(']');
    let port = parsed
        .port_u16()
        .filter(|port| *port != 0)
        .context("server requires a port from 1 to 65535")?;
    ensure!(!host.is_empty(), "server host cannot be empty");
    Ok((host.to_owned(), port))
}
