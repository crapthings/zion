//! Configuration files provide a small typed schema for client and server startup.

/// Client files configure one local listener and one authenticated remote endpoint.
mod client;
/// Server files configure TLS material and accepted client authentication.
mod server;

pub use client::ClientConfig;
pub use server::ServerConfig;

use anyhow::{Context, ensure};
use serde::de::DeserializeOwned;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Configuration reads cannot allocate more than this bounded source size.
const MAX_CONFIG: u64 = 64 * 1024;

/// Load a JSON or YAML file without exposing source values through parser errors.
fn read<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let mut source = Zeroizing::new(String::new());
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(MAX_CONFIG + 1)
            .read_to_string(&mut source)
            .context("cannot read JSON configuration from stdin")?;
    } else {
        File::open(path)
            .context("cannot open configuration file")?
            .take(MAX_CONFIG + 1)
            .read_to_string(&mut source)
            .context("cannot read configuration file")?;
    }
    ensure!(
        source.len() as u64 <= MAX_CONFIG,
        "configuration exceeds 64 KiB"
    );
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let extension = if path == Path::new("-") {
        "json"
    } else {
        extension.as_str()
    };
    match extension {
        "json" => serde_json::from_str(&source).map_err(|error| {
            anyhow::anyhow!(
                "invalid JSON configuration at line {}, column {}; check field names and types",
                error.line(),
                error.column()
            )
        }),
        "yaml" | "yml" => serde_saphyr::from_str(&source).map_err(|_| {
            anyhow::anyhow!("invalid YAML configuration; check syntax, field names and types")
        }),
        _ => anyhow::bail!("configuration filename must end in .json, .yaml, or .yml"),
    }
}

/// Resolve credential paths relative to the configuration file rather than the process directory.
fn resolve(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

/// Resolve an optional credential path while preserving an omitted default.
fn resolve_optional(path: &mut Option<PathBuf>, base: &Path) {
    if let Some(path) = path {
        resolve(path, base);
    }
}

/// The unauthenticated local listener defaults to a loopback SOCKS5 address.
fn client_listen() -> std::net::SocketAddr {
    "127.0.0.1:1080".parse().expect("valid literal")
}

/// The authenticated QUIC server defaults to the existing public listener port.
fn server_listen() -> std::net::SocketAddr {
    "[::]:8443".parse().expect("valid literal")
}
