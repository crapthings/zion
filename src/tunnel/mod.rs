//! Zion carriers authenticate TCP/TLS and UDP/QUIC peers with certificates and connection-bound proofs.

/// Client connections select an authenticated carrier for SOCKS5 and packet-engine sessions.
mod client;
/// Server connections dispatch authenticated streams to direct outbound transports.
mod server;
/// TLS configuration and local credential issuance are shared by both roles.
pub mod tls;
/// Versioned bounded messages describe tunnel requests and responses.
mod wire;

pub use client::Client;
pub use server::TunnelServer;
pub use session::Session;

/// Stream completion validates acknowledgements and peer cancellation codes.
mod finish;

/// Client UDP sockets optionally bind their egress to a selected network interface.
mod socket;

/// Shared passwords authenticate requests with TLS-bound HMAC proofs.
pub mod auth;

/// Length-delimited TLS datagrams retain boundaries and bounded background queues.
mod framed;
/// Stream adapters expose either transport without erasing QUIC completion semantics.
mod session;
/// TCP/TLS sessions share the existing identity policy and bounded proxy commands.
mod stream;

pub use stream::TlsServer;

/// Client transport selection never falls back to another mode or unauthenticated direct access.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    #[serde(alias = "udp")]
    #[value(alias = "udp")]
    Quic,
    #[serde(alias = "tcp")]
    #[value(alias = "tcp")]
    Tls,
}

/// Server mode can expose TCP and UDP at the same numeric port with the same authentication policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ServerTransport {
    #[default]
    #[serde(alias = "udp")]
    #[value(alias = "udp")]
    Quic,
    #[serde(alias = "tcp")]
    #[value(alias = "tcp")]
    Tls,
    Both,
}
