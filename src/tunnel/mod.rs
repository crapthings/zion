//! The private Zion QUIC transport authenticates peers with TLS certificates and optional password proofs.

/// Client connections adapt SOCKS5 sessions to authenticated QUIC channels.
mod client;
/// Server connections dispatch authenticated streams to direct outbound transports.
mod server;
/// TLS configuration and local credential issuance are shared by both roles.
pub mod tls;
/// Versioned bounded messages describe tunnel requests and responses.
mod wire;

pub use client::{Client, Session};
pub use server::TunnelServer;

/// Stream completion validates acknowledgements and peer cancellation codes.
mod finish;

/// Client UDP sockets optionally bind their egress to a selected network interface.
mod socket;

/// Shared passwords authenticate requests with TLS-bound HMAC proofs.
pub mod auth;
