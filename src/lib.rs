//! Zion provides a bounded local SOCKS5 proxy with separate stream and datagram paths.

/// Direct outbound connections resolve and connect to requested destinations.
pub mod outbound;
/// The server owns connection admission and task lifecycles.
pub mod server;
/// SOCKS5 handling adapts protocol requests to outbound operations.
mod socks;
/// UDP associations validate senders and relay bounded destination sets.
mod udp;

/// Datagram forwarding is shared by local and remote association handlers.
pub mod datagram;
/// Authenticated QUIC tunnels connect local SOCKS5 sessions to a remote server.
pub mod tunnel;

/// Minimal JSON and YAML configuration files assemble authenticated client and server roles.
pub mod config;

/// Machine-readable process events allow native clients to supervise the proxy core.
pub mod control;

/// Shared network policies bound dual-stack address racing and socket behavior.
mod network;

/// DNS policies share explicit upstreams, TTL caching, and bounded concurrent lookup work.
pub mod dns;

/// Packet tunnels adapt either native backend to the same bounded QUIC flow engine.
#[cfg(feature = "packet-tunnel")]
pub mod packet;

/// The native C bridge embeds the packet engine without a loopback proxy process.
#[cfg(feature = "packet-tunnel")]
pub mod packet_ffi;

/// Native app commands expose a versioned local control interface for users and agents.
pub mod app_cli;
