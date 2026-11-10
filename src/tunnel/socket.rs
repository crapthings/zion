//! Client socket creation optionally selects egress without modifying global routing.

use anyhow::{Context, ensure};
use quinn::Endpoint;
use socket2::{Domain, Protocol, Socket, Type};
use std::{net::SocketAddr, sync::Arc};

/// Create a nonblocking QUIC endpoint using either normal routing or a named interface.
pub(super) fn client_endpoint(
    remote: SocketAddr,
    interface: Option<&str>,
) -> anyhow::Result<Endpoint> {
    let bind: SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let Some(interface) = interface else {
        return Ok(Endpoint::client(bind)?);
    };
    ensure!(
        !interface.is_empty() && !interface.contains('\0'),
        "invalid network interface name"
    );
    let socket = Socket::new(
        Domain::for_address(remote),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    bind_interface(&socket, interface, remote.is_ipv6())
        .with_context(|| format!("cannot bind QUIC egress to interface {interface}"))?;
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    tracing::info!(interface, %remote, "QUIC egress interface selected");
    Ok(Endpoint::new(
        Default::default(),
        None,
        socket.into(),
        Arc::new(quinn::TokioRuntime),
    )?)
}

/// Bind an Apple UDP socket to its interface index for the selected address family.
#[cfg(target_vendor = "apple")]
fn bind_interface(socket: &Socket, name: &str, ipv6: bool) -> anyhow::Result<()> {
    let index = nix::net::if_::if_nametoindex(name)?;
    let index = std::num::NonZeroU32::new(index).context("network interface has no index")?;
    if ipv6 {
        socket.bind_device_by_index_v6(Some(index))?;
    } else {
        socket.bind_device_by_index_v4(Some(index))?;
    }
    Ok(())
}

/// Bind a Linux or Android UDP socket to the selected device using the native socket API.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_interface(socket: &Socket, name: &str, _ipv6: bool) -> anyhow::Result<()> {
    socket.bind_device(Some(name.as_bytes()))?;
    Ok(())
}

/// Reject unsupported interface selection instead of silently using a different route.
#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn bind_interface(_socket: &Socket, _name: &str, _ipv6: bool) -> anyhow::Result<()> {
    anyhow::bail!("explicit QUIC egress interfaces are unsupported on this platform")
}

/// Bind an authenticated server with explicit dual-stack support for an IPv6 wildcard.
pub(super) fn server_endpoint(
    listen: SocketAddr,
    config: quinn::ServerConfig,
) -> anyhow::Result<Endpoint> {
    let dual_stack = listen.is_ipv6() && listen.ip().is_unspecified();
    let socket = crate::network::udp_socket(listen, dual_stack)?;
    Ok(Endpoint::new(
        Default::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?)
}
