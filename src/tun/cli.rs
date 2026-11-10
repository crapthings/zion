//! Explicit CLI startup creates a device only after a remote tunnel has authenticated.

use super::{TunDevice, TunOptions, forward};
use crate::{config::ClientConfig, packet::PacketTunnel};
use anyhow::ensure;
use clap::Args;
use ipnet::{Ipv4Net, Ipv6Net};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// TUN CLI options keep interface addresses separate from the existing client authentication file.
#[derive(Args)]
pub struct TunArgs {
    /// Client JSON/YAML containing authentication and an explicit physical outbound interface.
    #[arg(short, long)]
    config: PathBuf,
    /// New interface name; omit to let the OS allocate one.
    #[arg(long)]
    name: Option<String>,
    /// Local IPv4 interface address and prefix, for example 198.18.0.1/30.
    #[arg(long, required_unless_present = "ipv6")]
    ipv4: Option<Ipv4Net>,
    /// Local IPv6 interface address and prefix, for example fd77::1/64.
    #[arg(long)]
    ipv6: Option<Ipv6Net>,
    /// Virtual interface MTU, independent of QUIC's network path MTU.
    #[arg(long, default_value_t = 1500)]
    mtu: u16,
}

/// Authenticate, create one device, and forward until shutdown without setting default routes or DNS.
pub async fn run(options: TunArgs, shutdown: CancellationToken) -> anyhow::Result<()> {
    let device_options = TunOptions {
        name: options.name,
        mtu: options.mtu,
        ipv4: options.ipv4,
        ipv6: options.ipv6,
    };
    device_options.validate()?;
    let client = ClientConfig::load(&options.config)?;
    ensure!(
        client
            .interface
            .as_ref()
            .is_some_and(|name| !name.is_empty()),
        "TUN client configuration requires an explicit outbound interface"
    );
    let mtu = usize::from(device_options.mtu);
    let tunnel = tokio::select! {
        _ = shutdown.cancelled() => return Ok(()),
        result = async { PacketTunnel::start(client.build().await?, mtu).await } => result?,
    };
    if shutdown.is_cancelled() {
        return tunnel.stop().await;
    }
    let device = match TunDevice::create(&device_options) {
        Ok(device) => device,
        Err(error) => {
            let _ = tunnel.stop().await;
            return Err(error);
        }
    };
    let name = match device.name() {
        Ok(name) => name,
        Err(error) => {
            let _ = tunnel.stop().await;
            return Err(error.into());
        }
    };
    tracing::info!(interface = %name, mtu, "TUN device ready; default routes and DNS are unchanged");
    let statistics = forward(device, tunnel, shutdown).await?;
    tracing::info!(
        accepted = statistics.accepted,
        dropped = statistics.dropped,
        written = statistics.written,
        "TUN forwarding stopped"
    );
    Ok(())
}
