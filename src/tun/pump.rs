//! The packet pump connects a datagram device to the existing authenticated packet engine.

use crate::packet::PacketTunnel;
use anyhow::{Context, ensure};
use std::{future::Future, io};
use tokio_util::sync::CancellationToken;

/// A packet device delivers exactly one raw IP packet per read or write.
pub trait PacketDevice: Send + Sync {
    /// Read one packet into the supplied bounded buffer without retaining it beyond the future.
    fn recv(&self, packet: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    /// Write one complete packet and report the exact byte count accepted by the device.
    fn send(&self, packet: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

/// Pump totals describe accepted and dropped packets without retaining payloads.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TunStatistics {
    pub accepted: u64,
    pub dropped: u64,
    pub written: u64,
}

/// Forward raw packets with bounded buffers and stop the owned engine on cancellation or I/O failure.
pub async fn forward<D: PacketDevice>(
    device: D,
    mut tunnel: PacketTunnel,
    shutdown: CancellationToken,
) -> anyhow::Result<TunStatistics> {
    let mtu = tunnel.mtu();
    let input = tunnel.sender();
    let mut statistics = TunStatistics::default();
    let result: anyhow::Result<()> = {
        let ingress = async {
            // One extra byte detects oversized reads instead of accepting truncated packet prefixes.
            let mut packet = vec![0; mtu + 1];
            loop {
                let size = device
                    .recv(&mut packet)
                    .await
                    .context("reading TUN packet")?;
                ensure!(
                    size != 0 && size <= packet.len(),
                    "TUN device closed or returned an invalid read size"
                );
                if size > mtu || input.try_send(packet[..size].to_vec()).is_err() {
                    statistics.dropped += 1;
                } else {
                    statistics.accepted += 1;
                }
                tokio::task::consume_budget().await;
            }
        };
        let egress = async {
            loop {
                let packet = tunnel.receive().await.context("packet engine stopped")?;
                let size = device.send(&packet).await.context("writing TUN packet")?;
                ensure!(size == packet.len(), "partial TUN packet write");
                statistics.written += 1;
                tokio::task::consume_budget().await;
            }
        };
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => Ok(()),
            result = ingress => result,
            result = egress => result,
        }
    };
    // Closing the engine also cancels all TCP and UDP sessions before the device is dropped.
    let stopped = tunnel.stop().await;
    result?;
    stopped?;
    Ok(statistics)
}
