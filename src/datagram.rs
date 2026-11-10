//! Direct UDP forwarding retains only bounded destinations requested by its association.

use bytes::Bytes;
use fast_socks5::{new_udp_header, parse_udp_request};
use quinn::{Connection, SendDatagramError};
use std::{collections::HashSet, net::SocketAddr, time::Duration};
use tokio::net::UdpSocket;

/// A send outcome separates accepted packets from recoverable per-packet drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Sent,
    Dropped(DropReason),
}

/// A drop reason identifies the packet policy or transient failure that prevented sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    InvalidPacket,
    UnsupportedFragment,
    DnsFailure,
    DestinationLimit,
    UnsupportedAddressFamily,
    TooLarge,
    SocketError,
    UnexpectedSource,
    NoClient,
}

/// Outcome helpers record packet drops without treating them as transport failures.
impl SendOutcome {
    /// Record a recoverable drop and report whether this packet counts as activity.
    pub(crate) fn record(self, direction: &'static str) -> bool {
        match self {
            Self::Sent => true,
            Self::Dropped(reason) => {
                tracing::debug!(direction, ?reason, "UDP packet dropped");
                false
            }
        }
    }
}

/// Send a QUIC datagram while preserving connection and capability errors for the caller.
pub(crate) fn send_quic(connection: &Connection, packet: Bytes) -> anyhow::Result<SendOutcome> {
    match connection.send_datagram(packet) {
        Ok(()) => Ok(SendOutcome::Sent),
        Err(SendDatagramError::TooLarge) => Ok(SendOutcome::Dropped(DropReason::TooLarge)),
        Err(error) => Err(anyhow::Error::new(error).context("QUIC datagram transport failed")),
    }
}

/// Datagram receive buffers accommodate a complete UDP payload.
pub(crate) const PACKET_CAPACITY: usize = 65_535;
/// Each association can authorize no more than this many remote endpoints.
const MAX_DESTINATIONS: usize = 256;

/// Direct UDP state owns sockets and the set of authorized response sources.
pub(crate) struct DirectDatagram {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    destinations: HashSet<SocketAddr>,
    resolver: crate::dns::Resolver,
}

/// Direct datagram operations preserve SOCKS5 envelopes at their transport boundary.
impl DirectDatagram {
    /// Bind outbound sockets for the address families supported by the host.
    #[cfg(test)]
    pub async fn bind() -> anyhow::Result<Self> {
        Self::bind_with(crate::dns::Resolver::default()).await
    }

    /// Bind an association while sharing the server's resolver and indexed cache.
    pub async fn bind_with(resolver: crate::dns::Resolver) -> anyhow::Result<Self> {
        let v4 = Self::bind_family("0.0.0.0:0".parse()?)
            .inspect_err(|error| tracing::debug!(%error, "IPv4 UDP egress unavailable"))
            .ok();
        let v6 = Self::bind_family("[::]:0".parse()?)
            .inspect_err(|error| tracing::debug!(%error, "IPv6 UDP egress unavailable"))
            .ok();
        anyhow::ensure!(
            v4.is_some() || v6.is_some(),
            "no UDP address family is available"
        );
        Ok(Self {
            v4,
            v6,
            destinations: HashSet::new(),
            resolver,
        })
    }

    /// Keep outbound IPv4 and IPv6 sockets separate to avoid mapped-source ambiguity.
    fn bind_family(address: SocketAddr) -> std::io::Result<UdpSocket> {
        UdpSocket::from_std(crate::network::udp_socket(address, false)?)
    }

    /// Send a valid unfragmented SOCKS5 datagram and authorize its resolved endpoint.
    pub async fn send(&mut self, packet: &[u8], deadline: Duration) -> SendOutcome {
        let (fragment, target, payload) = match parse_udp_request(packet).await {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::debug!(%error, "invalid SOCKS5 UDP envelope");
                return SendOutcome::Dropped(DropReason::InvalidPacket);
            }
        };
        if fragment != 0 {
            return SendOutcome::Dropped(DropReason::UnsupportedFragment);
        }
        let destinations = match self.resolver.resolve(&target, deadline).await {
            Ok(destinations) => destinations,
            Err(error) => {
                tracing::debug!(%error, "UDP destination resolution failed");
                return SendOutcome::Dropped(DropReason::DnsFailure);
            }
        };
        self.send_candidates(&destinations, payload).await
    }

    /// Try alternate addresses only after local failure so UDP payloads are never raced or duplicated.
    async fn send_candidates(
        &mut self,
        destinations: &[SocketAddr],
        payload: &[u8],
    ) -> SendOutcome {
        let mut reason = DropReason::UnsupportedAddressFamily;
        for destination in destinations {
            let outbound = if destination.is_ipv4() {
                self.v4.as_ref()
            } else {
                self.v6.as_ref()
            };
            let Some(outbound) = outbound else {
                continue;
            };
            if !self.destinations.contains(destination)
                && self.destinations.len() >= MAX_DESTINATIONS
            {
                reason = DropReason::DestinationLimit;
                continue;
            }
            match outbound.send_to(payload, destination).await {
                Ok(_) => {
                    self.destinations.insert(*destination);
                    return SendOutcome::Sent;
                }
                Err(error) => {
                    tracing::debug!(%error, %destination, "UDP socket send failed; trying next address");
                    reason = DropReason::SocketError;
                }
            }
        }
        SendOutcome::Dropped(reason)
    }

    /// Receive an authorized remote response and encode its source in a SOCKS5 envelope.
    pub async fn receive(&self, buffer: &mut [u8]) -> anyhow::Result<Bytes> {
        loop {
            let (length, source) = self.receive_raw(buffer).await?;
            if !self.destinations.contains(&source) {
                continue;
            }
            let mut response = new_udp_header(source)?;
            response.extend_from_slice(&buffer[..length]);
            return Ok(response.into());
        }
    }

    /// Receive a remote datagram while tolerating spurious socket readiness.
    async fn receive_raw(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match (&self.v4, &self.v6) {
            (Some(v4), Some(v6)) => loop {
                let result = tokio::select! {
                    ready = v4.readable() => { ready?; v4.try_recv_from(buffer) }
                    ready = v6.readable() => { ready?; v6.try_recv_from(buffer) }
                };
                match result {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    result => return result,
                }
            },
            (Some(v4), None) => v4.recv_from(buffer).await,
            (None, Some(v6)) => v6.recv_from(buffer).await,
            (None, None) => Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no UDP sockets",
            )),
        }
    }
}

/// UDP fallback tests exercise missing address families without duplicating successful sends.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    /// An unavailable IPv6 socket falls back to IPv4 and authorizes only the actual destination.
    #[tokio::test]
    async fn unavailable_family_falls_back_without_duplicate_delivery() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let mut outbound = DirectDatagram {
            v4: Some(UdpSocket::bind("0.0.0.0:0").await.unwrap()),
            v6: None,
            destinations: HashSet::new(),
            resolver: crate::dns::Resolver::default(),
        };
        let ipv6 = SocketAddr::new("::1".parse().unwrap(), address.port());
        assert_eq!(
            outbound.send_candidates(&[ipv6, address], b"once").await,
            SendOutcome::Sent
        );
        let mut buffer = [0; 32];
        let (size, _) = timeout(Duration::from_secs(2), target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], b"once");
        assert_eq!(outbound.destinations, HashSet::from([address]));
        assert!(
            timeout(Duration::from_millis(40), target.recv_from(&mut buffer))
                .await
                .is_err()
        );
    }

    /// A local send error tries the next candidate instead of discarding an otherwise deliverable packet.
    #[tokio::test]
    async fn local_send_failure_tries_next_address() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let mut outbound = DirectDatagram::bind().await.unwrap();
        assert_eq!(
            outbound
                .send_candidates(&["127.0.0.1:0".parse().unwrap(), address], b"fallback")
                .await,
            SendOutcome::Sent
        );
        let mut buffer = [0; 32];
        let (size, _) = timeout(Duration::from_secs(2), target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], b"fallback");
    }
}
