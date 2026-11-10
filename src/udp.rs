//! UDP associations pin local clients while choosing direct or authenticated remote egress.

use crate::{
    datagram::{DirectDatagram, DropReason, PACKET_CAPACITY, SendOutcome},
    server::Config,
    socks::Command,
    tunnel::Session,
};
use bytes::Bytes;
use fast_socks5::{ReplyError, parse_udp_request, util::target_addr::TargetAddr};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::UdpSocket,
    time::{Instant, sleep_until},
};

/// A datagram channel preserves packet boundaries across either outbound transport.
enum Channel {
    Direct(DirectDatagram),
    Tunnel(Session),
}

/// Channel operations adapt direct UDP and QUIC Datagram to the same envelope format.
impl Channel {
    /// Select a transport without silently bypassing an unavailable configured tunnel.
    async fn open(config: &Config) -> anyhow::Result<Self> {
        match &config.tunnel {
            Some(client) => Ok(Self::Tunnel(client.udp(config.connect_timeout).await?)),
            None => Ok(Self::Direct(
                DirectDatagram::bind_with(config.resolver.clone()).await?,
            )),
        }
    }

    /// Send a complete envelope without fragmenting oversized QUIC datagrams.
    async fn send(&mut self, packet: &[u8], deadline: Duration) -> anyhow::Result<SendOutcome> {
        match self {
            Self::Direct(outbound) => Ok(outbound.send(packet, deadline).await),
            Self::Tunnel(session) => session.send_datagram(Bytes::copy_from_slice(packet)),
        }
    }

    /// Receive one response or report that its underlying tunnel has closed.
    async fn receive(&self, buffer: &mut [u8]) -> anyhow::Result<Bytes> {
        match self {
            Self::Direct(outbound) => outbound.receive(buffer).await,
            Self::Tunnel(session) => Ok(session.guard.0.read_datagram().await?),
        }
    }
}

/// Local association state pins its sender independently of the selected transport.
struct Association {
    client: UdpSocket,
    channel: Channel,
    peer: SocketAddr,
    client_endpoint: Option<SocketAddr>,
}

/// Association operations validate client endpoints and forward their datagrams.
impl Association {
    /// Bind the local relay and establish its outbound transport before acknowledging SOCKS5.
    async fn bind(
        peer: SocketAddr,
        local_ip: IpAddr,
        requested: TargetAddr,
        config: &Config,
    ) -> anyhow::Result<Self> {
        let client_endpoint = match requested {
            TargetAddr::Ip(addr) if addr.port() != 0 => {
                Some(SocketAddr::new(peer.ip(), addr.port()))
            }
            _ => None,
        };
        Ok(Self {
            client: UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?,
            channel: Channel::open(config).await?,
            peer,
            client_endpoint,
        })
    }

    /// Pin and forward only valid unfragmented packets from the control peer.
    async fn send_outbound(
        &mut self,
        packet: &[u8],
        source: SocketAddr,
        config: &Config,
    ) -> anyhow::Result<SendOutcome> {
        if source.ip() != self.peer.ip()
            || self
                .client_endpoint
                .is_some_and(|expected| expected != source)
        {
            return Ok(SendOutcome::Dropped(DropReason::UnexpectedSource));
        }
        match parse_udp_request(packet).await {
            Ok((0, _, _)) => {}
            Ok(_) => return Ok(SendOutcome::Dropped(DropReason::UnsupportedFragment)),
            Err(_) => return Ok(SendOutcome::Dropped(DropReason::InvalidPacket)),
        }
        let outcome = self.channel.send(packet, config.connect_timeout).await?;
        if outcome == SendOutcome::Sent {
            self.client_endpoint = Some(source);
        }
        Ok(outcome)
    }

    /// Return an outbound envelope only to the association's pinned client.
    async fn send_response(&self, packet: &[u8]) -> SendOutcome {
        let Some(destination) = self.client_endpoint else {
            return SendOutcome::Dropped(DropReason::NoClient);
        };
        match self.client.send_to(packet, destination).await {
            Ok(_) => SendOutcome::Sent,
            Err(error) => {
                tracing::debug!(%error, "UDP response socket send failed");
                SendOutcome::Dropped(DropReason::SocketError)
            }
        }
    }
}

/// Relay datagrams until their TCP control closes, the transport fails, or activity expires.
pub async fn relay(
    request: Command,
    peer: SocketAddr,
    local_ip: IpAddr,
    requested: TargetAddr,
    config: &Config,
) -> anyhow::Result<()> {
    let mut association = match Association::bind(peer, local_ip, requested, config).await {
        Ok(association) => association,
        Err(error) => {
            request.reply_error(&ReplyError::GeneralFailure).await?;
            return Err(error);
        }
    };
    let mut control = request
        .reply_success(association.client.local_addr()?)
        .await?;
    let mut incoming = vec![0; PACKET_CAPACITY];
    let mut outgoing = vec![0; PACKET_CAPACITY];
    let mut control_byte = [0];
    let mut expires = Instant::now() + config.udp_idle_timeout;
    loop {
        let activity = tokio::select! {
            biased;
            _ = control.read(&mut control_byte) => return Ok(()),
            _ = sleep_until(expires) => return Ok(()),
            packet = association.client.recv_from(&mut incoming) => {
                let (length, source) = packet?;
                association.send_outbound(&incoming[..length], source, config).await?.record("local outbound")
            }
            packet = association.channel.receive(&mut outgoing) => association.send_response(&packet?).await.record("local response"),
        };
        if activity {
            expires = Instant::now() + config.udp_idle_timeout;
        }
    }
}
