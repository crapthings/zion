//! A bounded packet port decouples virtual-interface ownership from TCP and UDP proxying.

/// UDP sessions translate stack datagrams into authenticated QUIC associations.
mod udp;

use crate::server::Config;
use anyhow::{Context, ensure};
use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use std::sync::Arc;
use tokio::{
    io::copy_bidirectional,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

/// Packet queues bound memory independently of the number of active proxy sessions.
const QUEUE_CAPACITY: usize = 256;
/// A conservative virtual MTU fits both IP families while leaving QUIC path sizing independent.
pub const DEFAULT_MTU: usize = 1500;
/// Every native packet entry point uses the same maximum virtual packet size.
pub const MAX_MTU: usize = 9000;

/// Require a virtual MTU that accommodates IPv6 while bounding per-packet allocations.
pub fn validate_mtu(mtu: usize) -> anyhow::Result<()> {
    ensure!(
        (1280..=MAX_MTU).contains(&mtu),
        "virtual MTU must be from 1280 to 9000"
    );
    Ok(())
}

/// A cloneable ingress port accepts complete IP packets from either native backend.
#[derive(Clone)]
pub struct PacketSender {
    channel: mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

/// A packet tunnel owns its worker task and the IP responses destined for the virtual interface.
pub struct PacketTunnel {
    ingress: PacketSender,
    egress: mpsc::Receiver<Vec<u8>>,
    shutdown: CancellationToken,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

/// Packet submission validates basic framing before the mature stack parses protocol details.
impl PacketSender {
    /// Queue one complete packet without blocking a platform callback when backpressure is active.
    pub fn try_send(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        ensure!(packet.len() <= self.mtu, "packet exceeds virtual MTU");
        let parsed = etherparse::SlicedPacket::from_ip(&packet).context("invalid IP packet")?;
        ensure!(
            parsed
                .net
                .as_ref()
                .and_then(|net| net.ip_payload_ref())
                .is_some_and(|payload| !payload.fragmented),
            "fragmented packets are unsupported"
        );
        ensure!(
            matches!(
                parsed.transport,
                Some(etherparse::TransportSlice::Tcp(_) | etherparse::TransportSlice::Udp(_))
            ),
            "packet mode supports TCP and UDP"
        );
        self.channel
            .try_send(packet)
            .context("packet ingress is full or stopped")
    }
}

/// Packet tunnel operations authenticate before a native backend is allowed to install routes.
impl PacketTunnel {
    /// Start a shared userspace stack without creating an interface or changing system networking.
    pub async fn start(config: Config, mtu: usize) -> anyhow::Result<Self> {
        validate_mtu(mtu)?;
        let client = config
            .tunnel
            .as_ref()
            .context("packet mode requires an authenticated tunnel")?;
        drop(client.udp(config.connect_timeout).await?);
        let (stack, runner, udp, tcp) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .stack_buffer_size(QUEUE_CAPACITY)
            .tcp_buffer_size(32)
            .udp_buffer_size(QUEUE_CAPACITY)
            .tcp_recv_buffer_size(64 * 1024)
            .tcp_send_buffer_size(64 * 1024)
            .mtu(mtu)
            .build()?;
        let (input, mut incoming) = mpsc::channel::<Vec<u8>>(QUEUE_CAPACITY);
        let (output, outgoing) = mpsc::channel(QUEUE_CAPACITY);
        let shutdown = CancellationToken::new();
        let stopping = shutdown.clone();
        let permits = Arc::new(tokio::sync::Semaphore::new(config.max_connections.get()));
        let task = tokio::spawn(async move {
            let (mut sink, mut stream) = stack.split();
            let mut drivers = JoinSet::new();
            drivers.spawn(async move {
                while let Some(packet) = incoming.recv().await {
                    if let Err(error) = sink.send(packet).await {
                        tracing::debug!(%error, "invalid or unhandled packet rejected by stack");
                    }
                }
                anyhow::bail!("packet input closed")
            });
            let stack_output = output.clone();
            drivers.spawn(async move {
                while let Some(packet) = stream.next().await {
                    stack_output
                        .send(packet?)
                        .await
                        .context("packet output closed")?;
                }
                anyhow::bail!("packet stack output closed")
            });
            drivers.spawn(async move {
                runner.context("TCP stack runner missing")?.await?;
                anyhow::bail!("TCP stack runner stopped")
            });
            drivers.spawn(tcp_sessions(
                tcp.context("TCP stack listener missing")?,
                config.clone(),
                permits.clone(),
            ));
            drivers.spawn(udp::run(
                udp.context("UDP stack socket missing")?,
                config,
                permits,
                output,
                mtu,
            ));
            let result = tokio::select! {
                _ = stopping.cancelled() => Ok(()),
                result = drivers.join_next() => match result {
                    Some(Ok(result)) => result,
                    Some(Err(error)) => Err(error.into()),
                    None => anyhow::bail!("packet engine stopped"),
                }
            };
            drivers.abort_all();
            while drivers.join_next().await.is_some() {}
            result
        });
        Ok(Self {
            ingress: PacketSender {
                channel: input,
                mtu,
            },
            egress: outgoing,
            shutdown,
            task: Some(task),
        })
    }

    /// Return the packet engine's configured MTU for a matching native-device transport.
    pub fn mtu(&self) -> usize {
        self.ingress.mtu
    }

    /// Clone the bounded ingress handle for a native packet callback.
    pub fn sender(&self) -> PacketSender {
        self.ingress.clone()
    }

    /// Receive one complete response packet for injection into the selected virtual interface.
    pub async fn receive(&mut self) -> Option<Vec<u8>> {
        self.egress.recv().await
    }

    /// Cancel every owned flow and wait for the packet engine to release its resources.
    pub async fn stop(mut self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        self.task.take().expect("owned packet task").await?
    }
}

/// Dropping a packet tunnel cancels only its owned work without touching system route state.
impl Drop for PacketTunnel {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// Stack TCP sessions share existing QUIC authentication, half-close, and delivery semantics.
async fn tcp_sessions(
    mut listener: netstack_smoltcp::TcpListener,
    config: Config,
    permits: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<()> {
    let mut sessions = JoinSet::new();
    let client = Arc::clone(config.tunnel.as_ref().context("missing tunnel")?);
    loop {
        tokio::select! {
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Ok(Err(error))) = result { tracing::debug!(%error, "packet TCP session ended"); }
            }
            incoming = listener.next() => {
                let Some((mut stream, _, destination)) = incoming else { anyhow::bail!("packet TCP listener closed"); };
                let Ok(permit) = permits.clone().try_acquire_owned() else { drop(stream); continue; };
                let client = client.clone();
                let deadline = config.connect_timeout;
                sessions.spawn(async move {
                    let _permit = permit;
                    let mut session = client.tcp(&fast_socks5::util::target_addr::TargetAddr::Ip(destination), deadline).await?;
                    copy_bidirectional(&mut stream, &mut session.io).await?;
                    session.acknowledged().await?;
                    Ok::<_, anyhow::Error>(())
                });
            }
        }
    }
}
