//! A bounded flow table preserves UDP packet boundaries and authorized response endpoints.

use crate::{server::Config, tunnel::Client};
use anyhow::Context;
use fast_socks5::{new_udp_header, parse_udp_request, util::target_addr::TargetAddr};
use futures_util::StreamExt;
use netstack_smoltcp::udp::UdpMsg;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{Instant, sleep_until},
};

/// Each UDP source and destination pair owns one isolated authenticated association.
type Flow = (SocketAddr, SocketAddr);
/// Per-flow queues absorb bounded bursts without blocking other UDP destinations.
const FLOW_QUEUE: usize = 32;

/// Dispatch stack datagrams while removing closed associations and enforcing the session budget.
pub(super) async fn run(
    socket: netstack_smoltcp::UdpSocket,
    config: Config,
    permits: Arc<tokio::sync::Semaphore>,
    output: mpsc::Sender<Vec<u8>>,
    mtu: usize,
) -> anyhow::Result<()> {
    let (mut input, _) = socket.split();
    let (responses, mut receive) = mpsc::channel::<UdpMsg>(256);
    let mut flows: HashMap<Flow, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let client = config.tunnel.as_ref().context("missing tunnel")?.clone();
    loop {
        tokio::select! {
            finished = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(key)) = finished
                    && flows.get(&key).is_some_and(mpsc::Sender::is_closed) {
                    flows.remove(&key);
                }
            }
            response = receive.recv() => {
                let response = response.context("packet UDP responses closed")?;
                if let Ok(packet) = encode(response)
                    && packet.len() <= mtu { let _ = output.try_send(packet); }
            }
            incoming = input.next() => {
                let (payload, source, destination) = incoming.context("packet UDP input closed")?;
                let key = (source, destination);
                if flows.get(&key).is_some_and(mpsc::Sender::is_closed) { flows.remove(&key); }
                if let Some(flow) = flows.get(&key) {
                    let _ = flow.try_send(payload);
                    continue;
                }
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let (sender, receiver) = mpsc::channel(FLOW_QUEUE);
                let _ = sender.try_send(payload);
                flows.insert(key, sender);
                let client = client.clone();
                let responses = responses.clone();
                let deadline = config.connect_timeout;
                let idle = config.udp_idle_timeout;
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = session(key, client, receiver, responses, deadline, idle).await {
                        tracing::debug!(%error, "packet UDP association ended");
                    }
                    key
                });
            }
        }
    }
}

/// Relay one source/destination association with bounded idle time and strict response-source checking.
async fn session(
    (source, destination): Flow,
    client: Arc<Client>,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    responses: mpsc::Sender<UdpMsg>,
    deadline: Duration,
    idle: Duration,
) -> anyhow::Result<()> {
    let session = client.udp(deadline).await?;
    let mut expires = Instant::now() + idle;
    loop {
        tokio::select! {
            _ = sleep_until(expires) => return Ok(()),
            payload = outgoing.recv() => {
                let Some(payload) = payload else { return Ok(()); };
                let mut frame = new_udp_header(destination)?;
                frame.extend_from_slice(&payload);
                if session.send_datagram(frame.into())? == crate::datagram::SendOutcome::Sent {
                    expires = Instant::now() + idle;
                }
            }
            response = session.receive_datagram() => {
                let frame = response?;
                let (fragment, remote, payload) = parse_udp_request(&frame).await?;
                if fragment == 0 && remote == TargetAddr::Ip(destination) {
                    let _ = responses.try_send((payload.to_vec(), destination, source));
                    expires = Instant::now() + idle;
                }
            }
        }
    }
}

/// Encode response IP/UDP headers with the mature packet builder while preserving empty datagrams.
fn encode((payload, source, destination): UdpMsg) -> anyhow::Result<Vec<u8>> {
    use etherparse::PacketBuilder;
    let builder = match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            PacketBuilder::ipv4(source.ip().octets(), destination.ip().octets(), 64)
                .udp(source.port(), destination.port())
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            PacketBuilder::ipv6(source.ip().octets(), destination.ip().octets(), 64)
                .udp(source.port(), destination.port())
        }
        _ => anyhow::bail!("UDP response address family mismatch"),
    };
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload)?;
    Ok(packet)
}
