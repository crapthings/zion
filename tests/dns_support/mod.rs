//! Isolated DNS responders exercise resolver integration using Hickory's wire codec.

use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, SOA},
    },
};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

/// A response mode separates legitimate negative answers from temporary upstream failures.
#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Positive,
    NxDomain,
    NoData,
    ServFail,
    Drop,
}

/// A rule controls records and TTLs without relying on external DNS or machine hosts files.
#[derive(Clone)]
pub struct Rule {
    pub mode: Mode,
    pub ttl: u32,
    pub delay: Duration,
    pub v4: Ipv4Addr,
    pub v6: Ipv6Addr,
    pub cname_ttl: Option<u32>,
    pub truncate_udp: bool,
    pub aaaa_servfail: bool,
}

/// Default records return the two loopback families with a normal cacheable lifetime.
impl Default for Rule {
    fn default() -> Self {
        Self {
            mode: Mode::Positive,
            ttl: 30,
            delay: Duration::ZERO,
            v4: Ipv4Addr::LOCALHOST,
            v6: Ipv6Addr::LOCALHOST,
            cname_ttl: None,
            truncate_udp: false,
            aaaa_servfail: false,
        }
    }
}

/// Responder state counts upstream requests independently of the client's response cache.
struct State {
    rule: RwLock<Rule>,
    a: AtomicUsize,
    aaaa: AtomicUsize,
    tcp: AtomicUsize,
}

/// A DNS fixture owns temporary UDP/TCP listeners and cancels their request handlers on drop.
pub struct FakeDns {
    pub address: SocketAddr,
    state: Arc<State>,
    tasks: Vec<JoinHandle<()>>,
}

/// DNS fixture operations expose deterministic records and upstream request counters.
impl FakeDns {
    /// Bind a pair of loopback listeners using the requested address family.
    pub async fn start(rule: Rule, ipv6: bool) -> Self {
        let tcp = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = Arc::new(UdpSocket::bind(address).await.unwrap());
        let state = Arc::new(State {
            rule: RwLock::new(rule),
            a: AtomicUsize::new(0),
            aaaa: AtomicUsize::new(0),
            tcp: AtomicUsize::new(0),
        });
        let tasks = vec![
            tokio::spawn(serve_udp(udp, state.clone())),
            tokio::spawn(serve_tcp(tcp, state.clone())),
        ];
        Self {
            address,
            state,
            tasks,
        }
    }

    /// Construct one shared production resolver directed only at this fixture's port.
    pub fn resolver(&self) -> zion::dns::Resolver {
        zion::dns::Resolver::custom(&[self.address.to_string()]).unwrap()
    }

    /// Count queries of one record type across both transport protocols.
    pub fn count(&self, kind: RecordType) -> usize {
        match kind {
            RecordType::A => self.state.a.load(Ordering::SeqCst),
            RecordType::AAAA => self.state.aaaa.load(Ordering::SeqCst),
            _ => unreachable!(),
        }
    }

    /// Count TCP exchanges to verify UDP truncation causes an actual protocol fallback.
    pub fn tcp_count(&self) -> usize {
        self.state.tcp.load(Ordering::SeqCst)
    }

    /// Change records to demonstrate expiration and resolver-policy cache isolation.
    pub fn set_rule(&self, rule: Rule) {
        *self.state.rule.write().unwrap() = rule;
    }
}

/// Releasing a fixture aborts listener loops and their owned request task sets.
impl Drop for FakeDns {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Serve independent delayed UDP queries without serializing unrelated names.
async fn serve_udp(socket: Arc<UdpSocket>, state: Arc<State>) {
    let mut buffer = [0; 65535];
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            packet = socket.recv_from(&mut buffer) => {
                let (size, peer) = packet.unwrap();
                let request = Message::from_vec(&buffer[..size]).unwrap();
                let state = state.clone();
                let socket = socket.clone();
                tasks.spawn(async move {
                    if let Some(reply) = answer(request, &state, false).await {
                        let _ = socket.send_to(&reply, peer).await;
                    }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

/// Serve persistent framed TCP DNS connections and own every spawned connection task.
async fn serve_tcp(listener: TcpListener, state: Arc<State>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (socket, _) = incoming.unwrap();
                tasks.spawn(tcp_connection(socket, state.clone()));
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

/// Exchange bounded DNS frames over a fixture TCP connection until the client closes.
async fn tcp_connection(mut socket: TcpStream, state: Arc<State>) {
    loop {
        let Ok(Ok(size)) = timeout(Duration::from_secs(6), socket.read_u16()).await else {
            return;
        };
        let mut frame = vec![0; size as usize];
        if socket.read_exact(&mut frame).await.is_err() {
            return;
        }
        let request = Message::from_vec(&frame).unwrap();
        if let Some(reply) = answer(request, &state, true).await {
            if socket.write_u16(reply.len() as u16).await.is_err() {
                return;
            }
            if socket.write_all(&reply).await.is_err() {
                return;
            }
        }
    }
}

/// Generate an authoritative fixture response using mature DNS parsing and serialization.
async fn answer(request: Message, state: &State, tcp: bool) -> Option<Vec<u8>> {
    let query = request.queries.first().unwrap().clone();
    match query.query_type() {
        RecordType::A => {
            state.a.fetch_add(1, Ordering::SeqCst);
        }
        RecordType::AAAA => {
            state.aaaa.fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }
    if tcp {
        state.tcp.fetch_add(1, Ordering::SeqCst);
    }
    let rule = state.rule.read().unwrap().clone();
    tokio::time::sleep(rule.delay).await;
    if rule.mode == Mode::Drop {
        return None;
    }
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.add_query(query.clone());
    if rule.truncate_udp && !tcp {
        response.metadata.truncation = true;
        return Some(response.to_vec().unwrap());
    }
    let mode = if rule.aaaa_servfail && query.query_type() == RecordType::AAAA {
        Mode::ServFail
    } else {
        rule.mode
    };
    match mode {
        Mode::Positive => {
            let mut owner = query.name().clone();
            if let Some(ttl) = rule.cname_ttl {
                let canonical = Name::from_ascii("canonical.zion.test.").unwrap();
                if owner != canonical {
                    response.add_answer(Record::from_rdata(
                        owner,
                        ttl,
                        RData::CNAME(CNAME(canonical.clone())),
                    ));
                    owner = canonical;
                }
            }
            let data = match query.query_type() {
                RecordType::A => RData::A(A(rule.v4)),
                RecordType::AAAA => RData::AAAA(AAAA(rule.v6)),
                _ => unreachable!(),
            };
            response.add_answer(Record::from_rdata(owner, rule.ttl, data));
        }
        Mode::NxDomain | Mode::NoData => {
            response.metadata.response_code = if mode == Mode::NxDomain {
                ResponseCode::NXDomain
            } else {
                ResponseCode::NoError
            };
            let soa = SOA::new(
                Name::from_ascii("ns.zion.test.").unwrap(),
                Name::from_ascii("hostmaster.zion.test.").unwrap(),
                1,
                60,
                60,
                3600,
                rule.ttl,
            );
            response.add_authority(Record::from_rdata(
                Name::from_ascii("zion.test.").unwrap(),
                rule.ttl,
                RData::SOA(soa),
            ));
        }
        Mode::ServFail => response.metadata.response_code = ResponseCode::ServFail,
        Mode::Drop => unreachable!(),
    }
    Some(response.to_vec().unwrap())
}
