//! Raw packet integration tests exercise the shared data plane without creating a system TUN.
#![cfg(feature = "packet-tunnel")]

/// Trusted loopback servers keep packet tests independent of platform privileges.
mod support;

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use zion::{
    packet::{DEFAULT_MTU, PacketTunnel},
    server::Config,
};

/// Encode a complete UDP packet with the maintained checksum-aware packet builder.
fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let builder = match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
            PacketBuilder::ipv4(source.ip().octets(), destination.ip().octets(), 64)
                .udp(source.port(), destination.port())
        }
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
            PacketBuilder::ipv6(source.ip().octets(), destination.ip().octets(), 64)
                .udp(source.port(), destination.port())
        }
        _ => unreachable!(),
    };
    let mut packet = Vec::new();
    builder.write(&mut packet, payload).unwrap();
    packet
}

/// Build a trusted packet engine without binding a virtual interface or listening SOCKS port.
async fn engine() -> (support::Tunnel, PacketTunnel) {
    let tunnel = support::Tunnel::start(Config::default());
    let config = Config {
        tunnel: Some(tunnel.client(&tunnel.directory(), "localhost")),
        ..Config::default()
    };
    let engine = PacketTunnel::start(config, DEFAULT_MTU).await.unwrap();
    (tunnel, engine)
}

/// Both packet families preserve payloads and empty UDP datagrams through actual QUIC forwarding.
#[tokio::test]
async fn udp_packets_roundtrip_in_both_families_including_empty_payloads() {
    let (_server, mut engine) = engine().await;
    for (local, bind) in [
        ("192.0.2.2:4000", "127.0.0.1:0"),
        ("[fd99::2]:4001", "[::1]:0"),
    ] {
        let source: SocketAddr = local.parse().unwrap();
        let target = UdpSocket::bind(bind).await.unwrap();
        let destination = target.local_addr().unwrap();
        for payload in [b"packet UDP".as_slice(), b"".as_slice()] {
            engine
                .sender()
                .try_send(udp_packet(source, destination, payload))
                .unwrap();
            let mut buffer = [0; 128];
            let (size, peer) = timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..size], payload);
            target.send_to(&buffer[..size], peer).await.unwrap();
            let response = timeout(Duration::from_secs(3), engine.receive())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, udp_packet(destination, source, payload));
        }
    }
    engine.stop().await.unwrap();
}

/// Invalid packets and queue pressure are rejected without any interface or unbounded allocations.
#[tokio::test]
async fn packet_ingress_validates_framing_and_is_bounded() {
    let (_server, engine) = engine().await;
    let sender = engine.sender();
    assert!(sender.try_send(vec![0; 10]).is_err());
    assert!(sender.try_send(vec![0x60; DEFAULT_MTU + 1]).is_err());
    let packet = udp_packet(
        "192.0.2.2:1".parse().unwrap(),
        "127.0.0.1:9".parse().unwrap(),
        b"x",
    );
    for _ in 0..256 {
        sender.try_send(packet.clone()).unwrap();
    }
    assert!(sender.try_send(packet.clone()).is_err());
    engine.stop().await.unwrap();
    assert!(sender.try_send(packet).is_err());
}

/// An untrusted server name cannot produce a running packet port or a native ready event.
#[tokio::test]
async fn packet_mode_requires_verified_remote_authentication() {
    let tunnel = support::Tunnel::start(Config::default());
    let config = Config {
        tunnel: Some(tunnel.client(&tunnel.directory(), "wrong.example")),
        ..Config::default()
    };
    assert!(PacketTunnel::start(config, DEFAULT_MTU).await.is_err());
}

/// TCP fixture flags describe only the minimal handshake and half-close packets under test.
#[derive(Clone, Copy)]
struct TcpFrame {
    sequence: u32,
    acknowledgement: Option<u32>,
    syn: bool,
    fin: bool,
}

/// Encode fixture TCP segments with the mature packet builder rather than custom wire checksums.
fn tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    flags: TcpFrame,
    payload: &[u8],
) -> Vec<u8> {
    let builder = match (source, destination) {
        (SocketAddr::V4(source), SocketAddr::V4(destination)) => PacketBuilder::ipv4(
            source.ip().octets(),
            destination.ip().octets(),
            64,
        )
        .tcp(source.port(), destination.port(), flags.sequence, 65535),
        (SocketAddr::V6(source), SocketAddr::V6(destination)) => PacketBuilder::ipv6(
            source.ip().octets(),
            destination.ip().octets(),
            64,
        )
        .tcp(source.port(), destination.port(), flags.sequence, 65535),
        _ => unreachable!(),
    };
    let builder = if let Some(acknowledgement) = flags.acknowledgement {
        builder.ack(acknowledgement)
    } else {
        builder
    };
    let builder = if flags.syn { builder.syn() } else { builder };
    let builder = if flags.fin { builder.fin() } else { builder };
    let mut packet = Vec::new();
    builder.write(&mut packet, payload).unwrap();
    packet
}

/// Raw TCP handshakes carry an actual response sent only after the destination receives EOF.
#[tokio::test]
async fn tcp_packet_sessions_preserve_half_close_in_both_families() {
    let (_server, mut engine) = engine().await;
    for (local, bind) in [
        ("192.0.2.2:5000", "127.0.0.1:0"),
        ("[fd99::2]:5001", "[::1]:0"),
    ] {
        let source = local.parse().unwrap();
        let listener = TcpListener::bind(bind).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut input = Vec::new();
            socket.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"packet TCP");
            socket.write_all(b"response after EOF").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        engine
            .sender()
            .try_send(tcp_packet(
                source,
                destination,
                TcpFrame {
                    sequence: 100,
                    acknowledgement: None,
                    syn: true,
                    fin: false,
                },
                b"",
            ))
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(3), engine.receive())
            .await
            .unwrap()
            .unwrap();
        let parsed = SlicedPacket::from_ip(&syn_ack).unwrap();
        let Some(TransportSlice::Tcp(tcp)) = parsed.transport else {
            panic!("expected TCP SYN ACK");
        };
        assert!(tcp.syn() && tcp.ack());
        let mut ack = tcp.sequence_number().wrapping_add(1);
        engine
            .sender()
            .try_send(tcp_packet(
                source,
                destination,
                TcpFrame {
                    sequence: 101,
                    acknowledgement: Some(ack),
                    syn: false,
                    fin: false,
                },
                b"",
            ))
            .unwrap();
        engine
            .sender()
            .try_send(tcp_packet(
                source,
                destination,
                TcpFrame {
                    sequence: 101,
                    acknowledgement: Some(ack),
                    syn: false,
                    fin: true,
                },
                b"packet TCP",
            ))
            .unwrap();
        let mut response = Vec::new();
        loop {
            let packet = timeout(Duration::from_secs(3), engine.receive())
                .await
                .unwrap()
                .unwrap();
            let parsed = SlicedPacket::from_ip(&packet).unwrap();
            let Some(TransportSlice::Tcp(tcp)) = parsed.transport else {
                continue;
            };
            if tcp.sequence_number() == ack {
                response.extend_from_slice(tcp.payload());
                ack = ack
                    .wrapping_add(tcp.payload().len() as u32)
                    .wrapping_add(u32::from(tcp.fin()));
            }
            engine
                .sender()
                .try_send(tcp_packet(
                    source,
                    destination,
                    TcpFrame {
                        sequence: 101 + b"packet TCP".len() as u32 + 1,
                        acknowledgement: Some(ack),
                        syn: false,
                        fin: false,
                    },
                    b"",
                ))
                .unwrap();
            if tcp.fin() {
                break;
            }
        }
        assert_eq!(response, b"response after EOF");
        target.await.unwrap();
    }
    engine.stop().await.unwrap();
}

/// A native test context copies borrowed lifecycle bytes into an owned channel.
struct NativeContext {
    events: std::sync::mpsc::Sender<Vec<u8>>,
}

/// Copy bounded C callback bytes while the fixture context remains alive through destroy.
unsafe extern "C" fn native_event(context: *mut std::ffi::c_void, data: *const u8, length: usize) {
    // SAFETY: the fixture passes a live boxed context and the bridge borrows valid callback bytes.
    let context = unsafe { &*(context as *const NativeContext) };
    // SAFETY: callback storage remains valid until this callback returns.
    let data = unsafe { std::slice::from_raw_parts(data, length) }.to_vec();
    let _ = context.events.send(data);
}

/// Ignore native packet callbacks in lifecycle tests that do not inject application traffic.
unsafe extern "C" fn native_packet(_: *mut std::ffi::c_void, _: *const u8, _: usize) {}

/// The native ABI authenticates using embedded PEM even when profile file paths do not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_bridge_uses_embedded_identity_and_joins_before_destroy_returns() {
    let tunnel = support::Tunnel::start(Config::default());
    let directory = tunnel.directory();
    let payload = serde_json::to_vec(&serde_json::json!({
        "client": { "server": tunnel.address.to_string(), "server_name": "localhost",
            "ca": "/not/shared/ca.pem", "cert": "/not/shared/client.pem", "key": "/not/shared/client.key" },
        "ca_pem": std::fs::read_to_string(directory.join("ca.pem")).unwrap(),
        "cert_pem": std::fs::read_to_string(directory.join("client.pem")).unwrap(),
        "key_pem": std::fs::read_to_string(directory.join("client.key")).unwrap(), "mtu": 1500,
    })).unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut context = Box::new(NativeContext { events: sender });
    // SAFETY: fixture storage and callbacks remain live until the one owned destroy call completes.
    let handle = unsafe {
        zion::packet_ffi::zion_packet_create(
            payload.as_ptr(),
            payload.len(),
            native_packet,
            native_event,
            (&mut *context as *mut NativeContext).cast(),
        )
    };
    assert!(!handle.is_null());
    let ready = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&ready).unwrap()["event"],
        "ready"
    );
    // SAFETY: no packet send races with this unique owned handle's destruction.
    unsafe {
        zion::packet_ffi::zion_packet_destroy(handle);
    }
    let stopped = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&stopped).unwrap()["event"],
        "stopped"
    );
    assert!(receiver.try_recv().is_err());
}

/// An invalid native envelope cannot allocate a worker or leak parser diagnostics.
#[test]
fn native_bridge_rejects_invalid_envelopes_before_spawning() {
    let payload = b"invalid";
    // SAFETY: the invalid envelope is readable and no callback can run before successful parsing.
    let handle = unsafe {
        zion::packet_ffi::zion_packet_create(
            payload.as_ptr(),
            payload.len(),
            native_packet,
            native_event,
            std::ptr::null_mut(),
        )
    };
    assert!(handle.is_null());
}
