//! TUN transport tests use packet fixtures and real QUIC without creating interfaces or changing routes.
#![cfg(all(feature = "tun-device", any(target_os = "macos", target_os = "linux")))]

/// Loopback QUIC fixtures provide real authentication without remote network dependencies.
mod support;

use etherparse::PacketBuilder;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{UdpSocket, UnixDatagram},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zion::{
    packet::{DEFAULT_MTU, PacketTunnel},
    server::Config,
    tun::{PacketDevice, TunOptions, forward},
};

/// Resolve the native test binary or an explicitly staged cross-platform test executable.
fn command() -> std::process::Command {
    std::process::Command::new(
        std::env::var_os("ZION_TEST_BINARY").unwrap_or_else(|| env!("CARGO_BIN_EXE_zion").into()),
    )
}

/// A packet fixture implements device I/O with Unix datagrams while leaving all system interfaces untouched.
struct FixtureDevice {
    socket: UnixDatagram,
    partial_write: bool,
}

/// Fixture reads and writes retain packet boundaries and can inject a short-write failure.
impl PacketDevice for FixtureDevice {
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(packet).await
    }
    async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        if self.partial_write {
            return Ok(packet.len().saturating_sub(1));
        }
        self.socket.send(packet).await
    }
}

/// A failed reader proves the packet engine and every cloned ingress handle are stopped on I/O errors.
struct FailedDevice;

/// Failed device reads return an I/O error while writes never become ready.
impl PacketDevice for FailedDevice {
    async fn recv(&self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("fixture read failure"))
    }
    async fn send(&self, _: &[u8]) -> io::Result<usize> {
        std::future::pending().await
    }
}

/// A blocked writer simulates a device that cannot accept responses while shutdown remains responsive.
struct BlockedWriter {
    socket: UnixDatagram,
    started: Arc<tokio::sync::Notify>,
}

/// The fixture signals that writing began and then waits indefinitely without blocking the executor.
impl PacketDevice for BlockedWriter {
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(packet).await
    }
    async fn send(&self, _: &[u8]) -> io::Result<usize> {
        self.started.notify_one();
        std::future::pending().await
    }
}

/// Create an authenticated packet engine backed by a trusted local QUIC server.
async fn engine() -> (support::Tunnel, PacketTunnel) {
    let remote = support::Tunnel::start(Config::default());
    let config = Config {
        tunnel: Some(remote.client(&remote.directory(), "localhost")),
        ..Config::default()
    };
    let engine = PacketTunnel::start(config, DEFAULT_MTU).await.unwrap();
    (remote, engine)
}

/// Build one checksum-correct raw UDP packet with etherparse rather than implementing IP framing.
fn packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let builder = match (source, destination) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            PacketBuilder::ipv4(s.ip().octets(), d.ip().octets(), 64).udp(s.port(), d.port())
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            PacketBuilder::ipv6(s.ip().octets(), d.ip().octets(), 64).udp(s.port(), d.port())
        }
        _ => unreachable!(),
    };
    let mut bytes = Vec::new();
    builder.write(&mut bytes, payload).unwrap();
    bytes
}

/// Device input and output traverse the real netstack and QUIC transport for IPv4 and IPv6 UDP.
#[tokio::test]
async fn device_packets_roundtrip_both_families() {
    let (_remote, engine) = engine().await;
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let shutdown = CancellationToken::new();
    let driver = tokio::spawn(forward(
        FixtureDevice {
            socket,
            partial_write: false,
        },
        engine,
        shutdown.clone(),
    ));
    for (source, bind) in [
        ("192.0.2.2:4500", "127.0.0.1:0"),
        ("[fd99::2]:4501", "[::1]:0"),
    ] {
        let source: SocketAddr = source.parse().unwrap();
        let target = UdpSocket::bind(bind).await.unwrap();
        let destination = target.local_addr().unwrap();
        for payload in [b"device roundtrip".as_slice(), b"".as_slice()] {
            peer.send(&packet(source, destination, payload))
                .await
                .unwrap();
            let mut buffer = vec![0; 4096];
            let (length, remote) = timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..length], payload);
            target.send_to(payload, remote).await.unwrap();
            let length = timeout(Duration::from_secs(3), peer.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..length], packet(destination, source, payload));
        }
    }
    shutdown.cancel();
    let statistics = timeout(Duration::from_secs(3), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(statistics.accepted, 4);
    assert_eq!(statistics.written, 4);
    assert_eq!(statistics.dropped, 0);
}

/// Malformed and oversized packets are dropped while a subsequent valid packet still reaches its target.
#[tokio::test]
async fn malformed_and_oversized_input_does_not_stop_forwarding() {
    let (_remote, engine) = engine().await;
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let shutdown = CancellationToken::new();
    let driver = tokio::spawn(forward(
        FixtureDevice {
            socket,
            partial_write: false,
        },
        engine,
        shutdown.clone(),
    ));
    peer.send(&[0; 20]).await.unwrap();
    peer.send(&vec![0; DEFAULT_MTU + 20]).await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send(&packet(
        "192.0.2.2:4500".parse().unwrap(),
        target.local_addr().unwrap(),
        b"valid",
    ))
    .await
    .unwrap();
    let mut buffer = [0; 32];
    assert_eq!(
        timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap()
            .0,
        5
    );
    shutdown.cancel();
    let statistics = timeout(Duration::from_secs(3), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(statistics.dropped, 2);
    assert_eq!(statistics.accepted, 1);
}

/// An ingress error stops the underlying engine instead of leaving cloned senders accepting packets.
#[tokio::test]
async fn read_failure_stops_engine() {
    let (_remote, engine) = engine().await;
    let input = engine.sender();
    assert!(
        timeout(
            Duration::from_secs(3),
            forward(FailedDevice, engine, CancellationToken::new())
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(
        input
            .try_send(packet(
                "192.0.2.2:4500".parse().unwrap(),
                "127.0.0.1:53".parse().unwrap(),
                b"stopped"
            ))
            .is_err()
    );
}

/// Device writes are atomic packets, so a short write fails rather than emitting a second partial packet.
#[tokio::test]
async fn partial_device_write_is_fatal() {
    let (_remote, engine) = engine().await;
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let driver = tokio::spawn(forward(
        FixtureDevice {
            socket,
            partial_write: true,
        },
        engine,
        CancellationToken::new(),
    ));
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send(&packet(
        "192.0.2.2:4500".parse().unwrap(),
        target.local_addr().unwrap(),
        b"request",
    ))
    .await
    .unwrap();
    let mut buffer = [0; 32];
    let (_, remote) = timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    target.send_to(b"response", remote).await.unwrap();
    let error = timeout(Duration::from_secs(3), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("partial TUN packet write"));
}

/// Validation catches invalid MTUs, zero prefixes, and unsafe addresses without constructing a device.
#[test]
fn options_validate_before_device_creation() {
    let mut options = TunOptions::default();
    assert!(options.validate().is_err());
    options.ipv4 = Some("198.18.0.1/30".parse().unwrap());
    assert!(options.validate().is_ok());
    options.mtu = 1279;
    assert!(options.validate().is_err());
    options.mtu = 1500;
    for address in ["0.0.0.0/24", "127.0.0.1/8", "224.0.0.1/24", "198.18.0.1/0"] {
        options.ipv4 = Some(address.parse().unwrap());
        assert!(options.validate().is_err());
    }
    options.ipv4 = None;
    for address in ["::/64", "::1/128", "ff02::1/64", "fe80::1/64", "fd77::1/0"] {
        options.ipv6 = Some(address.parse().unwrap());
        assert!(options.validate().is_err());
    }
    options.ipv6 = Some("fd77::1/64".parse().unwrap());
    assert!(options.validate().is_ok());
    options.name = Some("bad/name".into());
    assert!(options.validate().is_err());
}

/// Cancellation interrupts an indefinitely blocked device write and joins the owned packet engine.
#[tokio::test]
async fn cancellation_interrupts_a_blocked_device_write() {
    let (_remote, engine) = engine().await;
    let input = engine.sender();
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let shutdown = CancellationToken::new();
    let driver = tokio::spawn(forward(
        BlockedWriter {
            socket,
            started: started.clone(),
        },
        engine,
        shutdown.clone(),
    ));
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = packet(
        "192.0.2.2:4500".parse().unwrap(),
        target.local_addr().unwrap(),
        b"request",
    );
    peer.send(&request).await.unwrap();
    let mut buffer = [0; 32];
    let (_, remote) = timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    target.send_to(b"response", remote).await.unwrap();
    timeout(Duration::from_secs(3), started.notified())
        .await
        .unwrap();
    shutdown.cancel();
    let statistics = timeout(Duration::from_secs(3), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(statistics.written, 0);
    assert!(input.try_send(request).is_err());
}

/// The CLI exposes the feature without opening a device merely to display usage.
#[test]
fn cli_help_does_not_require_tun_permissions() {
    let output = command().args(["tun", "--help"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--ipv4") && help.contains("--ipv6"));
}

/// Invalid device settings fail before loading credentials or attempting privileged interface creation.
#[test]
fn invalid_cli_settings_fail_before_accessing_configuration() {
    let output = command()
        .args([
            "tun",
            "-c",
            "/nonexistent/zion-client.json",
            "--ipv4",
            "198.18.0.1/30",
            "--mtu",
            "1279",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("virtual MTU") && !error.contains("cannot open configuration"));
}
