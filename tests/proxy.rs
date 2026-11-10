//! Loopback integration tests exercise SOCKS5 behavior without external services.

use fast_socks5::{new_udp_header, parse_udp_request, util::target_addr::TargetAddr};
/// Shared fixtures provide isolated QUIC identities and listeners.
mod support;

use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zion::server::{Config, Server};

/// A test proxy cancels its background task when its owner is dropped.
struct Proxy {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
    _tunnel: Option<support::Tunnel>,
}

/// Test fixture operations start and stop an isolated proxy.
impl Proxy {
    /// Start a proxy on an OS-assigned loopback port.
    async fn start(mut config: Config, tunneled: bool) -> Self {
        let tunnel = tunneled.then(|| support::Tunnel::start(config.clone()));
        if let Some(tunnel) = &tunnel {
            config.tunnel = Some(tunnel.client(&tunnel.directory(), "localhost"));
        }
        config.listen.set_port(0);
        config.shutdown_grace = config.shutdown_grace.min(Duration::from_millis(200));
        let server = Server::bind(config).await.unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server.run(shutdown.clone()));
        Self {
            address,
            shutdown,
            task,
            _tunnel: tunnel,
        }
    }

    /// Stop the proxy and verify that its supervised tasks drain promptly.
    async fn stop(&mut self) {
        self.shutdown.cancel();
        timeout(Duration::from_secs(2), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

/// Dropping a fixture prevents failed tests from leaking proxy tasks.
impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

/// Negotiate SOCKS5 without authentication over a fresh control connection.
async fn negotiate(address: SocketAddr) -> TcpStream {
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    timeout(Duration::from_secs(2), socket.read_exact(&mut method))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(method, [5, 0]);
    socket
}

/// Send a command and decode its response address independently of the server parser.
async fn command(socket: &mut TcpStream, command: u8, target: TargetAddr) -> (u8, SocketAddr) {
    let mut packet = vec![5, command, 0];
    packet.extend(target.to_be_bytes().unwrap());
    socket.write_all(&packet).await.unwrap();
    let mut header = [0; 4];
    timeout(Duration::from_secs(2), socket.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(header[0], 5);
    assert_eq!(header[2], 0);
    let ip = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            std::net::IpAddr::from(bytes)
        }
        4 => {
            let mut bytes = [0; 16];
            socket.read_exact(&mut bytes).await.unwrap();
            std::net::IpAddr::from(bytes)
        }
        other => panic!("unexpected reply address type {other}"),
    };
    let port = socket.read_u16().await.unwrap();
    (header[1], SocketAddr::new(ip, port))
}

/// TCP forwarding preserves payloads and permits a response after the client half-closes.
async fn tcp_domain_and_half_close_scenario(tunneled: bool) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, vec![42; 128 * 1024]);
        socket.write_all(b"response after EOF").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut proxy = Proxy::start(Config::default(), tunneled).await;
    let mut socket = negotiate(proxy.address).await;
    let (status, _) = command(&mut socket, 1, TargetAddr::Domain("localhost".into(), port)).await;
    assert_eq!(status, 0);
    socket.write_all(&vec![42; 128 * 1024]).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"response after EOF");
    echo.await.unwrap();
    proxy.stop().await;
}

/// A refused outbound connection returns failure rather than premature success.
async fn tcp_refused_destination_scenario(tunneled: bool) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    drop(target);
    let mut proxy = Proxy::start(Config::default(), tunneled).await;
    let mut socket = negotiate(proxy.address).await;
    assert_eq!(command(&mut socket, 1, TargetAddr::Ip(address)).await.0, 5);
    proxy.stop().await;
}

/// UDP forwarding rejects fragments and alternate senders and ends on control EOF.
async fn udp_roundtrip_source_pinning_and_control_close_scenario(tunneled: bool) {
    let mut proxy = Proxy::start(Config::default(), tunneled).await;
    let mut control = negotiate(proxy.address).await;
    let (status, relay) = command(
        &mut control,
        3,
        TargetAddr::Ip("0.0.0.0:0".parse().unwrap()),
    )
    .await;
    assert_eq!(status, 0);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();
    let mut packet = new_udp_header(remote_addr).unwrap();
    packet.extend_from_slice(b"datagram");
    let mut buffer = [0; 1024];
    let mut fragment = packet.clone();
    fragment[2] = 1;
    client.send_to(&fragment, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(80), remote.recv_from(&mut buffer))
            .await
            .is_err()
    );
    client.send_to(&packet, relay).await.unwrap();
    let (length, outbound) = timeout(Duration::from_secs(2), remote.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"datagram");
    remote.send_to(b"reply", outbound).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let (fragment, source, payload) = parse_udp_request(&buffer[..length]).await.unwrap();
    assert_eq!(fragment, 0);
    assert_eq!(source, TargetAddr::Ip(remote_addr));
    assert_eq!(payload, b"reply");
    let impostor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    impostor.send_to(&packet, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(80), remote.recv_from(&mut buffer))
            .await
            .is_err()
    );
    control.shutdown().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), control.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    client.send_to(&packet, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(80), remote.recv_from(&mut buffer))
            .await
            .is_err()
    );
    proxy.stop().await;
}

/// A stalled handshake releases capacity so the next client can negotiate.
async fn handshake_timeout_releases_capacity_scenario(tunneled: bool) {
    let config = Config {
        max_connections: NonZeroUsize::new(1).unwrap(),
        handshake_timeout: Duration::from_millis(100),
        ..Config::default()
    };
    let mut proxy = Proxy::start(config, tunneled).await;
    let mut stalled = TcpStream::connect(proxy.address).await.unwrap();
    stalled.write_all(&[5]).await.unwrap();
    let _next = negotiate(proxy.address).await;
    assert!(stalled.read_u8().await.is_err());
    proxy.stop().await;
}

/// UDP inactivity expires the association even when its TCP control remains open.
async fn udp_idle_timeout_closes_control_scenario(tunneled: bool) {
    let config = Config {
        udp_idle_timeout: Duration::from_millis(100),
        ..Config::default()
    };
    let mut proxy = Proxy::start(config, tunneled).await;
    let mut control = negotiate(proxy.address).await;
    assert_eq!(
        command(
            &mut control,
            3,
            TargetAddr::Ip("0.0.0.0:0".parse().unwrap())
        )
        .await
        .0,
        0
    );
    assert_eq!(
        timeout(Duration::from_secs(2), control.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    proxy.stop().await;
}

/// Shutdown aborts an active relay after the configured drain deadline.
async fn shutdown_bounds_active_session_lifetime_scenario(tunneled: bool) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config {
        shutdown_grace: Duration::from_millis(20),
        ..Config::default()
    };
    let mut proxy = Proxy::start(config, tunneled).await;
    let mut client = negotiate(proxy.address).await;
    assert_eq!(
        command(&mut client, 1, TargetAddr::Ip(target.local_addr().unwrap()))
            .await
            .0,
        0
    );
    let (_remote, _) = target.accept().await.unwrap();
    proxy.stop().await;
    assert!(client.read_u8().await.is_err());
}

/// The initial unauthenticated server rejects public listener addresses.
#[tokio::test]
async fn rejects_public_listener() {
    let config = Config {
        listen: "0.0.0.0:1080".parse().unwrap(),
        ..Config::default()
    };
    assert!(Server::bind(config).await.is_err());
}

/// Verify the scenario with direct outbound sockets.
#[tokio::test]
async fn tcp_domain_and_half_close() {
    tcp_domain_and_half_close_scenario(false).await;
}

/// Verify the same scenario through a mutually authenticated QUIC tunnel.
#[tokio::test]
async fn quic_tcp_domain_and_half_close() {
    tcp_domain_and_half_close_scenario(true).await;
}

/// Verify the scenario with direct outbound sockets.
#[tokio::test]
async fn tcp_refused_destination() {
    tcp_refused_destination_scenario(false).await;
}

/// Verify the same scenario through a mutually authenticated QUIC tunnel.
#[tokio::test]
async fn quic_tcp_refused_destination() {
    tcp_refused_destination_scenario(true).await;
}

/// Verify the scenario with direct outbound sockets.
#[tokio::test]
async fn udp_roundtrip_source_pinning_and_control_close() {
    udp_roundtrip_source_pinning_and_control_close_scenario(false).await;
}

/// Verify the same scenario through a mutually authenticated QUIC tunnel.
#[tokio::test]
async fn quic_udp_roundtrip_source_pinning_and_control_close() {
    udp_roundtrip_source_pinning_and_control_close_scenario(true).await;
}

/// Verify the scenario with direct outbound sockets.
#[tokio::test]
async fn handshake_timeout_releases_capacity() {
    handshake_timeout_releases_capacity_scenario(false).await;
}

/// Verify the same scenario through a mutually authenticated QUIC tunnel.
#[tokio::test]
async fn quic_handshake_timeout_releases_capacity() {
    handshake_timeout_releases_capacity_scenario(true).await;
}

/// Verify the scenario with direct outbound sockets.
#[tokio::test]
async fn udp_idle_timeout_closes_control() {
    udp_idle_timeout_closes_control_scenario(false).await;
}

/// Verify the same scenario through a mutually authenticated QUIC tunnel.
#[tokio::test]
async fn quic_udp_idle_timeout_closes_control() {
    udp_idle_timeout_closes_control_scenario(true).await;
}

/// Verify the scenario with direct outbound sockets.
#[tokio::test]
async fn shutdown_bounds_active_session_lifetime() {
    shutdown_bounds_active_session_lifetime_scenario(false).await;
}

/// Verify the same scenario through a mutually authenticated QUIC tunnel.
#[tokio::test]
async fn quic_shutdown_bounds_active_session_lifetime() {
    shutdown_bounds_active_session_lifetime_scenario(true).await;
}

/// A slow TCP consumer receives the complete response before a QUIC connection is released.
#[tokio::test]
async fn quic_slow_reader_receives_complete_response() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let payload = vec![0x5a; 4 * 1024 * 1024];
    let expected = payload.clone();
    let producer = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        socket.write_all(&payload).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut proxy = Proxy::start(Config::default(), true).await;
    let mut client = negotiate(proxy.address).await;
    assert_eq!(command(&mut client, 1, TargetAddr::Ip(address)).await.0, 0);
    client.shutdown().await.unwrap();
    let received = timeout(Duration::from_secs(10), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut result = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let length = client.read(&mut buffer).await.unwrap();
            if length == 0 {
                break;
            }
            result.extend_from_slice(&buffer[..length]);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        result
    })
    .await
    .unwrap();
    assert!(
        received == expected,
        "response content mismatch (received {} of {} bytes)",
        received.len(),
        expected.len()
    );
    producer.await.unwrap();
    proxy.stop().await;
}

/// A SOCKS client reaches a literal destination while preserving request half-close semantics.
async fn mixed_socks_tcp(proxy: SocketAddr, bind: &str) {
    let target = TcpListener::bind(bind).await.unwrap();
    let address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        socket.write_all(&data).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut socket = negotiate(proxy).await;
    let (status, _) = command(&mut socket, 1, TargetAddr::Ip(address)).await;
    assert_eq!(status, 0);
    let payload = vec![if address.is_ipv6() { 6 } else { 4 }; 16 * 1024];
    socket.write_all(&payload).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, payload);
    echo.await.unwrap();
}

/// One local SOCKS association returns exact IPv4 and IPv6 source envelopes to its pinned client.
async fn mixed_socks_udp(proxy: SocketAddr) {
    let mut control = negotiate(proxy).await;
    let (status, relay) = command(
        &mut control,
        3,
        TargetAddr::Ip(SocketAddr::new(proxy.ip(), 0)),
    )
    .await;
    assert_eq!(status, 0);
    let client = UdpSocket::bind(SocketAddr::new(proxy.ip(), 0))
        .await
        .unwrap();
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
    let addresses = [v4.local_addr().unwrap(), v6.local_addr().unwrap()];
    for (index, address) in addresses.iter().enumerate() {
        let mut packet = new_udp_header(*address).unwrap();
        packet.push(index as u8);
        client.send_to(&packet, relay).await.unwrap();
    }
    let echo = |socket: UdpSocket| async move {
        let mut buffer = [0; 32];
        let (size, peer) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        socket.send_to(&buffer[..size], peer).await.unwrap();
    };
    tokio::join!(echo(v4), echo(v6));
    let mut received = std::collections::HashSet::new();
    for _ in 0..2 {
        let mut buffer = [0; 128];
        let (size, source) = timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay);
        let (fragment, source, payload) = parse_udp_request(&buffer[..size]).await.unwrap();
        assert_eq!(fragment, 0);
        let index = payload[0] as usize;
        assert!(index < 2);
        assert_eq!(source, TargetAddr::Ip(addresses[index]));
        assert!(received.insert(index));
    }
}

/// Exercise both loopback listener families against mixed destinations through one proxy instance.
async fn mixed_socks_scenario(tunneled: bool) {
    for listen in ["127.0.0.1:0", "[::1]:0"] {
        let mut proxy = Proxy::start(
            Config {
                listen: listen.parse().unwrap(),
                ..Config::default()
            },
            tunneled,
        )
        .await;
        tokio::join!(
            mixed_socks_tcp(proxy.address, "127.0.0.1:0"),
            mixed_socks_tcp(proxy.address, "[::1]:0"),
            mixed_socks_udp(proxy.address),
        );
        proxy.stop().await;
    }
}

/// Direct SOCKS listeners in either family concurrently forward mixed TCP and UDP destinations.
#[tokio::test]
async fn direct_socks_supports_mixed_address_families() {
    mixed_socks_scenario(false).await;
}

/// QUIC-backed SOCKS listeners in either family concurrently forward mixed TCP and UDP destinations.
#[tokio::test]
async fn tunneled_socks_supports_mixed_address_families() {
    mixed_socks_scenario(true).await;
}

/// TCP DNS uses the families actually returned by the host without assuming localhost has AAAA.
#[tokio::test]
async fn direct_tcp_hostname_uses_available_dns_families() {
    let addresses = zion::outbound::resolve_all(
        &TargetAddr::Domain("localhost".into(), 1),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(!addresses.is_empty());
    for listen in ["127.0.0.1:0", "[::1]:0"] {
        let wanted = listen.parse::<SocketAddr>().unwrap();
        if !addresses
            .iter()
            .any(|address| address.is_ipv6() == wanted.is_ipv6())
        {
            continue;
        }
        let target = TcpListener::bind(listen).await.unwrap();
        let address = target.local_addr().unwrap();
        let stream = zion::outbound::connect(
            &TargetAddr::Domain("localhost".into(), address.port()),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
    }
}
