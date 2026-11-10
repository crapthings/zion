//! Tunnel security tests reject invalid trust material before permitting egress.

/// Shared fixtures provide isolated QUIC identities and listeners.
mod support;

use fast_socks5::util::target_addr::TargetAddr;
use std::time::Duration;
use zion::{server::Config, tunnel::tls};

/// A trusted CA cannot make a mismatched server hostname acceptable.
#[tokio::test]
async fn rejects_wrong_server_name() {
    let tunnel = support::Tunnel::start(Config::default());
    let client = tunnel.client(&tunnel.directory(), "wrong.example");
    assert!(client.udp(Duration::from_secs(2)).await.is_err());
}

/// A client trusting a different CA cannot establish an authenticated tunnel.
#[tokio::test]
async fn rejects_untrusted_server() {
    let tunnel = support::Tunnel::start(Config::default());
    let other = tempfile::tempdir().unwrap();
    let directory = other.path().join("other");
    tls::generate(&directory, "localhost").unwrap();
    let client = tunnel.client(&directory, "localhost");
    assert!(client.udp(Duration::from_secs(2)).await.is_err());
}

/// A server rejects a client certificate even when that client trusts its server CA.
#[tokio::test]
async fn rejects_untrusted_client() {
    let tunnel = support::Tunnel::start(Config::default());
    let other = tempfile::tempdir().unwrap();
    let directory = other.path().join("other");
    tls::generate(&directory, "localhost").unwrap();
    std::fs::copy(tunnel.directory().join("ca.pem"), directory.join("ca.pem")).unwrap();
    let client = tunnel.client(&directory, "localhost");
    assert!(client.udp(Duration::from_secs(2)).await.is_err());
}

/// Credential issuance refuses to overwrite a directory containing existing keys.
#[test]
fn credentials_are_not_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let identity = directory.path().join("identity");
    tls::generate(&identity, "localhost").unwrap();
    let original = std::fs::read(identity.join("server.key")).unwrap();
    assert!(tls::generate(&identity, "localhost").is_err());
    assert_eq!(
        original,
        std::fs::read(identity.join("server.key")).unwrap()
    );
}

/// Oversized UDP packets are rejected locally without closing an authenticated association.
#[tokio::test]
async fn oversized_datagram_preserves_association() {
    let tunnel = support::Tunnel::start(Config::default());
    let client = tunnel.client(&tunnel.directory(), "localhost");
    let session = client.udp(Duration::from_secs(2)).await.unwrap();
    use zion::datagram::{DropReason, SendOutcome};
    assert_eq!(
        session.send_datagram(vec![0; 65_535].into()).unwrap(),
        SendOutcome::Dropped(DropReason::TooLarge)
    );
    let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let header = fast_socks5::new_udp_header(remote.local_addr().unwrap()).unwrap();
    let mut request = header.clone();
    request.extend_from_slice(b"valid after oversize");
    assert_eq!(
        session.send_datagram(request.into()).unwrap(),
        SendOutcome::Sent
    );
    let mut buffer = [0; 128];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(2), remote.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..length], b"valid after oversize");
    remote.send_to(b"reply", source).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), session.guard.0.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let mut expected = header;
    expected.extend_from_slice(b"reply");
    assert_eq!(&response[..], &expected);
}

/// A failed TLS handshake never reports a destination connection as successful.
#[tokio::test]
async fn failed_authentication_never_opens_tcp_session() {
    let tunnel = support::Tunnel::start(Config::default());
    let client = tunnel.client(&tunnel.directory(), "wrong.example");
    let target = TargetAddr::Ip("127.0.0.1:9".parse().unwrap());
    assert!(client.tcp(&target, Duration::from_secs(2)).await.is_err());
}

/// A valid server certificate cannot be repurposed as a client authentication identity.
#[tokio::test]
async fn rejects_wrong_certificate_role() {
    let tunnel = support::Tunnel::start(Config::default());
    let other = tempfile::tempdir().unwrap();
    for (source, destination) in [
        ("ca.pem", "ca.pem"),
        ("server.pem", "client.pem"),
        ("server.key", "client.key"),
    ] {
        std::fs::copy(
            tunnel.directory().join(source),
            other.path().join(destination),
        )
        .unwrap();
    }
    let client = tunnel.client(other.path(), "localhost");
    assert!(client.udp(Duration::from_secs(2)).await.is_err());
}

/// A raw peer fixture exposes stream controls for transport-level failure regressions.
struct Peer {
    _client: std::sync::Arc<zion::tunnel::Client>,
    _credentials: tempfile::TempDir,
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    _send: quinn::SendStream,
    receive: quinn::RecvStream,
    session: zion::tunnel::Session,
    request: serde_json::Value,
}

/// Peer fixture operations establish a genuine authenticated control exchange.
impl Peer {
    /// Open an authenticated UDP session against a peer controlled by the regression test.
    async fn open() -> Self {
        Self::with_password(None).await
    }

    /// Capture a request from a client optionally supplying a password proof.
    async fn with_password(password: Option<zion::tunnel::auth::Password>) -> Self {
        tokio::time::timeout(Duration::from_secs(3), async {
            use tokio::io::AsyncReadExt;
            use zion::tunnel::{Client, tls::Identity};
            let credentials = tempfile::tempdir().unwrap();
            let directory = credentials.path().join("identity");
            tls::generate(&directory, "localhost").unwrap();
            let config = Identity::load(&directory, "server")
                .unwrap()
                .server()
                .unwrap();
            let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let client = Client::with_authentication(
                endpoint.local_addr().unwrap(),
                "localhost".into(),
                Identity::load(&directory, "client").unwrap(),
                None,
                password,
            )
            .unwrap();
            let opening = tokio::spawn(async move {
                // Keep the client's endpoint alive until the fixture releases the session.
                let session = client.udp(Duration::from_secs(2)).await.unwrap();
                (client, session)
            });
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let length = receive.read_u16().await.unwrap() as usize;
            let mut request = vec![0; length];
            receive.read_exact(&mut request).await.unwrap();
            let response = br#"{"status":0,"bound":"0.0.0.0:0"}"#;
            send.write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            send.write_all(response).await.unwrap();
            let (client, session) = opening.await.unwrap();
            Self {
                _client: client,
                _credentials: credentials,
                _endpoint: endpoint,
                connection,
                _send: send,
                receive,
                session,
                request: serde_json::from_slice(&request).unwrap(),
            }
        })
        .await
        .unwrap()
    }
}

/// An explicit peer stop must not be reported as successful stream acknowledgement.
#[tokio::test]
async fn acknowledgement_rejects_peer_stop_code() {
    let mut peer = Peer::open().await;
    peer.receive.stop(42u8.into()).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(2), peer.session.acknowledged())
        .await
        .unwrap()
        .unwrap_err();
    assert!(format!("{error:#}").contains("peer stopped QUIC send stream with code 42"));
}

/// A finished stream acknowledged by the peer completes successfully.
#[tokio::test]
async fn acknowledgement_accepts_finished_stream() {
    let mut peer = Peer::open().await;
    peer.session.io.writer_mut().finish().unwrap();
    tokio::time::timeout(Duration::from_secs(2), peer.receive.read_to_end(1))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), peer.session.acknowledged())
        .await
        .unwrap()
        .unwrap();
}

/// A closed transport is a fatal datagram error instead of a recoverable packet drop.
#[tokio::test]
async fn datagram_reports_closed_connection() {
    let peer = Peer::open().await;
    peer.connection.close(7u8.into(), b"test shutdown");
    tokio::time::timeout(Duration::from_secs(2), peer.session.guard.0.closed())
        .await
        .unwrap();
    let error = peer
        .session
        .send_datagram(bytes::Bytes::from_static(b"packet"))
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<quinn::SendDatagramError>(),
        Some(quinn::SendDatagramError::ConnectionLost(_))
    ));
}

/// The server keeps an acknowledged response available until the client consumes it.
#[tokio::test]
async fn drained_server_waits_for_client_close() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };
    let tunnel = support::Tunnel::start(Config::default());
    let client = tunnel.client(&tunnel.directory(), "localhost");
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let (produced, completion) = tokio::sync::oneshot::channel();
    let producer = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        socket.write_all(&vec![0x5a; 256 * 1024]).await.unwrap();
        socket.shutdown().await.unwrap();
        produced.send(()).unwrap();
    });
    let mut session = client
        .tcp(&TargetAddr::Ip(address), Duration::from_secs(2))
        .await
        .unwrap();
    session.io.writer_mut().finish().unwrap();
    timeout(Duration::from_secs(2), completion)
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        session.guard.0.close_reason().is_none(),
        "server closed before client consumed the response"
    );
    let mut response = Vec::new();
    timeout(
        Duration::from_secs(2),
        session.io.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.len(), 256 * 1024);
    assert!(response.iter().all(|byte| *byte == 0x5a));
    timeout(Duration::from_secs(2), session.acknowledged())
        .await
        .unwrap()
        .unwrap();
    producer.await.unwrap();
}

/// An invalid requested interface fails client startup instead of using the default route.
#[tokio::test]
async fn rejects_unknown_egress_interface() {
    use zion::tunnel::{Client, tls::Identity};
    let tunnel = support::Tunnel::start(Config::default());
    assert!(
        Client::new_with_interface(
            tunnel.address,
            "localhost".into(),
            Identity::load(&tunnel.directory(), "client").unwrap(),
            Some("zion-test-none")
        )
        .is_err()
    );
}

/// Explicit macOS loopback egress can complete an authenticated QUIC session.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn accepts_macos_loopback_egress() {
    use zion::tunnel::{Client, tls::Identity};
    let tunnel = support::Tunnel::start(Config::default());
    let client = Client::new_with_interface(
        tunnel.address,
        "localhost".into(),
        Identity::load(&tunnel.directory(), "client").unwrap(),
        Some("lo0"),
    )
    .unwrap();
    assert!(client.udp(Duration::from_secs(2)).await.is_ok());
}

/// A captured password proof contains no plaintext password and cannot authenticate another connection.
#[tokio::test]
async fn password_proof_cannot_be_replayed() {
    use zion::tunnel::{TunnelServer, auth::Password, tls::Identity};
    let secret = "password-never-sent-as-plaintext";
    let peer = Peer::with_password(Some(Password::new(secret).unwrap())).await;
    assert!(peer.request.get("auth").unwrap().is_array());
    assert!(!peer.request.to_string().contains(secret));
    let directory = peer._credentials.path().join("identity");
    let identity = Identity::server_from_files(
        &directory.join("server.pem"),
        &directory.join("server.key"),
        None,
    )
    .unwrap();
    let server = TunnelServer::bind_with_password(
        "127.0.0.1:0".parse().unwrap(),
        identity,
        Config::default(),
        Some(Password::new(secret).unwrap()),
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let running = tokio::spawn(server.run(tokio_util::sync::CancellationToken::new()));
    let _running = tokio_util::task::AbortOnDropHandle::new(running);
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        Identity::client_from_files(Some(&directory.join("ca.pem")), None, None)
            .unwrap()
            .client()
            .unwrap(),
    );
    let connection = tokio::time::timeout(
        Duration::from_secs(2),
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut send, _receive) = connection.open_bi().await.unwrap();
    let request = serde_json::to_vec(&peer.request).unwrap();
    send.write_all(&(request.len() as u16).to_be_bytes())
        .await
        .unwrap();
    send.write_all(&request).await.unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(2), connection.closed())
        .await
        .unwrap();
    assert!(
        matches!(reason, quinn::ConnectionError::ApplicationClosed(error) if error.error_code == 16u8.into())
    );
}

/// A TCP destination echoes a substantial response after the tunneled request half-closes.
async fn dual_tcp_echo(client: &zion::tunnel::Client, bind: &str) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };
    let target = TcpListener::bind(bind).await.unwrap();
    let address = target.local_addr().unwrap();
    let payload = vec![if address.is_ipv6() { 6 } else { 4 }; 64 * 1024];
    let expected = payload.clone();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut input = Vec::new();
        socket.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, expected);
        socket.write_all(&input).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut session = client
        .tcp(&TargetAddr::Ip(address), Duration::from_secs(3))
        .await
        .unwrap();
    session.io.write_all(&payload).await.unwrap();
    session.io.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(
        Duration::from_secs(3),
        session.io.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, payload);
    session.acknowledged().await.unwrap();
    drop(session);
    echo.await.unwrap();
}

/// One authenticated UDP association exchanges packets with both address families concurrently.
async fn dual_udp_echo(client: &zion::tunnel::Client) {
    use fast_socks5::{new_udp_header, parse_udp_request};
    use tokio::{net::UdpSocket, time::timeout};
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
    let addresses = [v4.local_addr().unwrap(), v6.local_addr().unwrap()];
    let session = client.udp(Duration::from_secs(3)).await.unwrap();
    for (index, address) in addresses.iter().enumerate() {
        let mut packet = new_udp_header(*address).unwrap();
        packet.push(index as u8);
        assert_eq!(
            session.send_datagram(packet.into()).unwrap(),
            zion::datagram::SendOutcome::Sent
        );
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
        let packet = timeout(Duration::from_secs(3), session.guard.0.read_datagram())
            .await
            .unwrap()
            .unwrap();
        let (fragment, source, payload) = parse_udp_request(&packet).await.unwrap();
        assert_eq!(fragment, 0);
        let index = payload[0] as usize;
        assert!(index < 2);
        assert_eq!(source, TargetAddr::Ip(addresses[index]));
        assert!(received.insert(index));
    }
    assert_eq!(received.len(), 2);
}

/// A single explicit dual-stack listener accepts both tunnel families while forwarding mixed TCP and UDP.
#[tokio::test]
async fn dual_stack_listener_forwards_mixed_families_concurrently() {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use zion::tunnel::{Client, tls::Identity};
    let tunnel = support::Tunnel::start_on(Config::default(), "[::]:0".parse().unwrap());
    let port = tunnel.address.port();
    let v4 = Client::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        "localhost".into(),
        Identity::load(&tunnel.directory(), "client").unwrap(),
    )
    .unwrap();
    let v6 = Client::new(
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        "localhost".into(),
        Identity::load(&tunnel.directory(), "client").unwrap(),
    )
    .unwrap();
    tokio::join!(
        dual_tcp_echo(&v4, "127.0.0.1:0"),
        dual_tcp_echo(&v4, "[::1]:0"),
        dual_udp_echo(&v4),
        dual_tcp_echo(&v6, "127.0.0.1:0"),
        dual_tcp_echo(&v6, "[::1]:0"),
        dual_udp_echo(&v6),
    );
}

/// A silently dropped preferred QUIC path must fall back in either family direction.
#[tokio::test]
async fn quic_address_racing_bypasses_blackholes_in_either_family() {
    use tokio::{
        net::UdpSocket,
        time::{Instant, timeout},
    };
    use zion::tunnel::{Client, tls::Identity};
    for (listen, blackhole) in [("127.0.0.1:0", "[::1]:0"), ("[::1]:0", "127.0.0.1:0")] {
        let tunnel = support::Tunnel::start_on(Config::default(), listen.parse().unwrap());
        let sink = UdpSocket::bind(blackhole).await.unwrap();
        let client = Client::with_addresses(
            vec![sink.local_addr().unwrap(), tunnel.address],
            "localhost".into(),
            Identity::load(&tunnel.directory(), "client").unwrap(),
            None,
            None,
        )
        .unwrap();
        let started = Instant::now();
        let session = timeout(Duration::from_secs(3), client.udp(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            session.guard.0.remote_address().is_ipv4(),
            tunnel.address.is_ipv4()
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}

/// Racing TLS paths must send a TCP proxy operation only to the winning authenticated connection.
#[tokio::test]
async fn quic_racing_does_not_duplicate_destination_connections() {
    use tokio::{net::TcpListener, time::timeout};
    use zion::tunnel::{Client, tls::Identity};
    let tunnel = support::Tunnel::start_on(Config::default(), "[::]:0".parse().unwrap());
    let port = tunnel.address.port();
    let client = Client::with_addresses(
        vec![
            format!("[::1]:{port}").parse().unwrap(),
            format!("127.0.0.1:{port}").parse().unwrap(),
        ],
        "localhost".into(),
        Identity::load(&tunnel.directory(), "client").unwrap(),
        None,
        None,
    )
    .unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let session = client
        .tcp(
            &TargetAddr::Ip(target.local_addr().unwrap()),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    let _accepted = timeout(Duration::from_secs(2), target.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_millis(400), target.accept())
            .await
            .is_err()
    );
    drop(session);
}

/// IPv6 literal configuration reaches a verified IPv6-only server without bracketed-name errors.
#[tokio::test]
async fn ipv6_literal_client_configuration_authenticates() {
    let tunnel = support::Tunnel::start_on(Config::default(), "[::1]:0".parse().unwrap());
    let config = serde_json::json!({
        "server": tunnel.address.to_string(), "server_name": "localhost",
        "ca": tunnel.directory().join("ca.pem"),
        "cert": tunnel.directory().join("client.pem"), "key": tunnel.directory().join("client.key")
    });
    let path = tunnel.credentials.path().join("ipv6.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let client = zion::config::ClientConfig::load(&path)
        .unwrap()
        .build()
        .await
        .unwrap()
        .tunnel
        .unwrap();
    client.udp(Duration::from_secs(3)).await.unwrap();
}

/// Server hostname configuration retains every available family without requiring a specific hosts file.
#[tokio::test]
async fn localhost_configuration_uses_available_server_address_families() {
    let addresses = tokio::net::lookup_host(("localhost", 1))
        .await
        .unwrap()
        .collect::<Vec<_>>();
    assert!(!addresses.is_empty());
    for listen in ["127.0.0.1:0", "[::1]:0"] {
        let wanted = listen.parse::<std::net::SocketAddr>().unwrap();
        if !addresses
            .iter()
            .any(|address| address.is_ipv6() == wanted.is_ipv6())
        {
            continue;
        }
        let tunnel = support::Tunnel::start_on(Config::default(), listen.parse().unwrap());
        let config = serde_json::json!({
            "server": format!("localhost:{}", tunnel.address.port()),
            "ca": tunnel.directory().join("ca.pem"),
            "cert": tunnel.directory().join("client.pem"), "key": tunnel.directory().join("client.key")
        });
        let path = tunnel.credentials.path().join("hostname.json");
        std::fs::write(&path, config.to_string()).unwrap();
        let client = zion::config::ClientConfig::load(&path)
            .unwrap()
            .build()
            .await
            .unwrap()
            .tunnel
            .unwrap();
        client.udp(Duration::from_secs(3)).await.unwrap();
    }
}

/// An IPv6 IP SAN validates the literal remote address without requiring a DNS-name override.
#[tokio::test]
async fn ipv6_ip_san_authenticates_without_server_name_override() {
    let tunnel = support::Tunnel::start_named(Config::default(), "[::1]:0".parse().unwrap(), "::1");
    let config = serde_json::json!({
        "server": tunnel.address.to_string(),
        "ca": tunnel.directory().join("ca.pem"),
        "cert": tunnel.directory().join("client.pem"), "key": tunnel.directory().join("client.key")
    });
    let path = tunnel.credentials.path().join("ipv6-san.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let client = zion::config::ClientConfig::load(&path)
        .unwrap()
        .build()
        .await
        .unwrap()
        .tunnel
        .unwrap();
    client.udp(Duration::from_secs(3)).await.unwrap();
}
