//! TCP/TLS carrier tests use real loopback sockets and preserve QUIC as a separate explicit mode.

use fast_socks5::{new_udp_header, util::target_addr::TargetAddr};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zion::{
    server::Config,
    tunnel::{
        Client, ServerTransport, Transport, TunnelServer,
        auth::Password,
        tls::{self, Identity},
    },
};

/// A fixture owns private identities and one supervised listener configuration.
struct Fixture {
    directory: tempfile::TempDir,
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}

/// Fixture operations choose authentication independently from the selected carrier.
impl Fixture {
    /// Bind a loopback server using a password, certificate policy, or both.
    fn start(
        mode: ServerTransport,
        password: Option<&str>,
        certificates: bool,
        listen: &str,
        config: Config,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let identity = directory.path().join("identity");
        tls::generate(&identity, "localhost").unwrap();
        let ca = certificates.then(|| identity.join("ca.pem"));
        let server = Identity::server_from_files(
            &identity.join("server.pem"),
            &identity.join("server.key"),
            ca.as_deref(),
        )
        .unwrap();
        let server = TunnelServer::bind_transport(
            listen.parse().unwrap(),
            server,
            config,
            password.map(|v| Password::new(v).unwrap()),
            mode,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server.run(shutdown.clone()));
        Self {
            directory,
            address,
            shutdown,
            task,
        }
    }

    /// Locate this fixture's private test identity files.
    fn identity(&self) -> PathBuf {
        self.directory.path().join("identity")
    }

    /// Prepare a client with explicit trust and no implicit transport fallback.
    fn client(
        &self,
        transport: Transport,
        password: Option<&str>,
        certificate: bool,
        name: &str,
    ) -> Arc<Client> {
        let identity = self.identity();
        let cert = certificate.then(|| identity.join("client.pem"));
        let key = certificate.then(|| identity.join("client.key"));
        let identity = Identity::client_from_files(
            Some(&identity.join("ca.pem")),
            cert.as_deref(),
            key.as_deref(),
        )
        .unwrap();
        Client::with_transport(
            vec![self.address],
            name.into(),
            identity,
            None,
            password.map(|v| Password::new(v).unwrap()),
            transport,
        )
        .unwrap()
    }
}

/// Fixture cleanup cannot leave authenticated sessions or listener tasks behind.
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

/// Both TCP address families preserve 128 KiB and response-after-EOF through the TCP/TLS carrier.
#[tokio::test]
async fn tcp_half_close_and_large_response_in_both_families() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let client = fixture.client(Transport::Tls, Some("secret"), false, "localhost");
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let target = TcpListener::bind(bind).await.unwrap();
        let address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut data = Vec::new();
            socket.read_to_end(&mut data).await.unwrap();
            socket.write_all(&data).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let mut session = client
            .tcp(&TargetAddr::Ip(address), Duration::from_secs(2))
            .await
            .unwrap();
        assert!(session.guard.is_none());
        let payload: Vec<_> = (0..128 * 1024).map(|v| v as u8).collect();
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
        echo.await.unwrap();
    }
}

/// UDP envelopes preserve IPv4, IPv6, empty payloads, and packets larger than QUIC datagrams.
#[tokio::test]
async fn udp_envelopes_preserve_boundaries_and_large_payloads() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let client = fixture.client(Transport::Tls, Some("secret"), false, "localhost");
    let session = client.udp(Duration::from_secs(2)).await.unwrap();
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let target = UdpSocket::bind(bind).await.unwrap();
        let header = new_udp_header(target.local_addr().unwrap()).unwrap();
        for payload in [Vec::new(), vec![42; 8192], b"after large packet".to_vec()] {
            let mut envelope = header.clone();
            envelope.extend_from_slice(&payload);
            assert_eq!(
                session.send_datagram(envelope.into()).unwrap(),
                zion::datagram::SendOutcome::Sent
            );
            let mut bytes = vec![0; 65535];
            let (length, source) = timeout(Duration::from_secs(2), target.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..length], payload);
            target.send_to(&payload, source).await.unwrap();
            let mut expected = header.clone();
            expected.extend_from_slice(&payload);
            assert_eq!(
                timeout(Duration::from_secs(2), session.receive_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                expected
            );
        }
    }
}

/// A wrong password cannot create a destination connection even after a valid TLS handshake.
#[tokio::test]
async fn authentication_failure_never_opens_a_destination() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = fixture.client(Transport::Tls, Some("wrong"), false, "localhost");
    assert!(
        client
            .tcp(
                &TargetAddr::Ip(target.local_addr().unwrap()),
                Duration::from_secs(1)
            )
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(80), target.accept())
            .await
            .is_err()
    );
}

/// Both configured factors remain mandatory for TLS and a hostname mismatch is never bypassed.
#[tokio::test]
async fn certificate_and_password_requirements_are_preserved() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        true,
        "127.0.0.1:0",
        Config::default(),
    );
    assert!(
        fixture
            .client(Transport::Tls, Some("secret"), true, "localhost")
            .udp(Duration::from_secs(2))
            .await
            .is_ok()
    );
    assert!(
        fixture
            .client(Transport::Tls, None, true, "localhost")
            .udp(Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(
        fixture
            .client(Transport::Tls, Some("secret"), false, "localhost")
            .udp(Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(
        fixture
            .client(Transport::Tls, Some("secret"), true, "wrong.example")
            .udp(Duration::from_secs(1))
            .await
            .is_err()
    );
}

/// Certificate-only authentication works without sending a password proof.
#[tokio::test]
async fn certificate_only_carrier_authenticates() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        None,
        true,
        "127.0.0.1:0",
        Config::default(),
    );
    assert!(
        fixture
            .client(Transport::Tls, None, true, "localhost")
            .udp(Duration::from_secs(2))
            .await
            .is_ok()
    );
    assert!(
        fixture
            .client(Transport::Tls, Some("unexpected"), true, "localhost")
            .udp(Duration::from_secs(1))
            .await
            .is_err()
    );
}

/// One server accepts both network protocols on the same numeric port without carrier negotiation.
#[tokio::test]
async fn both_carriers_share_a_port_and_authentication_policy() {
    let fixture = Fixture::start(
        ServerTransport::Both,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let quic = fixture.client(Transport::Quic, Some("secret"), false, "localhost");
    let tls = fixture.client(Transport::Tls, Some("secret"), false, "localhost");
    let (a, b) = tokio::join!(
        quic.udp(Duration::from_secs(2)),
        tls.udp(Duration::from_secs(2))
    );
    assert!(a.is_ok() && b.is_ok());
    assert!(a.unwrap().guard.is_some() && b.unwrap().guard.is_none());
}

/// TLS mode remains usable when the same-number UDP port is an unresponsive black hole.
#[tokio::test]
async fn tls_does_not_depend_on_udp() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let _blackhole = UdpSocket::bind(fixture.address).await.unwrap();
    assert!(
        fixture
            .client(Transport::Tls, Some("secret"), false, "localhost")
            .udp(Duration::from_secs(1))
            .await
            .is_ok()
    );
    assert!(
        fixture
            .client(Transport::Quic, Some("secret"), false, "localhost")
            .udp(Duration::from_millis(200))
            .await
            .is_err()
    );
}

/// A stalled TCP peer cannot consume a TLS handshake slot beyond the configured deadline.
#[tokio::test]
async fn handshake_timeout_releases_shared_capacity() {
    let config = Config {
        handshake_timeout: Duration::from_millis(80),
        max_connections: 1.try_into().unwrap(),
        ..Config::default()
    };
    let fixture = Fixture::start(
        ServerTransport::Both,
        Some("secret"),
        false,
        "127.0.0.1:0",
        config,
    );
    let mut stalled = TcpStream::connect(fixture.address).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(1), stalled.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        fixture
            .client(Transport::Tls, Some("secret"), false, "localhost")
            .udp(Duration::from_secs(1))
            .await
            .is_ok()
    );
}

/// The TCP and UDP listeners share one combined connection budget.
#[tokio::test]
async fn both_carriers_share_admission_capacity() {
    let config = Config {
        max_connections: 1.try_into().unwrap(),
        ..Config::default()
    };
    let fixture = Fixture::start(
        ServerTransport::Both,
        Some("secret"),
        false,
        "127.0.0.1:0",
        config,
    );
    let held = fixture
        .client(Transport::Tls, Some("secret"), false, "localhost")
        .udp(Duration::from_secs(2))
        .await
        .unwrap();
    let quic = fixture.client(Transport::Quic, Some("secret"), false, "localhost");
    assert!(quic.udp(Duration::from_millis(200)).await.is_err());
    drop(held);
    timeout(Duration::from_secs(3), async {
        loop {
            if quic.udp(Duration::from_millis(300)).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

/// IPv6 transport also accepts IPv4 clients through an explicit dual-stack wildcard listener.
#[tokio::test]
async fn tls_dual_stack_listener_accepts_both_families() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "[::]:0",
        Config::default(),
    );
    for host in ["127.0.0.1", "::1"] {
        let mut address = fixture.address;
        address.set_ip(host.parse().unwrap());
        let identity =
            Identity::client_from_files(Some(&fixture.identity().join("ca.pem")), None, None)
                .unwrap();
        let client = Client::with_transport(
            vec![address],
            "localhost".into(),
            identity,
            None,
            Some(Password::new("secret").unwrap()),
            Transport::Tls,
        )
        .unwrap();
        assert!(client.udp(Duration::from_secs(2)).await.is_ok());
    }
}

/// Obtain a raw TLS stream for adversarial framed-protocol tests using the maintained TLS implementation.
async fn raw_tls(
    fixture: &Fixture,
    certificate: bool,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let identity = fixture.identity();
    let cert = certificate.then(|| identity.join("client.pem"));
    let key = certificate.then(|| identity.join("client.key"));
    let config = Identity::client_from_files(
        Some(&identity.join("ca.pem")),
        cert.as_deref(),
        key.as_deref(),
    )
    .unwrap()
    .client_tls(b"zion-tls/1")
    .unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            "localhost".try_into().unwrap(),
            TcpStream::connect(fixture.address).await.unwrap(),
        )
        .await
        .unwrap()
}

/// Write a bounded control request without sharing the production parser under test.
async fn request(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    value: &serde_json::Value,
) {
    let bytes = serde_json::to_vec(value).unwrap();
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
}

/// Read the protocol's bounded success response independently of its production reader.
async fn success(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) {
    let length = stream.read_u16().await.unwrap();
    assert!(length <= 4096);
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["status"],
        0
    );
}

/// Proofs accepted on one TLS connection cannot authenticate another connection.
#[tokio::test]
async fn password_proof_cannot_be_replayed_on_another_tls_connection() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let mut first = raw_tls(&fixture, false).await;
    let binding = first
        .get_ref()
        .1
        .export_keying_material(
            [0u8; 32],
            b"EXPORTER-zion-password-v1",
            Some(br#"[1,"Udp"]"#),
        )
        .unwrap();
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"secret"),
        &binding,
    );
    let value = serde_json::json!({"version":1,"operation":"Udp","auth":tag.as_ref()});
    request(&mut first, &value).await;
    success(&mut first).await;
    let mut second = raw_tls(&fixture, false).await;
    request(&mut second, &value).await;
    let mut byte = [0];
    let result = timeout(Duration::from_secs(1), second.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
}

/// An oversized declared UDP frame closes its authenticated session before receiving the body.
#[tokio::test]
async fn oversized_udp_frame_closes_session() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        None,
        true,
        "127.0.0.1:0",
        Config::default(),
    );
    let mut stream = raw_tls(&fixture, true).await;
    request(
        &mut stream,
        &serde_json::json!({"version":1,"operation":"Udp"}),
    )
    .await;
    success(&mut stream).await;
    stream.write_u32(65536).await.unwrap();
    let mut byte = [0];
    let result = timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
}

/// Closing the server cancels established TLS associations and pending reads.
#[tokio::test]
async fn shutdown_closes_established_tls_association() {
    let fixture = Fixture::start(
        ServerTransport::Both,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let session = fixture
        .client(Transport::Tls, Some("secret"), false, "localhost")
        .udp(Duration::from_secs(1))
        .await
        .unwrap();
    fixture.shutdown.cancel();
    assert!(
        timeout(Duration::from_secs(2), session.receive_datagram())
            .await
            .unwrap()
            .is_err()
    );
}

/// The SOCKS TCP entry delegates through TLS while preserving response-after-half-close.
#[tokio::test]
async fn socks_tcp_uses_tls_carrier() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        tunnel: Some(fixture.client(Transport::Tls, Some("secret"), false, "localhost")),
        ..Config::default()
    };
    let proxy = zion::server::Server::bind(config).await.unwrap();
    let address = proxy.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(proxy.run(shutdown.clone()));
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        socket.write_all(&data).await.unwrap();
    });
    let mut stream = fast_socks5::client::Socks5Stream::connect(
        address,
        destination.ip().to_string(),
        destination.port(),
        fast_socks5::client::Config::default(),
    )
    .await
    .unwrap();
    stream.write_all(b"SOCKS over TLS").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"SOCKS over TLS");
    echo.await.unwrap();
    shutdown.cancel();
    task.await.unwrap().unwrap();
}

/// The SOCKS UDP adapter uses TLS framing instead of attempting a QUIC datagram send.
#[tokio::test]
async fn socks_udp_uses_tls_carrier() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        tunnel: Some(fixture.client(Transport::Tls, Some("secret"), false, "localhost")),
        ..Config::default()
    };
    let proxy = zion::server::Server::bind(config).await.unwrap();
    let address = proxy.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(proxy.run(shutdown.clone()));
    let socket = fast_socks5::client::Socks5Datagram::bind(
        TcpStream::connect(address).await.unwrap(),
        "127.0.0.1:0",
    )
    .await
    .unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    socket.send_to(b"UDP via TCP", destination).await.unwrap();
    let mut bytes = vec![0; 65535];
    let (length, peer) = timeout(Duration::from_secs(2), target.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..length], b"UDP via TCP");
    target.send_to(b"reply", peer).await.unwrap();
    let (length, source) = timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..length], b"reply");
    assert_eq!(source, TargetAddr::Ip(destination));
    drop(socket);
    shutdown.cancel();
    task.await.unwrap().unwrap();
}

/// Destination refusal preserves its SOCKS error code instead of becoming an unrelated carrier failure.
#[tokio::test]
async fn destination_refusal_preserves_status() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    drop(target);
    let error = fixture
        .client(Transport::Tls, Some("secret"), false, "localhost")
        .tcp(&TargetAddr::Ip(address), Duration::from_secs(2))
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.downcast_ref::<fast_socks5::ReplyError>(),
        Some(fast_socks5::ReplyError::ConnectionRefused)
    ));
}

/// The shared packet engine can establish a TLS association without a local SOCKS listener.
#[cfg(feature = "packet-tunnel")]
#[tokio::test]
async fn packet_engine_uses_tls_carrier() {
    let fixture = Fixture::start(
        ServerTransport::Tls,
        Some("secret"),
        false,
        "127.0.0.1:0",
        Config::default(),
    );
    let config = Config {
        tunnel: Some(fixture.client(Transport::Tls, Some("secret"), false, "localhost")),
        ..Config::default()
    };
    let mut engine = zion::packet::PacketTunnel::start(config, 1500)
        .await
        .unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let builder = etherparse::PacketBuilder::ipv4([192, 0, 2, 2], [127, 0, 0, 1], 64)
        .udp(4500, address.port());
    let mut packet = Vec::new();
    builder.write(&mut packet, b"packet via TLS").unwrap();
    engine.sender().try_send(packet).unwrap();
    let mut bytes = [0; 128];
    let (length, peer) = timeout(Duration::from_secs(2), target.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..length], b"packet via TLS");
    target.send_to(b"reply", peer).await.unwrap();
    let packet = timeout(Duration::from_secs(2), engine.receive())
        .await
        .unwrap()
        .unwrap();
    let parsed = etherparse::SlicedPacket::from_ip(&packet).unwrap();
    let Some(etherparse::TransportSlice::Udp(udp)) = parsed.transport else {
        panic!("expected UDP response")
    };
    assert_eq!(udp.payload(), b"reply");
    engine.stop().await.unwrap();
}
