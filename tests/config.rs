//! Configuration tests exercise minimal schemas, authentication modes, and CLI precedence.

use std::{net::SocketAddr, process::Command, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zion::{
    config::{ClientConfig, ServerConfig},
    tunnel::{Client, auth::Password, tls},
};

/// A configured pair owns its files and aborts its test server when released.
struct Pair {
    _directory: TempDir,
    client: std::sync::Arc<Client>,
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}

/// Pair operations exercise configuration loading before starting any tunnel sessions.
impl Pair {
    /// Build matching client and server files using password, certificate, or combined authentication.
    async fn open(password: bool, certificate: bool) -> Self {
        Self::open_transport(password, certificate, "quic").await
    }

    /// Select the carrier through the same JSON/YAML schema used by deployed clients and servers.
    async fn open_transport(password: bool, certificate: bool, transport: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        tls::generate(&directory.path().join("identity"), "127.0.0.1").unwrap();
        let mut server = serde_json::json!({"listen":"127.0.0.1:0", "cert":"identity/server.pem", "key":"identity/server.key"});
        server["transport"] = transport.into();
        if password {
            server["password"] = "shared-secret-for-tests".into();
        }
        if certificate {
            server["ca"] = "identity/ca.pem".into();
        }
        let server_path = directory.path().join("server.json");
        std::fs::write(&server_path, server.to_string()).unwrap();
        let server = ServerConfig::load(&server_path).unwrap().build().unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server.run(shutdown.clone()));
        let mut client =
            format!("server: {address}\ntransport: {transport}\nca: identity/ca.pem\n");
        if password {
            client.push_str("password: shared-secret-for-tests\n");
        }
        if certificate {
            client.push_str("cert: identity/client.pem\nkey: identity/client.key\n");
        }
        let client_path = directory.path().join("client.yaml");
        std::fs::write(&client_path, client).unwrap();
        let config = ClientConfig::load(&client_path)
            .unwrap()
            .build()
            .await
            .unwrap();
        assert_eq!(
            config.listen,
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );
        Self {
            _directory: directory,
            client: config.tunnel.unwrap(),
            address,
            shutdown,
            task,
        }
    }
}

/// Releasing a configured pair stops its listener before temporary credentials disappear.
impl Drop for Pair {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

/// Exercise actual TCP and UDP forwarding through an authenticated configured pair.
async fn forwards(password: bool, certificate: bool) {
    forwards_transport(password, certificate, "quic").await;
}

/// Both carrier modes forward the same TCP/UDP commands from real configuration files.
async fn forwards_transport(password: bool, certificate: bool, transport: &str) {
    let pair = Pair::open_transport(password, certificate, transport).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let producer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        socket.write_all(&request).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut tcp = pair
        .client
        .tcp(
            &fast_socks5::util::target_addr::TargetAddr::Ip(target),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    tcp.io.write_all(b"configured TCP").await.unwrap();
    tcp.io.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), tcp.io.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"configured TCP");
    tcp.acknowledged().await.unwrap();
    drop(tcp);
    producer.await.unwrap();
    let udp = pair.client.udp(Duration::from_secs(2)).await.unwrap();
    let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = fast_socks5::new_udp_header(destination.local_addr().unwrap()).unwrap();
    packet.extend_from_slice(b"configured UDP");
    assert_eq!(
        udp.send_datagram(packet.into()).unwrap(),
        zion::datagram::SendOutcome::Sent
    );
    let mut buffer = [0; 128];
    let (length, source) = timeout(Duration::from_secs(2), destination.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"configured UDP");
    destination.send_to(b"UDP reply", source).await.unwrap();
    let response = timeout(Duration::from_secs(2), udp.receive_datagram())
        .await
        .unwrap()
        .unwrap();
    let (_, _, payload) = fast_socks5::parse_udp_request(&response).await.unwrap();
    assert_eq!(payload, b"UDP reply");
}

/// Password-only configuration provides authenticated TCP and UDP without a client certificate.
#[tokio::test]
async fn password_config_forwards_tcp_and_udp() {
    forwards(true, false).await;
}

/// Certificate-only configuration preserves the existing mutual TLS authentication mode.
#[tokio::test]
async fn certificate_config_forwards_tcp_and_udp() {
    forwards(false, true).await;
}

/// Combined configuration requires and successfully supplies both authentication factors.
#[tokio::test]
async fn combined_config_forwards_tcp_and_udp() {
    forwards(true, true).await;
}

/// Equivalent JSON and YAML files use the same defaults and resolve the same credential path.
#[test]
fn json_yaml_defaults_and_relative_paths_match() {
    let directory = tempfile::tempdir().unwrap();
    let json = directory.path().join("client.json");
    let yaml = directory.path().join("client.yml");
    std::fs::write(
        &json,
        r#"{"server":"example.com:443","password":"secret-value","ca":"ca.pem"}"#,
    )
    .unwrap();
    std::fs::write(
        &yaml,
        "server: example.com:443\npassword: secret-value\nca: ca.pem\n",
    )
    .unwrap();
    let first = ClientConfig::load(&json).unwrap();
    let second = ClientConfig::load(&yaml).unwrap();
    assert_eq!(first.server, second.server);
    assert_eq!(first.listen, second.listen);
    assert_eq!(first.ca, Some(directory.path().join("ca.pem")));
    assert_eq!(first.ca, second.ca);
    let server = directory.path().join("server.json");
    std::fs::write(
        &server,
        r#"{"cert":"server.pem","key":"server.key","password":"test-value"}"#,
    )
    .unwrap();
    assert_eq!(
        ServerConfig::load(&server).unwrap().listen,
        "[::]:8443".parse::<SocketAddr>().unwrap()
    );
    assert!(first.server_name.is_none());
    assert!(!format!("{first:?}").contains("secret-value"));
}

/// Invalid fields, certificate pairs, and authentication omissions fail before network startup.
#[test]
fn rejects_invalid_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.json");
    for source in [
        r#"{"server":"example.com:443","password":"test","username":"user"}"#,
        r#"{"server":"example.com:443","cert":"client.pem"}"#,
        r#"{"server":"example.com:443"}"#,
        r#"{"server":"user@example.com:443","password":"test"}"#,
        r#"{"server":"example.com:0","password":"test"}"#,
        r#"{"server":"example.com:443","password":""}"#,
        r#"{"server":"example.com:443","password":"test","listen":"0.0.0.0:1080"}"#,
    ] {
        std::fs::write(&path, source).unwrap();
        assert!(ClientConfig::load(&path).is_err());
    }
    let server = directory.path().join("server.json");
    std::fs::write(&server, r#"{"cert":"server.pem","key":"server.key"}"#).unwrap();
    assert!(ServerConfig::load(&server).is_err());
}

/// Parser error chains never print the source password when JSON or YAML is invalid.
#[test]
fn parser_diagnostics_do_not_leak_passwords() {
    let directory = tempfile::tempdir().unwrap();
    for (name, source) in [
        (
            "client.json",
            r#"{"server":"example.com:443","password":"private-secret-do-not-print","username":"bad"}"#,
        ),
        (
            "client.yaml",
            "server: example.com:443\npassword: private-secret-do-not-print\nusername: bad\n",
        ),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, source).unwrap();
        let error = ClientConfig::load(&path).unwrap_err();
        assert!(!format!("{error:#}").contains("private-secret-do-not-print"));
        assert!(!format!("{error:?}").contains("private-secret-do-not-print"));
    }
}

/// Configuration files cannot silently ignore explicitly supplied CLI overrides.
#[test]
fn cli_rejects_mixed_file_and_inline_configuration() {
    let binary =
        std::env::var_os("ZION_TEST_BINARY").unwrap_or_else(|| env!("CARGO_BIN_EXE_zion").into());
    for role in ["client", "server"] {
        let output = Command::new(&binary)
            .args([
                role,
                "--config",
                "config.yaml",
                "--listen",
                "127.0.0.1:1234",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}

/// Unsupported filenames and oversized files fail before parsing their contents.
#[test]
fn rejects_unsupported_or_oversized_files() {
    let directory = tempfile::tempdir().unwrap();
    for (name, contents) in [
        ("client.toml", "server = 'example.com:443'".to_owned()),
        ("client.json", " ".repeat(64 * 1024 + 1)),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).unwrap();
        assert!(ClientConfig::load(&path).is_err());
    }
}

/// A wrong password cannot establish a tunnel or cause an outbound TCP connection.
#[tokio::test]
async fn wrong_password_does_not_open_destination() {
    let pair = Pair::open(true, false).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client_path = pair._directory.path().join("client.yaml");
    let text = std::fs::read_to_string(&client_path)
        .unwrap()
        .replace("shared-secret-for-tests", "wrong-password");
    std::fs::write(&client_path, text).unwrap();
    let client = ClientConfig::load(&client_path)
        .unwrap()
        .build()
        .await
        .unwrap()
        .tunnel
        .unwrap();
    let result = client
        .tcp(
            &fast_socks5::util::target_addr::TargetAddr::Ip(address),
            Duration::from_secs(2),
        )
        .await;
    assert!(result.is_err());
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

/// Basic password validation rejects empty secrets without exposing accepted secrets through Debug.
#[test]
fn password_is_redacted() {
    assert!(Password::new("").is_err());
    assert_eq!(
        format!("{:?}", Password::new("sensitive-password").unwrap()),
        "Password([redacted])"
    );
}

/// A server requiring both factors rejects either an absent certificate or an absent proof.
#[tokio::test]
async fn combined_authentication_cannot_be_downgraded() {
    use zion::tunnel::tls::Identity;
    let pair = Pair::open(true, true).await;
    let identity = pair._directory.path().join("identity");
    let without_certificate = Client::with_authentication(
        pair.address,
        "127.0.0.1".into(),
        Identity::client_from_files(Some(&identity.join("ca.pem")), None, None).unwrap(),
        None,
        Some(Password::new("shared-secret-for-tests").unwrap()),
    )
    .unwrap();
    assert!(
        without_certificate
            .udp(Duration::from_secs(2))
            .await
            .is_err()
    );
    let without_password = Client::new(
        pair.address,
        "127.0.0.1".into(),
        Identity::load(&identity, "client").unwrap(),
    )
    .unwrap();
    assert!(without_password.udp(Duration::from_secs(2)).await.is_err());
}

/// Spawn a supervised client using stdin so credentials never appear in its command line.
async fn machine_client(pair: &Pair, password: &str) -> tokio::process::Child {
    use std::process::Stdio;
    let binary =
        std::env::var_os("ZION_TEST_BINARY").unwrap_or_else(|| env!("CARGO_BIN_EXE_zion").into());
    let mut child = tokio::process::Command::new(binary)
        .args(["client", "--config", "-", "--events-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let source = serde_json::json!({
        "server": pair.address.to_string(),
        "listen": "127.0.0.1:0",
        "password": password,
        "ca": pair._directory.path().join("identity/ca.pem")
    });
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(source.to_string().as_bytes())
        .await
        .unwrap();
    drop(input);
    child
}

/// Native supervision becomes ready only after actual remote authentication succeeds.
#[tokio::test]
async fn machine_events_authenticate_before_ready_and_stop_cleanly() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let pair = Pair::open(true, false).await;
    let mut child = machine_client(&pair, "shared-secret-for-tests").await;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = timeout(Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let zion::control::Event::Ready { listen } = serde_json::from_str(&line).unwrap() else {
        panic!("expected authenticated readiness");
    };
    assert!(listen.ip().is_loopback());
    assert_ne!(listen.port(), 0);
    assert!(tokio::net::TcpStream::connect(listen).await.is_ok());
    let status = tokio::process::Command::new("kill")
        .args(["-INT", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    let line = timeout(Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<zion::control::Event>(&line).unwrap(),
        zion::control::Event::Stopped
    );
    assert!(
        timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

/// A rejected password emits an error without announcing readiness or exposing its value.
#[tokio::test]
async fn machine_events_reject_wrong_password_without_leaking_it() {
    let pair = Pair::open(true, false).await;
    let child = machine_client(&pair, "wrong-secret-native-test").await;
    let output = timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<zion::control::Event> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(matches!(
        events.as_slice(),
        [zion::control::Event::Error { .. }]
    ));
    assert!(!stdout.contains("wrong-secret-native-test"));
    assert!(!stderr.contains("wrong-secret-native-test"));
}

/// File-based TLS mode preserves password, certificate, and combined authentication for both target protocols.
#[tokio::test]
async fn tls_json_yaml_authentication_modes_forward() {
    for (password, certificate) in [(true, false), (false, true), (true, true)] {
        forwards_transport(password, certificate, "tls").await;
    }
}

/// Carrier aliases are explicit while unknown or null values cannot silently select a default.
#[test]
fn transport_configuration_is_strict_and_backward_compatible() {
    for (value, expected) in [
        ("quic", zion::tunnel::Transport::Quic),
        ("udp", zion::tunnel::Transport::Quic),
        ("tls", zion::tunnel::Transport::Tls),
        ("tcp", zion::tunnel::Transport::Tls),
    ] {
        let client: ClientConfig = serde_json::from_value(
            serde_json::json!({"server":"localhost:8443","password":"test","transport":value}),
        )
        .unwrap();
        assert_eq!(client.transport, expected);
    }
    let legacy: ClientConfig =
        serde_json::from_value(serde_json::json!({"server":"localhost:8443","password":"test"}))
            .unwrap();
    assert_eq!(legacy.transport, zion::tunnel::Transport::Quic);
    for value in [
        serde_json::Value::Null,
        serde_json::json!("auto"),
        serde_json::json!("both"),
    ] {
        assert!(
            serde_json::from_value::<ClientConfig>(
                serde_json::json!({"server":"localhost:8443","password":"test","transport":value})
            )
            .is_err()
        );
    }
}

/// Real supervised SOCKS traffic emits exact payload counters and its routing decision on stdout.
#[tokio::test]
async fn machine_traffic_reports_policy_process_and_payload_counters() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let pair = Pair::open(true, false).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        socket.write_all(&data).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut child = machine_client(&pair, "shared-secret-for-tests").await;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = timeout(Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let zion::control::Event::Ready { listen } = serde_json::from_str(&line).unwrap() else {
        panic!("expected ready");
    };
    let mut socket = tokio::net::TcpStream::connect(listen).await.unwrap();
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    socket.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    request.extend(
        fast_socks5::util::target_addr::TargetAddr::Ip(target)
            .to_be_bytes()
            .unwrap(),
    );
    socket.write_all(&request).await.unwrap();
    let mut header = [0; 4];
    timeout(Duration::from_secs(5), socket.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&header[..3], &[5, 0, 0]);
    let mut bound = vec![0; if header[3] == 1 { 6 } else { 18 }];
    socket.read_exact(&mut bound).await.unwrap();
    socket.write_all(b"counted payload").await.unwrap();
    socket.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"counted payload");
    echo.await.unwrap();
    let record = timeout(Duration::from_secs(5), async {
        loop {
            let line = lines.next_line().await.unwrap().unwrap();
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            if value["event"] == "traffic" && value["status"] == "closed" {
                break value;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(record["up"], 15);
    assert_eq!(record["down"], 15);
    assert_eq!(record["policy"], "proxy");
    assert_eq!(record["rule"], "FINAL");
    assert_eq!(record["target"], target.to_string());
    #[cfg(target_os = "macos")]
    assert_eq!(record["process"]["pid"], std::process::id());
    child.kill().await.unwrap();
}
