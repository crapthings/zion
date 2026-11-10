//! DNS integration tests cover policy isolation, indexed caching, and bounded concurrent work.

/// Fake DNS servers keep resolver tests independent of the public network and system configuration.
mod dns_support;

use dns_support::{FakeDns, Mode, Rule};
use fast_socks5::util::target_addr::TargetAddr;
use hickory_resolver::proto::rr::RecordType;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use zion::dns::Resolver;

/// Resolve one absolute domain using an independent application deadline.
async fn resolve(resolver: &Resolver, name: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    resolver
        .resolve(
            &TargetAddr::Domain(name.into(), port),
            Duration::from_secs(3),
        )
        .await
}

/// Cached A and AAAA records share normalized names across requests for different business ports.
#[tokio::test]
async fn indexed_cache_reuses_case_and_port_independent_records() {
    let dns = FakeDns::start(Rule::default(), false).await;
    let resolver = dns.resolver();
    let first = resolve(&resolver, "Cache.Zion.Test", 80).await.unwrap();
    let second = resolve(&resolver, "cache.zion.test.", 443).await.unwrap();
    assert_eq!(first.len(), 2);
    assert!(first.iter().any(SocketAddr::is_ipv4));
    assert!(first.iter().any(SocketAddr::is_ipv6));
    assert!(second.iter().all(|address| address.port() == 443));
    assert_eq!(dns.count(RecordType::A), 1);
    assert_eq!(dns.count(RecordType::AAAA), 1);
}

/// Concurrent callers share one dual-record lookup even when one caller cancels early.
#[tokio::test]
async fn concurrent_queries_merge_and_caller_timeout_does_not_cancel_others() {
    let dns = FakeDns::start(
        Rule {
            delay: Duration::from_millis(150),
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = dns.resolver();
    let target = TargetAddr::Domain("shared.zion.test".into(), 80);
    let first = resolver.resolve(&target, Duration::from_millis(30));
    let others = async {
        let mut tasks = tokio::task::JoinSet::new();
        for port in 1000..1032 {
            let resolver = resolver.clone();
            tasks
                .spawn(async move { resolve(&resolver, "SHARED.ZION.TEST.", port).await.unwrap() });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap().len(), 2);
        }
    };
    let (expired, ()) = tokio::join!(first, others);
    assert_eq!(expired.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(dns.count(RecordType::A), 1);
    assert_eq!(dns.count(RecordType::AAAA), 1);
}

/// TTL expiration triggers fresh records while a zero TTL never becomes a reusable cache entry.
#[tokio::test]
async fn positive_ttl_expires_and_zero_ttl_is_not_cached() {
    let dns = FakeDns::start(
        Rule {
            ttl: 1,
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = dns.resolver();
    resolve(&resolver, "expiry.zion.test.", 80).await.unwrap();
    dns.set_rule(Rule {
        v4: Ipv4Addr::new(127, 0, 0, 2),
        ..Rule::default()
    });
    tokio::time::sleep(Duration::from_millis(1150)).await;
    let fresh = resolve(&resolver, "expiry.zion.test.", 80).await.unwrap();
    assert!(fresh.contains(&"127.0.0.2:80".parse().unwrap()));
    assert_eq!(dns.count(RecordType::A), 2);

    let zero = FakeDns::start(
        Rule {
            ttl: 0,
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = zero.resolver();
    for _ in 0..2 {
        resolve(&resolver, "zero.zion.test.", 80).await.unwrap();
        tokio::task::yield_now().await;
    }
    assert_eq!(zero.count(RecordType::A), 2);
    assert_eq!(zero.count(RecordType::AAAA), 2);
}

/// NXDOMAIN and NODATA are cached using their SOA lifetime rather than queried on every request.
#[tokio::test]
async fn negative_answers_cache_and_expire() {
    for mode in [Mode::NxDomain, Mode::NoData] {
        let dns = FakeDns::start(
            Rule {
                mode,
                ttl: 1,
                ..Rule::default()
            },
            false,
        )
        .await;
        let resolver = dns.resolver();
        for _ in 0..2 {
            assert_eq!(
                resolve(&resolver, "absent.zion.test.", 80)
                    .await
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
        }
        assert_eq!(dns.count(RecordType::A), 1);
        assert_eq!(dns.count(RecordType::AAAA), 1);
        tokio::time::sleep(Duration::from_millis(1150)).await;
        assert!(resolve(&resolver, "absent.zion.test.", 80).await.is_err());
        assert_eq!(dns.count(RecordType::A), 2);
    }
}

/// A successful A answer remains usable when the AAAA query returns a temporary server failure.
#[tokio::test]
async fn partial_family_failure_keeps_successful_records() {
    let dns = FakeDns::start(
        Rule {
            aaaa_servfail: true,
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = dns.resolver();
    let addresses = resolve(&resolver, "partial.zion.test.", 80).await.unwrap();
    assert_eq!(
        addresses,
        vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()]
    );
    let aaaa_queries = dns.count(RecordType::AAAA);
    assert_eq!(
        resolve(&resolver, "partial.zion.test.", 80).await.unwrap(),
        addresses
    );
    assert_eq!(dns.count(RecordType::A), 1);
    assert_eq!(dns.count(RecordType::AAAA), aaaa_queries);
    dns.set_rule(Rule::default());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        resolve(&resolver, "partial.zion.test.", 80)
            .await
            .unwrap()
            .len(),
        2
    );
}

/// Transient failures use short backoff and recover without a false persistent negative cache.
#[tokio::test]
async fn servfail_backoff_is_short_and_not_nxdomain() {
    let dns = FakeDns::start(
        Rule {
            mode: Mode::ServFail,
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = dns.resolver();
    assert_ne!(
        resolve(&resolver, "recover.zion.test.", 80)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    let count = dns.count(RecordType::A);
    assert!(resolve(&resolver, "recover.zion.test.", 80).await.is_err());
    assert_eq!(dns.count(RecordType::A), count);
    dns.set_rule(Rule::default());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        resolve(&resolver, "recover.zion.test.", 80)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(dns.count(RecordType::A) > count);
}

/// A shorter CNAME lifetime bounds the lifetime of an otherwise long-lived address answer.
#[tokio::test]
async fn cname_chain_respects_shortest_ttl() {
    let dns = FakeDns::start(
        Rule {
            cname_ttl: Some(1),
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = dns.resolver();
    resolve(&resolver, "alias.zion.test.", 80).await.unwrap();
    resolve(&resolver, "alias.zion.test.", 80).await.unwrap();
    assert_eq!(dns.count(RecordType::A), 1);
    tokio::time::sleep(Duration::from_millis(1150)).await;
    resolve(&resolver, "alias.zion.test.", 80).await.unwrap();
    assert_eq!(dns.count(RecordType::A), 2);
}

/// A truncated UDP response is completed over the configured upstream's actual TCP port.
#[tokio::test]
async fn truncated_udp_falls_back_to_tcp() {
    let dns = FakeDns::start(
        Rule {
            truncate_udp: true,
            ..Rule::default()
        },
        false,
    )
    .await;
    assert_eq!(
        resolve(&dns.resolver(), "truncated.zion.test.", 80)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(dns.tcp_count() >= 2);
}

/// An IPv6 upstream can resolve both target families using an explicit nonstandard port.
#[tokio::test]
async fn ipv6_upstream_resolves_both_target_families() {
    let dns = FakeDns::start(Rule::default(), true).await;
    assert_eq!(
        resolve(&dns.resolver(), "ipv6.zion.test.", 80)
            .await
            .unwrap()
            .len(),
        2
    );
}

/// Independent DNS policies must not share answers even when their query names are identical.
#[tokio::test]
async fn resolver_policies_have_separate_caches() {
    let first = FakeDns::start(Rule::default(), false).await;
    let second = FakeDns::start(
        Rule {
            v4: Ipv4Addr::new(127, 0, 0, 9),
            ..Rule::default()
        },
        false,
    )
    .await;
    let left = resolve(&first.resolver(), "split.zion.test.", 80)
        .await
        .unwrap();
    let right = resolve(&second.resolver(), "split.zion.test.", 80)
        .await
        .unwrap();
    assert!(left.contains(&"127.0.0.1:80".parse().unwrap()));
    assert!(right.contains(&"127.0.0.9:80".parse().unwrap()));
}

/// Literal destinations bypass unreachable upstreams and default mode retains normal system lookup.
#[tokio::test]
async fn ip_literals_bypass_dns_and_system_mode_stays_compatible() {
    let dns = FakeDns::start(
        Rule {
            mode: Mode::Drop,
            ..Rule::default()
        },
        false,
    )
    .await;
    let address = "[::1]:443".parse().unwrap();
    assert_eq!(
        dns.resolver()
            .resolve(&TargetAddr::Ip(address), Duration::from_secs(1))
            .await
            .unwrap(),
        vec![address]
    );
    assert_eq!(dns.count(RecordType::A), 0);
    assert!(
        !resolve(&Resolver::default(), "localhost", 80)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Explicit upstream validation rejects empty groups, hostnames, URLs, and unusable addresses.
#[test]
fn invalid_upstreams_are_rejected_before_network_startup() {
    for values in [
        vec![],
        vec!["dns.example.com"],
        vec!["https://dns.example/dns-query"],
        vec!["0.0.0.0"],
        vec!["[::]:53"],
        vec!["127.0.0.1:0"],
        vec!["224.0.0.1"],
    ] {
        let strings = values.into_iter().map(String::from).collect::<Vec<_>>();
        assert!(Resolver::custom(&strings).is_err());
    }
    assert!(Resolver::custom(&vec!["1.1.1.1".to_owned(); 9]).is_err());
}

/// A configured tunnel fixture owns its temporary credentials and supervised server task.
struct ConfiguredTunnel {
    client: std::sync::Arc<zion::tunnel::Client>,
    shutdown: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    _files: tempfile::TempDir,
}

/// A fixture starts the real server from JSON so tests cover configuration-to-egress plumbing.
impl ConfiguredTunnel {
    /// Build an authenticated server with the requested custom DNS group.
    fn start(dns: Vec<String>) -> Self {
        use zion::tunnel::{
            Client,
            auth::Password,
            tls::{self, Identity},
        };
        let files = tempfile::tempdir().unwrap();
        let identity = files.path().join("identity");
        tls::generate(&identity, "localhost").unwrap();
        let config = serde_json::json!({
            "listen": "127.0.0.1:0", "cert": "identity/server.pem", "key": "identity/server.key",
            "password": "dns-integration-only", "dns": dns,
        });
        let path = files.path().join("server.json");
        std::fs::write(&path, config.to_string()).unwrap();
        let server = zion::config::ServerConfig::load(&path)
            .unwrap()
            .build()
            .unwrap();
        let client = Client::with_authentication(
            server.local_addr().unwrap(),
            "localhost".into(),
            Identity::client_from_files(Some(&identity.join("ca.pem")), None, None).unwrap(),
            None,
            Some(Password::new("dns-integration-only").unwrap()),
        )
        .unwrap();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(server.run(shutdown.clone()));
        Self {
            client,
            shutdown,
            task,
            _files: files,
        }
    }
}

/// Releasing a configured fixture stops only its own listener and removes its temporary files.
impl Drop for ConfiguredTunnel {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

/// Server-configured TCP and UDP sessions must share one custom resolver and its native cache.
#[tokio::test]
async fn server_configuration_applies_dns_to_tcp_and_udp_with_shared_cache() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        time::timeout,
    };
    let dns = FakeDns::start(Rule::default(), false).await;
    let tunnel = ConfiguredTunnel::start(vec![dns.address.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut input = Vec::new();
        socket.read_to_end(&mut input).await.unwrap();
        socket.write_all(&input).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut tcp = tunnel
        .client
        .tcp(
            &TargetAddr::Domain("remote.zion.test.".into(), port),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    tcp.io.write_all(b"custom DNS TCP").await.unwrap();
    tcp.io.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), tcp.io.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"custom DNS TCP");
    tcp.acknowledged().await.unwrap();
    drop(tcp);
    echo.await.unwrap();

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    for _ in 0..2 {
        let session = tunnel.client.udp(Duration::from_secs(3)).await.unwrap();
        let mut packet = fast_socks5::new_udp_header(TargetAddr::Domain(
            "REMOTE.ZION.TEST".into(),
            address.port(),
        ))
        .unwrap();
        packet.extend_from_slice(b"custom DNS UDP");
        session.send_datagram(packet.into()).unwrap();
        let mut buffer = [0; 128];
        let (size, peer) = timeout(Duration::from_secs(3), udp.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], b"custom DNS UDP");
        udp.send_to(&buffer[..size], peer).await.unwrap();
        let response = timeout(Duration::from_secs(3), session.guard.0.read_datagram())
            .await
            .unwrap()
            .unwrap();
        let (fragment, source, payload) = fast_socks5::parse_udp_request(&response).await.unwrap();
        assert_eq!(fragment, 0);
        assert_eq!(source, TargetAddr::Ip(address));
        assert_eq!(payload, b"custom DNS UDP");
    }
    assert_eq!(dns.count(RecordType::A), 1);
    assert_eq!(dns.count(RecordType::AAAA), 1);
}

/// Another configured upstream remains usable when a peer returns a temporary resolver failure.
#[tokio::test]
async fn configured_upstream_group_recovers_from_failed_peer() {
    let failed = FakeDns::start(
        Rule {
            mode: Mode::ServFail,
            ..Rule::default()
        },
        false,
    )
    .await;
    let working = FakeDns::start(
        Rule {
            delay: Duration::from_millis(50),
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver =
        Resolver::custom(&[failed.address.to_string(), working.address.to_string()]).unwrap();
    assert_eq!(
        resolve(&resolver, "upstream.zion.test.", 80)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(working.count(RecordType::A), 1);
    let failed_queries = failed.count(RecordType::A);
    tokio::time::sleep(Duration::from_millis(600)).await;
    for port in 81..85 {
        assert_eq!(
            resolve(&resolver, "upstream.zion.test.", port)
                .await
                .unwrap()
                .len(),
            2
        );
    }
    assert_eq!(working.count(RecordType::A), 1);
    assert_eq!(failed.count(RecordType::A), failed_queries);
}

/// A custom policy queries a single-label name directly instead of using the system hosts or search domains.
#[tokio::test]
async fn custom_dns_does_not_use_system_hosts_or_search_domains() {
    let dns = FakeDns::start(
        Rule {
            v4: Ipv4Addr::new(127, 0, 0, 9),
            ..Rule::default()
        },
        false,
    )
    .await;
    let result = resolve(&dns.resolver(), "ip6-localhost", 80).await.unwrap();
    assert!(result.contains(&"127.0.0.9:80".parse().unwrap()));
    assert_eq!(dns.count(RecordType::A), 1);
}

/// A configured negative response must reach the caller without querying a system fallback.
#[tokio::test]
async fn custom_negative_result_is_not_replaced_by_system_resolution() {
    let dns = FakeDns::start(
        Rule {
            mode: Mode::NxDomain,
            ..Rule::default()
        },
        false,
    )
    .await;
    assert_eq!(
        resolve(&dns.resolver(), "ip6-localhost", 80)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(dns.count(RecordType::A), 1);
}

/// Empty and malformed custom DNS arrays fail through both supported configuration formats.
#[test]
fn json_yaml_validate_dns_before_server_build() {
    let files = tempfile::tempdir().unwrap();
    let json = files.path().join("server.json");
    let yaml = files.path().join("server.yaml");
    std::fs::write(&json, r#"{"cert":"server.pem","key":"server.key","password":"test","dns":["1.1.1.1","[::1]:5353"]}"#).unwrap();
    std::fs::write(
        &yaml,
        "cert: server.pem\nkey: server.key\npassword: test\ndns: [1.1.1.1, '[::1]:5353']\n",
    )
    .unwrap();
    assert_eq!(
        zion::config::ServerConfig::load(&json).unwrap().dns,
        zion::config::ServerConfig::load(&yaml).unwrap().dns
    );
    for value in [
        serde_json::json!([]),
        serde_json::json!(["dns.example"]),
        serde_json::json!(["127.0.0.1:0"]),
        serde_json::json!("1.1.1.1"),
    ] {
        let config = serde_json::json!({"cert":"server.pem","key":"server.key","password":"test","dns":value});
        std::fs::write(&json, config.to_string()).unwrap();
        assert!(zion::config::ServerConfig::load(&json).is_err());
    }
}

/// A slow lookup for one name must not hold the registry lock while another name reaches upstream.
#[tokio::test]
async fn unrelated_names_make_progress_concurrently() {
    let dns = FakeDns::start(
        Rule {
            delay: Duration::from_millis(400),
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = dns.resolver();
    let first = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolve(&resolver, "first.zion.test.", 80).await.unwrap() })
    };
    let second = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolve(&resolver, "second.zion.test.", 80).await.unwrap() })
    };
    tokio::time::timeout(Duration::from_millis(300), async {
        while dns.count(RecordType::A) < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(first.await.unwrap().len(), 2);
    assert_eq!(second.await.unwrap().len(), 2);
}

/// Every caller can leave without causing a permanent pending-name slot or an abandoned duplicate query.
#[tokio::test]
async fn abandoned_waiters_do_not_strand_shared_work() {
    let dns = FakeDns::start(
        Rule {
            delay: Duration::from_millis(120),
            ..Rule::default()
        },
        false,
    )
    .await;
    let resolver = dns.resolver();
    let target = TargetAddr::Domain("abandoned.zion.test.".into(), 80);
    assert!(
        resolver
            .resolve(&target, Duration::from_millis(30))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(
        resolve(&resolver, "abandoned.zion.test.", 80)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(dns.count(RecordType::A), 1);
}
