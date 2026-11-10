//! Explicit upstreams avoid DNS bootstrap lookups and inherited host search policies.

use anyhow::{Context, ensure};
use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

/// A small upstream group bounds connection pools and per-query fanout.
const MAX_SERVERS: usize = 8;

/// Validate literal upstream IPs with optional ports while rejecting ambiguous empty policies.
pub(crate) fn parse_servers(values: &[String]) -> anyhow::Result<Vec<SocketAddr>> {
    ensure!(
        !values.is_empty() && values.len() <= MAX_SERVERS,
        "dns must contain from 1 to 8 upstream IP addresses"
    );
    let mut result = Vec::new();
    for value in values {
        let address = match value.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, 53),
            Err(_) => value
                .parse::<SocketAddr>()
                .context("dns upstream must be an IP or IP:port address")?,
        };
        ensure!(
            address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast(),
            "dns upstream requires a unicast IP and a port from 1 to 65535"
        );
        if !result.contains(&address) {
            result.push(address);
        }
    }
    Ok(result)
}

/// Partition one policy's response-cache budget across independently retriable upstreams.
pub(super) fn build(addresses: &[SocketAddr]) -> anyhow::Result<Vec<TokioResolver>> {
    addresses
        .iter()
        .map(|address| {
            let mut server = NameServerConfig::udp_and_tcp(address.ip());
            for connection in &mut server.connections {
                connection.port = address.port();
            }
            let config = ResolverConfig::from_parts(None, vec![], vec![server]);
            let mut builder =
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
            let options = builder.options_mut();
            options.cache_size /= addresses.len() as u64;
            options.use_hosts_file = ResolveHosts::Never;
            options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            options.timeout = Duration::from_secs(2);
            options.attempts = 1;
            options.num_concurrent_reqs = 1;
            options.try_tcp_on_error = true;
            options.positive_max_ttl = Some(Duration::from_secs(24 * 60 * 60));
            options.negative_max_ttl = Some(Duration::from_secs(60));
            Ok(builder.build()?)
        })
        .collect()
}
