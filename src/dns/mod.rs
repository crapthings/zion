//! Resolver policies preserve system behavior or isolate a cached custom upstream group.

/// Shared lookups merge concurrent work independently of the DNS response cache.
mod shared;
/// Custom upstream construction validates addresses without consulting system DNS.
mod upstream;

use fast_socks5::util::target_addr::TargetAddr;
use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::lookup_host, time::timeout};

pub(crate) use upstream::parse_servers;

/// A resolver shares one custom policy across all cloned TCP and UDP session settings.
#[derive(Clone, Default)]
pub struct Resolver {
    custom: Option<Arc<shared::Custom>>,
}

/// Resolver diagnostics identify policy without dumping cached queries or credentials.
impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("custom", &self.custom.is_some())
            .finish()
    }
}

/// Resolver operations keep IP literals independent of DNS configuration and availability.
impl Resolver {
    /// Build an isolated resolver with explicit upstreams, indexed caching, and no system fallback.
    pub fn custom(servers: &[String]) -> anyhow::Result<Self> {
        let resolver = upstream::build(&parse_servers(servers)?)?;
        Ok(Self {
            custom: Some(Arc::new(shared::Custom::new(resolver))),
        })
    }

    /// Resolve all bounded address candidates within the caller's deadline.
    pub async fn resolve(
        &self,
        target: &TargetAddr,
        deadline: Duration,
    ) -> io::Result<Vec<SocketAddr>> {
        timeout(deadline, async {
            let addresses = match target {
                TargetAddr::Ip(address) => vec![*address],
                TargetAddr::Domain(host, port) if host.parse::<IpAddr>().is_ok() => {
                    vec![SocketAddr::new(
                        host.parse::<IpAddr>().expect("validated IP literal"),
                        *port,
                    )]
                }
                TargetAddr::Domain(host, port) => match &self.custom {
                    Some(custom) => custom
                        .lookup(host)
                        .await?
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, *port))
                        .collect(),
                    None => lookup_host((host.as_str(), *port)).await?.collect(),
                },
            };
            let addresses = crate::network::candidates(addresses);
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "DNS returned no addresses",
                ));
            }
            Ok(addresses)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out"))?
    }
}
