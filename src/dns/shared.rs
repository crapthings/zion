//! Single-flight coordination shares bounded DNS work without duplicating TTL-managed responses.

use hickory_resolver::{
    TokioResolver,
    net::{DnsError, NetError},
    proto::{
        op::Query,
        rr::{Name, RecordType},
    },
};
use moka::sync::Cache;
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};

/// A fixed worker deadline bounds shared work even when every original caller has disconnected.
const LOOKUP_DEADLINE: Duration = Duration::from_secs(5);
/// Unique pending names are capped separately from the persistent response cache.
const MAX_PENDING: usize = 128;
/// Short transient failure backoff prevents repeated upstream storms without caching false NXDOMAINs.
const FAILURE_BACKOFF: Duration = Duration::from_millis(500);
/// Shared results contain bounded addresses without creating a second persistent DNS response cache.
type Result = std::result::Result<Vec<IpAddr>, Failure>;
/// A watch receiver lets independently timed callers await one shared lookup.
type Pending = watch::Receiver<Option<Result>>;

/// A custom policy owns one response cache, indexed pending work, and a bounded failure backoff.
pub(super) struct Custom {
    resolvers: Vec<TokioResolver>,
    pending: Mutex<HashMap<Name, Pending>>,
    failures: Cache<(Query, usize), Failure>,
    preferred: AtomicUsize,
}

/// A small error preserves negative-result semantics without retaining arbitrary wire data.
#[derive(Clone, Copy)]
struct Failure {
    kind: io::ErrorKind,
    message: &'static str,
}

/// Failure conversion distinguishes authoritative absence from temporary transport or server failure.
impl Failure {
    /// Classify lookup errors without treating SERVFAIL or refusal as a cached name absence.
    fn from_error(error: &NetError) -> Self {
        let negative = matches!(error, NetError::Dns(DnsError::NoRecordsFound(records))
            if matches!(records.response_code, hickory_resolver::proto::op::ResponseCode::NXDomain | hickory_resolver::proto::op::ResponseCode::NoError));
        if negative {
            Self {
                kind: io::ErrorKind::NotFound,
                message: "custom DNS returned no address records",
            }
        } else if matches!(error, NetError::Timeout) {
            Self {
                kind: io::ErrorKind::TimedOut,
                message: "custom DNS query timed out",
            }
        } else {
            Self {
                kind: io::ErrorKind::Other,
                message: "custom DNS lookup failed",
            }
        }
    }

    /// Convert a shared failure into an independent standard I/O error for each waiter.
    fn into_io(self) -> io::Error {
        io::Error::new(self.kind, self.message)
    }
}

/// A registration removes pending work even if its worker is cancelled or panics.
struct Registration {
    policy: Arc<Custom>,
    name: Name,
}

/// Dropping a registration releases its indexed slot on every worker exit path.
impl Drop for Registration {
    fn drop(&mut self) {
        self.policy.pending().remove(&self.name);
    }
}

/// Shared lookup operations never hold a registry lock during network I/O.
impl Custom {
    /// Wrap one Hickory resolver while leaving all DNS response TTLs in its native cache.
    pub(super) fn new(resolvers: Vec<TokioResolver>) -> Self {
        Self {
            resolvers,
            preferred: AtomicUsize::new(0),
            pending: Mutex::new(HashMap::new()),
            failures: Cache::builder()
                .max_capacity(1024)
                .time_to_live(FAILURE_BACKOFF)
                .build(),
        }
    }

    /// Recover the tiny registry lock without holding it across any await point.
    fn pending(&self) -> MutexGuard<'_, HashMap<Name, Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Merge canonical names while preserving independent deadlines for callers sharing a query.
    pub(super) async fn lookup(self: &Arc<Self>, host: &str) -> io::Result<Vec<IpAddr>> {
        let mut name = Name::from_utf8(host)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS name"))?
            .to_lowercase();
        name.set_fqdn(true);
        let mut receiver = {
            let mut pending = self.pending();
            match pending.get(&name) {
                Some(receiver) => receiver.clone(),
                None => {
                    if pending.len() >= MAX_PENDING {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "too many pending DNS names",
                        ));
                    }
                    let (sender, receiver) = watch::channel(None);
                    pending.insert(name.clone(), receiver.clone());
                    let registration = Registration {
                        policy: self.clone(),
                        name,
                    };
                    tokio::spawn(Self::run(registration, sender));
                    receiver
                }
            }
        };
        loop {
            if let Some(result) = receiver.borrow().clone() {
                return result.map_err(Failure::into_io);
            }
            receiver
                .changed()
                .await
                .map_err(|_| io::Error::other("DNS lookup worker stopped"))?;
        }
    }

    /// Bound the whole upstream group without letting a fast transient failure cancel healthy peers.
    async fn lookup_type(&self, name: Name, kind: RecordType) -> Result {
        timeout(LOOKUP_DEADLINE, self.query_peers(name, kind))
            .await
            .unwrap_or({
                Err(Failure {
                    kind: io::ErrorKind::TimedOut,
                    message: "custom DNS query deadline exceeded",
                })
            })
    }

    /// Prefer the last successful peer and stagger alternatives so cache hits avoid extra network queries.
    async fn query_peers(&self, name: Name, kind: RecordType) -> Result {
        let query = Query::query(name.clone(), kind);
        let count = self.resolvers.len();
        let preferred = self.preferred.load(Ordering::Relaxed);
        let mut peers = (0..count)
            .map(|offset| (preferred + offset) % count)
            .peekable();
        let mut tasks = JoinSet::new();
        let mut next = Instant::now();
        let mut last = Failure {
            kind: io::ErrorKind::Other,
            message: "custom DNS upstreams failed",
        };
        loop {
            if tasks.is_empty() || (tasks.len() < 2 && Instant::now() >= next) {
                for index in peers.by_ref() {
                    let key = (query.clone(), index);
                    if let Some(failure) = self.failures.get(&key) {
                        last = failure;
                        continue;
                    }
                    let name = name.clone();
                    let resolver = self.resolvers[index].clone();
                    tasks.spawn(async move { (index, lookup_peer(resolver, name, kind).await) });
                    next = Instant::now() + Duration::from_millis(50);
                    break;
                }
            }
            if tasks.is_empty() {
                return Err(last);
            }
            tokio::select! {
                result = tasks.join_next() => match result {
                    Some(Ok((index, Ok(addresses)))) => {
                        self.preferred.store(index, Ordering::Relaxed);
                        return Ok(addresses);
                    }
                    Some(Ok((_, Err(failure)))) if failure.kind == io::ErrorKind::NotFound => return Err(failure),
                    Some(Ok((index, Err(failure)))) => {
                        self.failures.insert((query.clone(), index), failure);
                        last = failure;
                    }
                    _ => {}
                },
                _ = sleep_until(next), if tasks.len() < 2 && peers.peek().is_some() => {}
            }
        }
    }

    /// Merge independently cached A and AAAA results while preserving either successful family.
    async fn run(registration: Registration, sender: watch::Sender<Option<Result>>) {
        let policy = &registration.policy;
        let (v4, v6) = tokio::join!(
            policy.lookup_type(registration.name.clone(), RecordType::A),
            policy.lookup_type(registration.name.clone(), RecordType::AAAA),
        );
        let result = match (v4, v6) {
            (Ok(mut v4), Ok(v6)) => {
                v4.extend(v6);
                Ok(v4)
            }
            (Ok(addresses), Err(_)) | (Err(_), Ok(addresses)) => Ok(addresses),
            (Err(v4), Err(v6)) => Err(if v4.kind == io::ErrorKind::NotFound {
                v6
            } else {
                v4
            }),
        };
        sender.send_replace(Some(result));
    }
}

/// Query one peer with a transport deadline while leaving TTL and negative responses in Hickory's cache.
async fn lookup_peer(resolver: TokioResolver, name: Name, kind: RecordType) -> Result {
    match timeout(Duration::from_secs(2), resolver.lookup(name, kind)).await {
        Ok(Ok(lookup)) => {
            let addresses = lookup
                .answers()
                .iter()
                .filter_map(|record| record.data.ip_addr())
                .take(8)
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                Err(Failure {
                    kind: io::ErrorKind::NotFound,
                    message: "custom DNS returned no address records",
                })
            } else {
                Ok(addresses)
            }
        }
        Ok(Err(error)) => {
            tracing::debug!(%error, "custom DNS upstream failed");
            Err(Failure::from_error(&error))
        }
        Err(_) => Err(Failure {
            kind: io::ErrorKind::TimedOut,
            message: "custom DNS upstream timed out",
        }),
    }
}

/// Registry tests validate resource limits and cancellation cleanup without any upstream traffic.
#[cfg(test)]
mod tests {
    use super::*;

    /// A full registry rejects new names while preserving existing work and bounded memory.
    #[tokio::test]
    async fn pending_name_limit_is_enforced() {
        let resolver = crate::dns::upstream::build(&["127.0.0.1:9".parse().unwrap()]).unwrap();
        let policy = Arc::new(Custom::new(resolver));
        let mut senders = Vec::new();
        for index in 0..MAX_PENDING {
            let (sender, receiver) = watch::channel(None);
            senders.push(sender);
            policy.pending().insert(
                Name::from_ascii(format!("name-{index}.zion.test.")).unwrap(),
                receiver,
            );
        }
        assert_eq!(
            policy
                .lookup("overflow.zion.test.")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(policy.pending().len(), MAX_PENDING);
    }

    /// Dropping a worker registration removes its name even before a query has completed.
    #[test]
    fn cancelled_registration_releases_pending_slot() {
        let resolver = crate::dns::upstream::build(&["127.0.0.1:9".parse().unwrap()]).unwrap();
        let policy = Arc::new(Custom::new(resolver));
        let name = Name::from_ascii("cancelled.zion.test.").unwrap();
        let (_sender, receiver) = watch::channel(None);
        policy.pending().insert(name.clone(), receiver);
        drop(Registration {
            policy: policy.clone(),
            name,
        });
        assert!(policy.pending().is_empty());
    }
}
