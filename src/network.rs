//! Address selection and explicit socket policies make dual-stack behavior deterministic.

use socket2::{Domain, Protocol, Socket, Type};
use std::{collections::HashSet, future::Future, io, net::SocketAddr, time::Duration};
use tokio::{
    task::JoinSet,
    time::{Instant, sleep_until},
};

/// Address racing launches another candidate before an unresponsive path consumes the deadline.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// Bounded address racing retains up to eight unique candidates from each family.
const FAMILY_LIMIT: usize = 8;

/// Interleave unique address families while preserving the resolver's first-family preference.
pub(crate) fn candidates(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut first_v6 = None;
    for address in addresses {
        let address = canonical(address);
        if !seen.insert(address) {
            continue;
        }
        first_v6.get_or_insert(address.is_ipv6());
        let family = if address.is_ipv6() { &mut v6 } else { &mut v4 };
        if family.len() < FAMILY_LIMIT {
            family.push(address);
        }
        if v4.len() == FAMILY_LIMIT && v6.len() == FAMILY_LIMIT {
            break;
        }
    }
    let (first, second) = if first_v6.unwrap_or(false) {
        (v6, v4)
    } else {
        (v4, v6)
    };
    let mut ordered = Vec::with_capacity(first.len() + second.len());
    for index in 0..first.len().max(second.len()) {
        if let Some(address) = first.get(index) {
            ordered.push(*address);
        }
        if let Some(address) = second.get(index) {
            ordered.push(*address);
        }
    }
    ordered
}

/// Normalize mapped IPv4 addresses so socket selection and UDP source authorization agree.
pub(crate) fn canonical(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(value) => value
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(ip.into(), value.port()))
            .unwrap_or(address),
        _ => address,
    }
}

/// Race bounded staggered connection attempts and cancel every losing future on return.
pub(crate) async fn race<T, F, Fut>(addresses: Vec<SocketAddr>, connect: F) -> io::Result<T>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>> + Send + 'static,
{
    let mut addresses = candidates(addresses).into_iter().peekable();
    let mut tasks = JoinSet::new();
    let mut next = Instant::now();
    let mut last = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no usable destination addresses",
    );
    loop {
        if (tasks.is_empty() || Instant::now() >= next)
            && let Some(address) = addresses.next()
        {
            tasks.spawn(connect(address));
            next = Instant::now() + ATTEMPT_DELAY;
        }
        if tasks.is_empty() {
            return Err(last);
        }
        tokio::select! {
            result = tasks.join_next() => match result {
                Some(Ok(Ok(value))) => return Ok(value),
                Some(Ok(Err(error))) => last = error,
                Some(Err(error)) => last = io::Error::other(error),
                None => {}
            },
            _ = sleep_until(next), if addresses.peek().is_some() => {}
        }
    }
}

/// Bind a nonblocking UDP socket with an explicit IPv6-only or wildcard dual-stack policy.
pub(crate) fn udp_socket(address: SocketAddr, dual_stack: bool) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(!dual_stack)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}

/// Address-selection tests verify bounded ordering and cancellation without relying on public networks.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::timeout;

    /// A dropped attempt proves that racing does not leave losing work running.
    struct PendingAttempt(Arc<AtomicUsize>);

    /// Dropping an attempt records cancellation for the waiting regression test.
    impl Drop for PendingAttempt {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Preserve the first family while deduplicating mapped addresses and retaining the other family.
    #[test]
    fn interleaves_and_deduplicates_families() {
        let input = [
            "[::1]:1",
            "[::1]:2",
            "127.0.0.1:1",
            "[::ffff:127.0.0.1]:1",
            "127.0.0.1:2",
        ];
        let output = candidates(input.map(|value| value.parse().unwrap()));
        let expected = ["[::1]:1", "127.0.0.1:1", "[::1]:2", "127.0.0.1:2"]
            .map(|value| value.parse::<SocketAddr>().unwrap());
        assert_eq!(output, expected);
        let many = (1..100)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .chain(std::iter::once("[::1]:1".parse().unwrap()));
        let output = candidates(many);
        assert_eq!(output.len(), FAMILY_LIMIT + 1);
        assert!(output[1].is_ipv6());
    }

    /// A hanging preferred path must not block a working alternate family or survive its success.
    #[tokio::test]
    async fn hanging_path_yields_to_other_family_and_is_cancelled() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let count = dropped.clone();
        let result = timeout(
            Duration::from_secs(2),
            race(
                vec!["[::1]:1".parse().unwrap(), "127.0.0.1:1".parse().unwrap()],
                move |address| {
                    let count = count.clone();
                    async move {
                        if address.is_ipv6() {
                            let _attempt = PendingAttempt(count);
                            std::future::pending::<()>().await;
                        }
                        Ok(address)
                    }
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(result.is_ipv4());
        for _ in 0..10 {
            if dropped.load(Ordering::SeqCst) != 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    /// An outer deadline must cancel all pending connection attempts.
    #[tokio::test]
    async fn deadline_cancels_pending_attempts() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let count = dropped.clone();
        let result = timeout(
            Duration::from_millis(30),
            race(vec!["[::1]:1".parse().unwrap()], move |_| {
                let count = count.clone();
                async move {
                    let _attempt = PendingAttempt(count);
                    std::future::pending::<io::Result<()>>().await
                }
            }),
        )
        .await;
        assert!(result.is_err());
        for _ in 0..10 {
            if dropped.load(Ordering::SeqCst) != 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
