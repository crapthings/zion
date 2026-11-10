//! Direct outbound operations resolve both address families and bound connection attempts.

use fast_socks5::util::target_addr::TargetAddr;
use std::{io, net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, time::timeout};

/// Connect through staggered address attempts within one DNS and connection deadline.
pub async fn connect(target: &TargetAddr, deadline: Duration) -> io::Result<TcpStream> {
    connect_with(&crate::dns::Resolver::default(), target, deadline).await
}

/// Connect through the shared DNS policy without changing address racing or its total deadline.
pub async fn connect_with(
    resolver: &crate::dns::Resolver,
    target: &TargetAddr,
    deadline: Duration,
) -> io::Result<TcpStream> {
    timeout(deadline, async {
        let addresses = resolver.resolve(target, deadline).await?;
        connect_candidates(addresses).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "destination connection timed out"))?
}

/// Apply TCP socket settings only to the winning connection from bounded address candidates.
async fn connect_candidates(addresses: Vec<SocketAddr>) -> io::Result<TcpStream> {
    let stream = crate::network::race(addresses, |address| async move {
        TcpStream::connect(address).await
    })
    .await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Resolve bounded interleaved destination candidates without dropping an entire address family.
pub async fn resolve_all(target: &TargetAddr, deadline: Duration) -> io::Result<Vec<SocketAddr>> {
    crate::dns::Resolver::default()
        .resolve(target, deadline)
        .await
}

/// TCP fallback tests inject resolved candidates instead of relying on system localhost aliases.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A refused first-family destination must allow a working alternate-family connection.
    #[tokio::test]
    async fn tcp_candidates_fall_back_in_both_family_directions() {
        for (listen, unavailable) in [("127.0.0.1:0", "[::1]:0"), ("[::1]:0", "127.0.0.1:0")] {
            let target = TcpListener::bind(listen).await.unwrap();
            let address = target.local_addr().unwrap();
            let unused = TcpListener::bind(unavailable).await.unwrap();
            let refused = unused.local_addr().unwrap();
            drop(unused);
            let stream = timeout(
                Duration::from_secs(2),
                connect_candidates(vec![refused, address]),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(stream.peer_addr().unwrap(), address);
        }
    }
}
