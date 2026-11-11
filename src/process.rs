//! Local process attribution uses bounded macOS command queries and never guesses socket ownership.

use crate::routing::ProcessIdentity;
use std::net::SocketAddr;

/// Identify the owner of an exact loopback TCP connection, or return an unknown identity.
pub async fn identify(peer: SocketAddr, local: SocketAddr) -> ProcessIdentity {
    #[cfg(target_os = "macos")]
    {
        use std::{process::Stdio, sync::OnceLock, time::Duration};
        use tokio::{process::Command, sync::Semaphore, time::timeout};
        /// Concurrent ownership queries are bounded independently from session admission.
        static QUERIES: OnceLock<Semaphore> = OnceLock::new();
        let lookup = async {
            let _permit = QUERIES
                .get_or_init(|| Semaphore::new(4))
                .acquire()
                .await
                .ok()?;
            let output = Command::new("/usr/sbin/lsof")
                .args([
                    "-nP",
                    "-a",
                    &format!("-iTCP:{}", peer.port()),
                    "-sTCP:ESTABLISHED",
                    "-Fpcn",
                ])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .output()
                .await
                .ok()?;
            let mut identity = parse_owners(&String::from_utf8_lossy(&output.stdout), peer, local)?;
            let output = Command::new("/bin/ps")
                .args(["-p", &identity.pid?.to_string(), "-o", "comm="])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .output()
                .await
                .ok();
            if let Some(output) = output.filter(|output| output.status.success()) {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if path.starts_with('/') {
                    identity.name = std::path::Path::new(&path)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned());
                    identity.path = Some(path);
                }
            }
            Some(identity)
        };
        timeout(Duration::from_millis(750), lookup)
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (peer, local);
        ProcessIdentity::default()
    }
}

/// Parse only the client-to-listener tuple, rejecting ambiguous or unrelated ownership records.
#[cfg(any(target_os = "macos", test))]
fn parse_owners(output: &str, peer: SocketAddr, local: SocketAddr) -> Option<ProcessIdentity> {
    let expected = format!("{peer}->{local}");
    let mut current = ProcessIdentity::default();
    let mut found = None;
    for line in output.lines() {
        if let Some(pid) = line.strip_prefix('p') {
            current = ProcessIdentity {
                pid: pid.parse().ok(),
                ..ProcessIdentity::default()
            };
        } else if let Some(name) = line.strip_prefix('c') {
            current.name = Some(name.into());
        } else if line.strip_prefix('n') == Some(expected.as_str()) && current.pid.is_some() {
            if found
                .as_ref()
                .is_some_and(|owner: &ProcessIdentity| owner.pid != current.pid)
            {
                return None;
            }
            found = Some(current.clone());
        }
    }
    found
}

/// Attribution tests ensure the proxy's reverse tuple is never mistaken for the client.
#[cfg(test)]
mod tests {
    use super::*;

    /// Exact tuple ownership avoids confusing simultaneous loopback connections.
    #[test]
    fn exact_owner_only() {
        let peer = "127.0.0.1:50001".parse().unwrap();
        let local = "127.0.0.1:1080".parse().unwrap();
        let data = "p9\ncproxy\nn127.0.0.1:1080->127.0.0.1:50001\np10\nccurl\nn127.0.0.1:50001->127.0.0.1:1080\n";
        assert_eq!(parse_owners(data, peer, local).unwrap().pid, Some(10));
        assert!(parse_owners(data, local, "127.0.0.1:9999".parse().unwrap()).is_none());
        assert!(
            parse_owners(
                &format!("{data}p11\ncother\nn{peer}->{local}\n"),
                peer,
                local
            )
            .is_none()
        );
    }
}

/// Live macOS attribution verifies native command output for both loopback address families.
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// A local connection resolves to this test executable rather than the accepting proxy socket.
    #[tokio::test]
    async fn identifies_live_loopback_owner() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).await.unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (_socket, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr().unwrap());
            let identity = identify(peer, listener.local_addr().unwrap()).await;
            assert_eq!(
                identity.pid,
                Some(std::process::id()),
                "identity: {identity:?}"
            );
            assert!(
                identity
                    .path
                    .as_ref()
                    .is_some_and(|path| path.starts_with('/')),
                "identity: {identity:?}"
            );
        }
    }
}
