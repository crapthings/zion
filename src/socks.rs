//! SOCKS5 parsing is delegated to fast-socks5 while Zion owns command execution.

use crate::server::Config;
use fast_socks5::{
    ReplyError, Socks5Command,
    server::{Socks5ServerProtocol, states},
    util::target_addr::TargetAddr,
};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::TcpStream,
    time::timeout,
};

/// A parsed command retains the protocol state required to send its response.
pub type Command<T = TcpStream> = Socks5ServerProtocol<T, states::CommandRead>;

/// Parse one bounded SOCKS5 handshake and dispatch its requested command.
pub async fn serve(socket: TcpStream, config: Config) -> anyhow::Result<()> {
    let peer = socket.peer_addr()?;
    let local = socket.local_addr()?;
    socket.set_nodelay(true)?;
    let (request, command, target) = read_request(socket, config.handshake_timeout).await?;
    let process = crate::process::identify(peer, local).await;
    let (policy, rule) = config.routing.decide(&process);
    let protocol = if command == Socks5Command::UDPAssociate {
        "UDP"
    } else {
        "TCP"
    };
    let mut flow = crate::traffic::Flow::start(
        process,
        target.to_string(),
        protocol,
        policy,
        rule,
        config.traffic_events,
    );
    if policy == crate::routing::Policy::Reject {
        flow.finish("rejected");
        request
            .reply_error(&ReplyError::ConnectionNotAllowed)
            .await?;
        return Ok(());
    }
    let mut config = config;
    if policy == crate::routing::Policy::Direct {
        config.tunnel = None;
    }
    let result = match command {
        Socks5Command::TCPConnect => relay_tcp(request, &target, &config, &flow).await,
        Socks5Command::UDPAssociate => {
            crate::udp::relay(request, peer, local.ip(), target, &config, &flow).await
        }
        _ => {
            request
                .reply_error(&ReplyError::CommandNotSupported)
                .await?;
            anyhow::bail!("unsupported SOCKS command")
        }
    };
    flow.finish(if result.is_ok() { "closed" } else { "failed" });
    result
}

/// Connect an outbound TCP stream before acknowledging and relaying both directions.
async fn relay_tcp(
    request: Command,
    target: &TargetAddr,
    config: &Config,
    flow: &crate::traffic::Flow,
) -> anyhow::Result<()> {
    if let Some(client) = &config.tunnel {
        return relay_tunnel_tcp(request, target, config, client, flow).await;
    }
    let mut outbound =
        match crate::outbound::connect_with(&config.resolver, target, config.connect_timeout).await
        {
            Ok(stream) => stream,
            Err(error) => {
                let status = match error.kind() {
                    io::ErrorKind::ConnectionRefused => ReplyError::ConnectionRefused,
                    _ => ReplyError::HostUnreachable,
                };
                request.reply_error(&status).await?;
                return Err(error.into());
            }
        };
    let mut socket = flow.stream(request.reply_success(outbound.local_addr()?).await?);
    let (sent, received) = copy_bidirectional(&mut socket, &mut outbound).await?;
    tracing::debug!(sent, received, "TCP relay completed");
    Ok(())
}

/// Negotiate and parse one command within a deadline independent of its I/O transport.
async fn read_request<T: AsyncRead + AsyncWrite + Unpin>(
    socket: T,
    deadline: Duration,
) -> anyhow::Result<(Command<T>, Socks5Command, TargetAddr)> {
    Ok(timeout(deadline, async {
        Socks5ServerProtocol::accept_no_auth(socket)
            .await?
            .read_command()
            .await
    })
    .await??)
}

/// Acknowledge an authenticated remote TCP connection before relaying SOCKS5 bytes.
async fn relay_tunnel_tcp(
    request: Command,
    target: &TargetAddr,
    config: &Config,
    client: &crate::tunnel::Client,
    flow: &crate::traffic::Flow,
) -> anyhow::Result<()> {
    let mut session = match client.tcp(target, config.connect_timeout).await {
        Ok(session) => session,
        Err(error) => {
            let status = error
                .downcast_ref::<ReplyError>()
                .copied()
                .unwrap_or(ReplyError::HostUnreachable);
            request.reply_error(&status).await?;
            return Err(error);
        }
    };
    let mut socket = flow.stream(request.reply_success(session.bound).await?);
    copy_bidirectional(&mut socket, &mut session.io).await?;
    session.acknowledged().await?;
    Ok(())
}

/// In-memory tests exercise handshake fragmentation, negotiation failure, and deadlines.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// A fragmented domain request retains its hostname for outbound-side resolution.
    #[tokio::test]
    async fn fragmented_domain_request() {
        let (server, mut client) = duplex(64);
        let task = tokio::spawn(read_request(server, Duration::from_secs(1)));
        client.write_all(&[5]).await.unwrap();
        tokio::task::yield_now().await;
        client.write_all(&[1, 0]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 0]);
        let mut request = vec![5, 1, 0];
        request.extend(
            TargetAddr::Domain("example.test".into(), 443)
                .to_be_bytes()
                .unwrap(),
        );
        for byte in request {
            client.write_all(&[byte]).await.unwrap();
        }
        let (_, command, target) = task.await.unwrap().unwrap();
        assert_eq!(command, Socks5Command::TCPConnect);
        assert_eq!(target, TargetAddr::Domain("example.test".into(), 443));
    }

    /// A client offering only an unsupported authentication method receives rejection.
    #[tokio::test]
    async fn rejects_unsupported_authentication() {
        let (server, mut client) = duplex(64);
        let task = tokio::spawn(read_request(server, Duration::from_secs(1)));
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 255]);
        assert!(task.await.unwrap().is_err());
    }

    /// An incomplete greeting cannot hold a session beyond its handshake deadline.
    #[tokio::test]
    async fn stalled_handshake_expires() {
        let (server, _client) = duplex(64);
        let error = read_request(server, Duration::from_millis(10))
            .await
            .err()
            .unwrap();
        assert!(
            error
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        );
    }
}
