//! Bounded JSON control messages negotiate one operation per QUIC connection.

use anyhow::{Context, ensure};
use fast_socks5::util::target_addr::TargetAddr;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The ALPN identifier separates this protocol from HTTP/3 and incompatible versions.
pub const ALPN: &[u8] = b"zion/1";
/// Control messages cannot allocate more than this number of encoded bytes.
const MAX_CONTROL: usize = 4096;
/// The protocol version must match before any outbound activity is permitted.
pub const VERSION: u16 = 1;

/// A request selects the supported operation for an authenticated connection.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub operation: Operation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<[u8; 32]>,
}

/// An operation carries either a TCP destination or an isolated UDP association.
#[derive(Debug, Serialize, Deserialize)]
pub enum Operation {
    Tcp { host: String, port: u16 },
    Udp,
}

/// A response reports the SOCKS-compatible result and its bound address.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub status: u8,
    pub bound: SocketAddr,
}

/// Request constructors preserve domain names until resolution on the remote server.
impl Request {
    /// Build a TCP command from an existing SOCKS5 destination.
    pub fn tcp(target: &TargetAddr) -> Self {
        let (host, port) = match target {
            TargetAddr::Ip(addr) => (addr.ip().to_string(), addr.port()),
            TargetAddr::Domain(host, port) => (host.clone(), *port),
        };
        Self {
            version: VERSION,
            operation: Operation::Tcp { host, port },
            auth: None,
        }
    }

    /// Reject unsupported versions and invalid destinations before opening sockets.
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.version == VERSION,
            "unsupported tunnel protocol version"
        );
        if let Operation::Tcp { host, port } = &self.operation {
            ensure!(
                !host.is_empty() && host.len() <= 255 && !host.contains('\0') && *port != 0,
                "invalid tunnel destination"
            );
        }
        Ok(())
    }
}

/// Write a length-prefixed control message without mixing it with subsequent payload.
pub async fn write<T: Serialize, W: AsyncWrite + Unpin>(
    io: &mut W,
    message: &T,
) -> anyhow::Result<()> {
    let encoded = serde_json::to_vec(message)?;
    ensure!(encoded.len() <= MAX_CONTROL, "control message too large");
    io.write_u16(encoded.len() as u16).await?;
    io.write_all(&encoded).await?;
    io.flush().await?;
    Ok(())
}

/// Read one bounded control message and reject malformed or oversized input.
pub async fn read<T: DeserializeOwned, R: AsyncRead + Unpin>(io: &mut R) -> anyhow::Result<T> {
    let length = io.read_u16().await? as usize;
    ensure!(
        length > 0 && length <= MAX_CONTROL,
        "invalid control message length"
    );
    let mut encoded = vec![0; length];
    io.read_exact(&mut encoded).await?;
    serde_json::from_slice(&encoded).context("invalid tunnel control message")
}

/// Protocol tests exercise version rejection and bounded message decoding.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    /// An incompatible version is rejected before any destination operation.
    #[test]
    fn rejects_unknown_version() {
        assert!(
            Request {
                version: VERSION + 1,
                operation: Operation::Udp,
                auth: None,
            }
            .validate()
            .is_err()
        );
    }

    /// A length prefix cannot request an allocation above the control-message budget.
    #[tokio::test]
    async fn rejects_oversized_control_frame() {
        let (mut reader, mut writer) = duplex(16);
        writer.write_u16((MAX_CONTROL + 1) as u16).await.unwrap();
        assert!(read::<Request, _>(&mut reader).await.is_err());
    }

    /// Unknown fields fail decoding instead of silently changing negotiation semantics.
    #[tokio::test]
    async fn rejects_unknown_request_fields() {
        let (mut reader, mut writer) = duplex(128);
        let encoded = br#"{"version":1,"operation":"Udp","unexpected":true}"#;
        writer.write_u16(encoded.len() as u16).await.unwrap();
        writer.write_all(encoded).await.unwrap();
        assert!(read::<Request, _>(&mut reader).await.is_err());
    }
}
