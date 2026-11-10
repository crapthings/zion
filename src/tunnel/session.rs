//! Session I/O preserves stream behavior while distinguishing QUIC from framed TLS datagrams.

use super::{client::ConnectionGuard, framed::Datagrams};
use bytes::Bytes;
use quinn::{RecvStream, SendStream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, Join, ReadBuf},
    net::TcpStream,
};

/// A session stream carries TCP bytes or marks an association whose data uses a separate packet channel.
pub enum SessionIo {
    Quic(Join<RecvStream, SendStream>),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Datagrams,
}

/// QUIC-specific access remains explicit for delivery and cancellation diagnostics.
impl SessionIo {
    /// Return the QUIC writer only for a QUIC session.
    pub fn quic_writer(&self) -> Option<&SendStream> {
        match self {
            Self::Quic(io) => Some(io.writer()),
            _ => None,
        }
    }
    /// Return the mutable QUIC writer only for a QUIC session.
    pub fn quic_writer_mut(&mut self) -> Option<&mut SendStream> {
        match self {
            Self::Quic(io) => Some(io.writer_mut()),
            _ => None,
        }
    }
}

/// Stream reads delegate to their actual transport and reject association-only streams.
impl AsyncRead for SessionIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Quic(io) => Pin::new(io).poll_read(cx, buffer),
            Self::Tls(io) => Pin::new(io.as_mut()).poll_read(cx, buffer),
            Self::Datagrams => Poll::Ready(Err(io::Error::other("session has no byte stream"))),
        }
    }
}

/// Stream writes retain each transport's flush and half-close behavior.
impl AsyncWrite for SessionIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Quic(io) => Pin::new(io).poll_write(cx, data),
            Self::Tls(io) => Pin::new(io.as_mut()).poll_write(cx, data),
            Self::Datagrams => Poll::Ready(Err(io::Error::other("session has no byte stream"))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Quic(io) => Pin::new(io).poll_flush(cx),
            Self::Tls(io) => Pin::new(io.as_mut()).poll_flush(cx),
            Self::Datagrams => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Quic(io) => Pin::new(io).poll_shutdown(cx),
            Self::Tls(io) => Pin::new(io.as_mut()).poll_shutdown(cx),
            Self::Datagrams => Poll::Ready(Ok(())),
        }
    }
}

/// A session owns a verified stream or an isolated bounded datagram association.
pub struct Session {
    pub guard: Option<ConnectionGuard>,
    pub io: SessionIo,
    pub bound: std::net::SocketAddr,
    pub(super) datagrams: Option<Datagrams>,
}

/// Session operations keep forwarding independent of the selected network carrier.
impl Session {
    /// Queue a complete UDP envelope without silently selecting another carrier.
    pub fn send_datagram(&self, packet: Bytes) -> anyhow::Result<crate::datagram::SendOutcome> {
        if let Some(guard) = &self.guard {
            return crate::datagram::send_quic(&guard.0, packet);
        }
        self.datagrams
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("not a UDP session"))?
            .send(packet)
    }

    /// Receive one envelope with cancellation-safe framing across repeated select calls.
    pub async fn receive_datagram(&self) -> anyhow::Result<Bytes> {
        if let Some(guard) = &self.guard {
            return Ok(guard.0.read_datagram().await?);
        }
        self.datagrams
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("not a UDP session"))?
            .receive()
            .await
    }

    /// Preserve QUIC acknowledgement checks and flush TLS streams after normal copy completion.
    pub async fn acknowledged(&mut self) -> anyhow::Result<()> {
        if let Some(writer) = self.io.quic_writer() {
            super::finish::acknowledged(writer, Duration::from_secs(5)).await
        } else {
            self.io.flush().await.map_err(Into::into)
        }
    }
}
