//! Tokio's length codec retains partial frames while bounded queues isolate TLS reads and writes.

use crate::datagram::{DropReason, PACKET_CAPACITY, SendOutcome};
use anyhow::Context;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Four maximum-sized envelopes keep each direction within a 256 KiB queue budget.
const QUEUE_CAPACITY: usize = 4;

/// Construct a four-byte network-order frame codec that rejects oversize envelopes before allocation.
pub(super) fn codec<S: AsyncRead + AsyncWrite>(stream: S) -> Framed<S, LengthDelimitedCodec> {
    LengthDelimitedCodec::builder()
        .length_field_length(4)
        .max_frame_length(PACKET_CAPACITY)
        .new_framed(stream)
}

/// An association owns its TLS worker and bounded queues for complete UDP envelopes.
pub(super) struct Datagrams {
    outgoing: mpsc::Sender<Bytes>,
    incoming: Mutex<mpsc::Receiver<io::Result<Bytes>>>,
    task: JoinHandle<()>,
}

/// Datagram operations never cancel a partially encoded or decoded TLS frame.
impl Datagrams {
    /// Split framing into owned worker futures whose partial state survives caller cancellation.
    pub(super) fn start<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream: S,
        deadline: Duration,
    ) -> Self {
        let (outgoing, mut queued) = mpsc::channel::<Bytes>(QUEUE_CAPACITY);
        let (responses, incoming) = mpsc::channel(QUEUE_CAPACITY);
        let task = tokio::spawn(async move {
            let (mut writer, mut reader) = codec(stream).split();
            let result: anyhow::Result<()> = tokio::try_join!(
                async {
                    while let Some(packet) = reader.next().await {
                        let packet = packet?;
                        anyhow::ensure!(!packet.is_empty(), "empty TLS datagram envelope");
                        responses
                            .send(Ok(packet.freeze()))
                            .await
                            .context("datagram receiver stopped")?;
                    }
                    anyhow::bail!("TLS datagram stream closed")
                },
                async {
                    while let Some(packet) = queued.recv().await {
                        timeout(deadline, writer.send(packet))
                            .await
                            .context("TLS datagram write timed out")??;
                    }
                    anyhow::bail!("TLS datagram sender stopped")
                }
            )
            .map(|_: ((), ())| ());
            if let Err(error) = result {
                let _ = responses.try_send(Err(io::Error::other(error.to_string())));
            }
        });
        Self {
            outgoing,
            incoming: Mutex::new(incoming),
            task,
        }
    }

    /// Preserve UDP loss semantics when the bounded TLS writer is congested.
    pub(super) fn send(&self, packet: Bytes) -> anyhow::Result<SendOutcome> {
        if packet.len() > PACKET_CAPACITY {
            return Ok(SendOutcome::Dropped(DropReason::TooLarge));
        }
        anyhow::ensure!(!packet.is_empty(), "empty UDP envelope");
        match self.outgoing.try_send(packet) {
            Ok(()) => Ok(SendOutcome::Sent),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Ok(SendOutcome::Dropped(DropReason::Congested))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                anyhow::bail!("TLS datagram stream closed")
            }
        }
    }

    /// Wait for one complete frame without losing partial wire data if the caller stops waiting.
    pub(super) async fn receive(&self) -> anyhow::Result<Bytes> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .context("TLS datagram stream closed")?
            .map_err(Into::into)
    }
}

/// Dropping an association immediately releases both TLS halves and every queued packet.
impl Drop for Datagrams {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Framing tests exercise cancellation and malicious lengths without relying on TCP packet segmentation.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Cancelling a receive midway through a header or body does not consume part of the next frame.
    #[tokio::test]
    async fn partial_frame_survives_receive_cancellation() {
        let (client, mut wire) = tokio::io::duplex(128);
        let channel = Datagrams::start(client, Duration::from_secs(1));
        wire.write_all(&[0, 0]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), channel.receive())
                .await
                .is_err()
        );
        wire.write_all(&[0, 3, b'a']).await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), channel.receive())
                .await
                .is_err()
        );
        wire.write_all(&[b'b', b'c', 0, 0, 0, 2, b'd', b'e'])
            .await
            .unwrap();
        assert_eq!(channel.receive().await.unwrap(), b"abc".as_slice());
        assert_eq!(channel.receive().await.unwrap(), b"de".as_slice());
    }

    /// Oversized declared lengths terminate the channel without allocating an attacker-sized frame.
    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (client, mut wire) = tokio::io::duplex(128);
        let channel = Datagrams::start(client, Duration::from_secs(1));
        wire.write_u32(PACKET_CAPACITY as u32 + 1).await.unwrap();
        assert!(
            timeout(Duration::from_secs(1), channel.receive())
                .await
                .unwrap()
                .is_err()
        );
    }

    /// A peer that stops reading cannot retain a blocked writer indefinitely.
    #[tokio::test]
    async fn writer_timeout_closes_association() {
        let (client, _wire) = tokio::io::duplex(8);
        let channel = Datagrams::start(client, Duration::from_millis(30));
        channel.send(Bytes::from(vec![0; 1024])).unwrap();
        assert!(
            timeout(Duration::from_secs(1), channel.receive())
                .await
                .unwrap()
                .is_err()
        );
    }

    /// Enqueuing on a full writer queue drops a packet instead of allocating unlimited pending work.
    #[tokio::test]
    async fn congested_writer_is_bounded() {
        let (client, _wire) = tokio::io::duplex(8);
        let channel = Datagrams::start(client, Duration::from_secs(1));
        for _ in 0..QUEUE_CAPACITY {
            assert_eq!(
                channel.send(Bytes::from_static(b"packet")).unwrap(),
                SendOutcome::Sent
            );
        }
        assert_eq!(
            channel.send(Bytes::from_static(b"overflow")).unwrap(),
            SendOutcome::Dropped(DropReason::Congested)
        );
    }
}
