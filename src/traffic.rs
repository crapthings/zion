//! Bounded per-session events report payload counters without recording request contents.

use crate::routing::{Policy, ProcessIdentity};
use serde::Serialize;
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Session metadata accompanies cumulative payload counters in the native event stream.
#[derive(Serialize)]
struct Record {
    event: &'static str,
    id: u64,
    process: ProcessIdentity,
    target: String,
    protocol: &'static str,
    policy: Policy,
    rule: String,
    #[serde(skip)]
    started: Instant,
}

/// Shared counters permit asynchronous snapshots without retaining application payloads.
#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

/// A session guard publishes at most one update per second and a final terminal record.
pub struct Flow {
    record: Arc<Record>,
    counters: Arc<Counters>,
    ticker: Option<tokio::task::JoinHandle<()>>,
    enabled: bool,
    status: &'static str,
}

/// Flow operations share counters between stream wrappers and UDP associations.
impl Flow {
    /// Start a bounded telemetry task only when machine events were explicitly requested.
    pub fn start(
        process: ProcessIdentity,
        target: String,
        protocol: &'static str,
        policy: Policy,
        rule: String,
        enabled: bool,
    ) -> Self {
        /// Session IDs increase across all accepted connections in one core process.
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let record = Arc::new(Record {
            event: "traffic",
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            process,
            target,
            protocol,
            policy,
            rule,
            started: Instant::now(),
        });
        let counters = Arc::new(Counters::default());
        let ticker = if enabled {
            publish(&record, &counters, "active");
            let record = record.clone();
            let counters = counters.clone();
            Some(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    publish(&record, &counters, "active");
                }
            }))
        } else {
            None
        };
        Self {
            record,
            counters,
            ticker,
            enabled,
            status: "cancelled",
        }
    }

    /// Add successfully forwarded UDP envelope bytes in their corresponding direction.
    pub fn add(&self, up: u64, down: u64) {
        self.counters.up.fetch_add(up, Ordering::Relaxed);
        self.counters.down.fetch_add(down, Ordering::Relaxed);
    }

    /// Mark the terminal outcome before the guard publishes its final snapshot.
    pub fn finish(&mut self, status: &'static str) {
        self.status = status;
    }

    /// Count TCP payload bytes while retaining all existing stream semantics.
    pub fn stream<T>(&self, io: T) -> Metered<T> {
        Metered {
            io,
            counters: self.counters.clone(),
        }
    }
}

/// Dropping a session stops its reporter and emits the final cumulative counters.
impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(task) = self.ticker.take() {
            task.abort();
        }
        if self.enabled {
            publish(&self.record, &self.counters, self.status);
        }
    }
}

/// Serialize a full cumulative snapshot so dropped intermediate updates need no recovery.
fn publish(record: &Record, counters: &Counters, status: &str) {
    use std::io::Write;
    let mut value = serde_json::to_value(record).expect("traffic record serializes");
    value["up"] = counters.up.load(Ordering::Relaxed).into();
    value["down"] = counters.down.load(Ordering::Relaxed).into();
    value["duration_ms"] =
        (record.started.elapsed().as_millis().min(u64::MAX as u128) as u64).into();
    value["status"] = status.into();
    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, &value);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

/// A metered stream records bytes read from and written to the local application socket.
pub struct Metered<T> {
    io: T,
    counters: Arc<Counters>,
}

/// Reads count application uploads even if a later network failure interrupts the relay.
impl<T: AsyncRead + Unpin> AsyncRead for Metered<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.io).poll_read(cx, buf);
        this.counters
            .up
            .fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        result
    }
}

/// Writes count only download bytes successfully accepted by the application socket.
impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(length)) = &result {
            this.counters
                .down
                .fetch_add(*length as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Metering tests verify byte accuracy and half-close behavior on a real asynchronous stream.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Counters measure application payloads and preserve EOF independently in either direction.
    #[tokio::test]
    async fn counts_payload_and_preserves_half_close() {
        let flow = Flow::start(
            ProcessIdentity::default(),
            "test:1".into(),
            "TCP",
            Policy::Direct,
            "FINAL".into(),
            false,
        );
        let (socket, mut client) = duplex(64);
        let mut metered = flow.stream(socket);
        client.write_all(b"upload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut data = Vec::new();
        metered.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"upload");
        metered.write_all(b"download").await.unwrap();
        metered.shutdown().await.unwrap();
        data.clear();
        client.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"download");
        assert_eq!(flow.counters.up.load(Ordering::Relaxed), 6);
        assert_eq!(flow.counters.down.load(Ordering::Relaxed), 8);
    }
}
