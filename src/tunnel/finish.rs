//! Stream completion distinguishes acknowledged delivery from peer cancellation.

use anyhow::{Context, bail};
use quinn::SendStream;
use std::time::Duration;
use tokio::time::timeout;

/// Wait for transport acknowledgement and reject a peer's explicit stop code.
pub(super) async fn acknowledged(stream: &SendStream, deadline: Duration) -> anyhow::Result<()> {
    let stopped = timeout(deadline, stream.stopped())
        .await
        .context("timed out waiting for QUIC stream acknowledgement")?
        .context("QUIC connection failed while waiting for stream acknowledgement")?;
    if let Some(code) = stopped {
        bail!("peer stopped QUIC send stream with code {code}");
    }
    Ok(())
}
