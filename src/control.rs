//! Process events expose readiness without mixing diagnostic logs or secret configuration.

use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    net::SocketAddr,
};

/// A process event describes authenticated readiness, clean shutdown, or startup failure.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Ready { listen: SocketAddr },
    Stopped,
    Error { message: String },
}

/// Event operations write one flushed JSON line for native process supervisors.
impl Event {
    /// Emit a bounded lifecycle event to stdout without serializing configuration fields.
    pub fn write(&self) -> io::Result<()> {
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, self)?;
        writeln!(output)?;
        output.flush()
    }
}
