//! tun-rs supplies privileged device access while the shared netstack handles TCP and UDP sessions.

/// CLI startup authenticates before creating a device and never changes default routes or DNS.
pub mod cli;
/// Device options validate addresses and keep device creation separate from routing policy.
mod device;
/// The packet pump bounds buffers and preserves device datagram boundaries.
mod pump;

pub use device::{TunDevice, TunOptions};
pub use pump::{PacketDevice, TunStatistics, forward};
