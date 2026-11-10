//! Device construction delegates platform framing and address configuration to tun-rs.

use super::PacketDevice;
use crate::packet::{DEFAULT_MTU, validate_mtu};
use anyhow::{Context, ensure};
use ipnet::{Ipv4Net, Ipv6Net};
use std::{
    io,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

/// TUN options configure a new L3 device without taking ownership of default routes or DNS.
#[derive(Clone, Debug)]
pub struct TunOptions {
    pub name: Option<String>,
    pub mtu: u16,
    pub ipv4: Option<Ipv4Net>,
    pub ipv6: Option<Ipv6Net>,
}

/// Default options leave addresses explicit and let the OS allocate a device name.
impl Default for TunOptions {
    fn default() -> Self {
        Self {
            name: None,
            mtu: DEFAULT_MTU as u16,
            ipv4: None,
            ipv6: None,
        }
    }
}

/// Validation rejects ambiguous devices and unsafe address ranges before any privileged operation.
impl TunOptions {
    /// Validate MTU, host addresses, prefixes, and an optional platform-compatible interface name.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_mtu(usize::from(self.mtu))?;
        ensure!(
            self.ipv4.is_some() || self.ipv6.is_some(),
            "supply at least one TUN address"
        );
        if let Some(network) = self.ipv4 {
            let ip = network.addr();
            ensure!(
                network.prefix_len() > 0
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_loopback()
                    && !ip.is_broadcast(),
                "TUN IPv4 must be a unicast host address with a nonzero prefix"
            );
        }
        if let Some(network) = self.ipv6 {
            let ip = network.addr();
            ensure!(
                network.prefix_len() > 0
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_loopback()
                    && !ip.is_unicast_link_local(),
                "TUN IPv6 must be an unscoped unicast address with a nonzero prefix"
            );
        }
        if let Some(name) = &self.name {
            ensure!(
                !name.is_empty()
                    && name.len() <= 15
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')),
                "invalid TUN interface name"
            );
            #[cfg(target_os = "macos")]
            {
                let unit = name
                    .strip_prefix("utun")
                    .context("macOS TUN names must use utun followed by a number")?;
                ensure!(
                    !unit.is_empty()
                        && unit.bytes().all(|c| c.is_ascii_digit())
                        && unit.parse::<u32>().is_ok_and(|value| value < u32::MAX),
                    "invalid macOS utun number"
                );
            }
        }
        Ok(())
    }
}

/// A device owns one tun-rs handle with normalized raw-IP framing and RAII descriptor cleanup.
pub struct TunDevice {
    device: AsyncDevice,
}

/// Native device operations require a Tokio runtime and the platform's TUN permissions.
impl TunDevice {
    /// Create a new interface after validation while disabling macOS library-managed associated routes.
    pub fn create(options: &TunOptions) -> anyhow::Result<Self> {
        options.validate()?;
        if let Some(name) = &options.name {
            match nix::net::if_::if_nametoindex(name.as_str()) {
                Ok(_) => anyhow::bail!("refusing to reconfigure an existing interface"),
                Err(nix::errno::Errno::ENXIO | nix::errno::Errno::ENODEV) => {}
                Err(error) => return Err(error).context("checking TUN interface name"),
            }
        }
        let mut builder = DeviceBuilder::new()
            .layer(Layer::L3)
            .mtu(options.mtu)
            .enable(true);
        if let Some(name) = &options.name {
            builder = builder.name(name);
        }
        if let Some(address) = options.ipv4 {
            builder = builder.ipv4(address.addr(), address.prefix_len(), None);
        }
        if let Some(address) = options.ipv6 {
            builder = builder.ipv6(address.addr(), address.prefix_len());
        }
        #[cfg(target_os = "macos")]
        {
            builder = builder.associate_route(false).packet_information(false);
        }
        Ok(Self {
            device: builder.build_async().context("creating TUN device")?,
        })
    }

    /// Adopt an owned device descriptor without changing its addresses, routes, DNS, or MTU.
    ///
    /// # Safety
    /// The descriptor must be a TUN device; Linux requires IFF_NO_PI and no IFF_VNET_HDR.
    /// macOS must use the native utun packet header, which tun-rs strips and restores.
    pub unsafe fn from_owned_fd(fd: OwnedFd) -> anyhow::Result<Self> {
        // SAFETY: ownership is transferred once and the caller guarantees native TUN framing.
        let device =
            unsafe { AsyncDevice::from_fd(fd.into_raw_fd()) }.context("adopting TUN descriptor")?;
        #[cfg(target_os = "macos")]
        device.set_associate_route(false);
        device.name().context("validating TUN descriptor")?;
        Ok(Self { device })
    }

    /// Transfer the live device descriptor for a future authenticated helper-to-app handoff.
    pub fn into_owned_fd(self) -> io::Result<OwnedFd> {
        let fd = self.device.into_fd()?;
        // SAFETY: tun-rs transferred unique ownership of this open descriptor on success.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Read the device MTU so an adopted descriptor can be matched to the packet engine.
    pub fn mtu(&self) -> io::Result<u16> {
        self.device.mtu()
    }

    /// Return the actual OS-assigned interface name without exposing the owned descriptor.
    pub fn name(&self) -> io::Result<String> {
        self.device.name()
    }
}

/// Packet reads and writes use tun-rs normalization rather than custom platform headers.
impl PacketDevice for TunDevice {
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        self.device.recv(packet).await
    }
    async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.device.send(packet).await
    }
}
