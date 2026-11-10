# TUN device transport

The `tun-device` feature connects tun-rs 2.8.18 to the shared netstack-smoltcp 0.2.5 packet engine on macOS and Linux. netstack-smoltcp was already current. tun-rs requires Tokio 1.53 or later; the lockfile now selects Tokio 1.54.1.

This is a library adapter and a foreground CLI entry point. The app's privileged helper still exposes only read-only status: descriptor transfer, route ownership, DNS policy, and recovery are not wired into the app. Installing the helper does not enable this transport.

## Build and run

```sh
cargo build --locked --release --features tun-device
```

Use the existing client JSON/YAML, including an explicit physical outbound `interface`, such as `en0` on macOS or `eth0` on Linux. This binds the selected QUIC or TCP/TLS carrier to that device. Server resolution and authentication happen before creating TUN.

With the platform's TUN permissions:

```sh
sudo ./target/release/zion tun -c client.json \
  --ipv4 198.18.0.1/30 --ipv6 fd77::1/64
```

At least one address is required. `--mtu` defaults to 1500 and accepts 1280–9000. Omit `--name` for OS allocation; macOS explicit names must be `utun` followed by a number. Existing named interfaces are rejected rather than reconfigured.

**The command does not install default routes or configure DNS.** Device creation alone does not capture application traffic. Assigning addresses can create OS-connected routes; macOS library-managed associated routes are disabled. A future capture policy must handle endpoint bypass, destination routing, DNS, and restoration together.

Stop with Ctrl-C. The pump stops the packet engine and releases its device handle. Newly created nonpersistent interfaces follow OS descriptor lifetime; adopted interfaces may have other owners.

## Library boundary

- `TunDevice::create` validates options and delegates interface setup to tun-rs.
- `from_owned_fd` adopts a real TUN descriptor; `into_owned_fd` transfers ownership for a future authenticated helper handoff. Linux descriptors require `IFF_NO_PI` and no `IFF_VNET_HDR`.
- tun-rs handles the macOS utun header. The packet engine receives raw IPv4/IPv6 packets.
- `forward` uses the engine's MTU and bounded queues. Invalid, oversized, or queue-rejected input is dropped. Short device writes and I/O failures stop forwarding; partial packets are not retried as separate writes.

ICMP and IP fragments remain unsupported. Large UDP datagrams are not automatically fragmented to fit QUIC or the virtual MTU.

## Verification

```sh
cargo test --locked --features tun-device
cargo clippy --locked --all-targets --features tun-device -- -D warnings
```

Tests use Unix datagram device fixtures and real loopback QUIC. They cover IPv4/IPv6 UDP, empty payloads, malformed and oversized input, short writes, I/O failure, and cancellation during a blocked write. Existing packet tests cover TCP and half-close. No test creates a kernel TUN or changes host networking; real privileged-device operation remains unverified.
