# Connection backends

The app stores one selected backend and allows switching while disconnected and free of pending recovery.

| Backend | Status |
| --- | --- |
| System proxy | Connected to the Rust SOCKS core and macOS settings controller |
| NetworkExtension | Selection only; provider, activation, and deployment are missing |
| Helper TUN | Bundled helper with registration and read-only IPC; Rust device transport exists, but app handoff, routing, and DNS are missing |

Unavailable backends cannot connect. Selection is saved in `connection.json`; corrupt preferences produce an error rather than selecting another backend. Connection failure does not cause automatic fallback.

## Helper installation

Select **Helper TUN** in the app to install the bundled component, open system approval settings, refresh status, or remove it. Component changes require a disconnected app with no pending recovery. The app refreshes approval status when it becomes active.

Registration uses Apple's `SMAppService.daemon`, with the plist in `Contents/Library/LaunchDaemons` and the executable in `Contents/Library/HelperTools`. macOS requires administrator approval before the daemon can run. The app does not copy files into system launchd directories or collect an administrator password. Apple recommends keeping daemon-hosting apps in `/Applications`. See [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

An approved registration does **not** make TUN usable. The current helper only reports capabilities; it cannot create interfaces or change network settings. IPC accepts the `dev.zion.client` app signed by the helper's own Apple signing team. Ad hoc builds cannot establish that identity and reject IPC clients. Real registration, approval, and signed IPC have not been exercised by automated tests.

Local packaging defaults to ad hoc signing. Set `ZION_CODESIGN_IDENTITY` to an installed signing identity to sign the app, core, and helper consistently; notarization remains outside the build script. Registering an updated helper may require removal and re-registration.

## Shared packet engine

The `packet-tunnel` Cargo feature uses netstack-smoltcp to turn raw IPv4/IPv6 TCP and UDP packets into Zion sessions over the configured QUIC or TCP/TLS carrier. It authenticates before reporting readiness and uses bounded queues with a shared TCP/UDP session budget.

The packet engine does not create interfaces or configure routes and DNS. The optional `tun-device` feature adds a tun-rs adapter and a foreground CLI for macOS/Linux; see [TUN transport](tun.md). NetworkExtension `packetFlow` and helper-to-app device handoff remain unimplemented.

ICMP and fragmented IP packets are unsupported. UDP exceeding the virtual MTU or QUIC Datagram limit is dropped. Full IPv6 extension-header coverage has not been established.

## Native bridge

`NativePacketEngine` links Rust statically through [CZionPacket.h](../macos/Sources/CZionPacket/include/CZionPacket.h). Startup passes client configuration and PEM credentials in memory, avoiding file-path access from a future extension. The envelope is limited to 256 KiB.

Packet and event callbacks borrow bytes until return; hosts must copy retained data. Keep callback context alive until destruction finishes. Submission must be serialized against destruction, and destruction must never run inside a callback: it cancels and joins the worker thread.

Swift removes the send handle before teardown and rejects late events from previous runs. Native lifecycle events are `ready`, `error`, and `stopped`; they contain no credentials.

## Build and test

The standard `scripts/build-macos.py` package uses the supervised SOCKS core and does not link the optional packet engine. It includes the helper for registration management; that helper does not provide a working TUN backend.

Test the current app/core integration after packaging:

```sh
python3 scripts/build-macos.py
ZION_INTEGRATION_CORE="$PWD/target/macos/Zion.app/Contents/Helpers/zion-core" \
ZION_CONTROL_CLI="$PWD/target/macos/Zion.app/Contents/Helpers/zion-core" \
swift test --package-path macos
```

To exercise the optional Rust device and native bridge independently:

```sh
cargo test --locked --features tun-device
cargo build --locked --release --features tun-device --lib
swift package --package-path macos clean
ZION_PACKET_LIBRARY="$PWD/target/release/libzion.a" \
ZION_INTEGRATION_CORE="$PWD/target/macos/Zion.app/Contents/Helpers/zion-core" \
swift test --package-path macos
```

Clean Swift build products when replacing the external static archive: SwiftPM does not track its contents as a source dependency. Default packaging explicitly disables this optional linkage.

Tests cover raw IPv4/IPv6 TCP and UDP, half-close, empty datagrams, queue limits, authentication, and native start/stop/restart. Backend controller tests use substitute adapters. No test installs a helper or extension, creates utun, or changes system networking.
