# Connection backends

The app stores one selected backend and allows switching while disconnected and free of pending recovery.

| Backend | Status |
| --- | --- |
| System proxy | Connected to the Rust SOCKS core and macOS settings controller |
| NetworkExtension | Selection only; provider, activation, and deployment are missing |
| Helper TUN | Selection only; privileged service, IPC, utun, route, and DNS management are missing |

Unavailable backends cannot connect. Selection is saved in `connection.json`; corrupt preferences produce an error rather than selecting another backend. Connection failure does not cause automatic fallback.

## Shared packet engine

The `packet-tunnel` Cargo feature uses netstack-smoltcp to turn raw IPv4/IPv6 TCP and UDP packets into Zion QUIC sessions. It authenticates before reporting readiness and uses bounded queues with a shared TCP/UDP session budget.

The engine does not create interfaces or configure routes and DNS. Future platform adapters must supply packets from NetworkExtension `packetFlow` or helper-managed utun. Neither adapter exists yet.

ICMP and fragmented IP packets are unsupported. UDP exceeding the virtual MTU or QUIC Datagram limit is dropped. Full IPv6 extension-header coverage has not been established.

## Native bridge

`NativePacketEngine` links Rust statically through [CZionPacket.h](../macos/Sources/CZionPacket/include/CZionPacket.h). Startup passes client configuration and PEM credentials in memory, avoiding file-path access from a future extension. The envelope is limited to 256 KiB.

Packet and event callbacks borrow bytes until return; hosts must copy retained data. Keep callback context alive until destruction finishes. Submission must be serialized against destruction, and destruction must never run inside a callback: it cancels and joins the worker thread.

Swift removes the send handle before teardown and rejects late events from previous runs. Native lifecycle events are `ready`, `error`, and `stopped`; they contain no credentials.

## Build and test

```sh
cargo test --locked --features packet-tunnel
python3 scripts/build-macos.py
ZION_PACKET_LIBRARY="$PWD/target/release/libzion.a" \
ZION_INTEGRATION_CORE="$PWD/target/macos/Zion.app/Contents/Helpers/zion-core" \
swift test --package-path macos
```

The packaging script enables the feature and links the static library. Standalone Swift builds need `ZION_PACKET_LIBRARY` to enable native linking. Real-core tests require `ZION_INTEGRATION_CORE`; native engine coverage also requires the library.

Tests cover raw IPv4/IPv6 TCP and UDP, half-close, empty datagrams, queue limits, authentication, and native start/stop/restart. Backend controller tests use substitute adapters. No test installs a helper or extension, creates utun, or changes system networking.

Remaining platform work includes authorized installation, caller identity checks, endpoint loop prevention, route and DNS policy, network changes, and crash recovery.
