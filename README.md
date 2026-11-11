# Zion

A Rust proxy core with a native macOS app for managing which processes use a proxy.

## Current features

- TCP and UDP forwarding over QUIC or TCP/TLS, with IPv4 and IPv6 support.
- Password authentication, client certificates, or both; verified server identity.
- macOS system SOCKS proxy controls, Keychain credentials, and network-settings recovery.
- Ordered process-name/path rules: proxy, direct, or reject, plus a default policy.
- Per-process traffic and connection decisions, retaining up to 500 connections in memory.
- JSON/YAML configuration and a local app-control CLI.

Process routing covers connections entering Zion's SOCKS listener. The app does not capture all device traffic. NetworkExtension and Helper TUN are not usable connection backends; helper registration and the optional packet/TUN library are separate from system-proxy operation.

## Start the macOS app

Requires macOS 14+, Rust 1.91+, and an Xcode toolchain supporting Swift 6.

```sh
python3 scripts/build-macos.py
open target/macos/Zion.app
```

Add a server, select system proxy, and connect. Disconnect before changing process rules; reconnect to apply them. See the [macOS guide](docs/macos-client.md).

## Run the core

```sh
cargo build --locked --release --bin zion
./target/release/zion server -c server.yaml
./target/release/zion client -c client.yaml
```

Run the server and client on their respective hosts. Minimal files:

```yaml
# server.yaml
password: replace-with-a-long-random-password
cert: server.pem
key: server.key
```

```yaml
# client.yaml
server: passage.example.com:8443
password: replace-with-a-long-random-password
```

The client listens at `127.0.0.1:1080`; the server defaults to QUIC on `[::]:8443`. The server certificate must be trusted and match its name. Add `ca: ca.pem` for a private CA. Set `transport: tls` on both sides for TCP/TLS, or `transport: both` on the server to accept either carrier.

See [configuration](docs/configuration.md), [examples](examples/), and the [app-control CLI](docs/cli.md).

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets --features tun-device -- -D warnings
cargo test --locked --features tun-device
swift test --package-path macos
```

Default macOS packaging uses the supervised SOCKS core. Optional packet-engine linking and integration tests are documented in [backends](docs/backends.md); the standalone device adapter is described in [TUN transport](docs/tun.md). Other references: [wire protocol](docs/protocol.md), [server DNS](docs/dns.md).

## Clean build products

```sh
python3 scripts/clean-build.py
```

This removes Rust/Swift build caches, including cross-target builds, while preserving `target/macos/Zion.app`. Use `--all` to remove the packaged app too. Source, runtime configuration, and credentials are retained. Build again with `scripts/build-macos.py` when needed.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
