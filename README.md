# Zion

*Across the noise, a quiet passage.*

A small Rust core and a native macOS companion, built around simple configuration, familiar foundations, and room to grow.

Tokio keeps time. Quinn carries the streams. Rustls guards the crossing.

## Inside

- TCP and UDP over authenticated QUIC, with IPv4 and IPv6 support.
- Minimal JSON or YAML configuration, using passwords, client certificates, or both.
- System DNS or explicit server-side resolvers, with shared TTL caches.
- A SwiftUI macOS app with Keychain storage, system proxy controls, and a menu bar presence.
- An optional IP packet engine with a tun-rs device adapter for macOS and Linux.

Zion is young. The system proxy works today; NetworkExtension and helper-based TUN are selectable in the interface, but their system adapters are still unfinished. Full-device traffic capture is not yet available.

## Begin

Requires Rust 1.91 or later.

```sh
cargo build --locked --release
```

A minimal client configuration:

```yaml
server: passage.example.com:8443
password: replace-with-a-long-random-password
```

The server needs a matching password and a TLS identity:

```yaml
password: replace-with-a-long-random-password
cert: server.pem
key: server.key
```

Run each on its respective host:

```sh
./target/release/zion server -c server.yaml
./target/release/zion client -c client.yaml
```

The client listens on `127.0.0.1:1080`. Point a SOCKS5-capable application there. The server listens on `[::]:8443` by default and needs inbound UDP access; use `0.0.0.0:8443` on an IPv4-only host.

Server identity is always verified. The minimal example assumes a publicly trusted certificate matching the server name; for a private CA, add `ca: ca.pem` to the client. Certificate paths are relative to the configuration file.

See [configuration](docs/configuration.md) and [examples](examples/) for certificate authentication, private identities, and additional options.

## On macOS

Requires macOS 14 or later and Xcode with command-line tools configured.

```sh
python3 scripts/build-macos.py
```

The locally signed app is written to `target/macos/Zion.app`, with the Rust core included. System proxy settings apply to applications that honor them. The interface is currently in Chinese.

Manage servers and connections through the [app control CLI](docs/cli.md), or read about the [native app](docs/macos-client.md) and [backend integration](docs/backends.md).

## Develop

```sh
cargo fmt --check
cargo clippy --locked --all-targets --features tun-device -- -D warnings
cargo test --locked --features tun-device
swift test --package-path macos
```

Swift tests require macOS. Native engine integration tests need the linked Rust library and a built core; setup is documented in [backend integration](docs/backends.md).

Further notes: [wire protocol](docs/protocol.md), [DNS](docs/dns.md), and [dual stack](docs/dual-stack.md), and [TUN transport](docs/tun.md).

## License

Available under either the [MIT License](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.
