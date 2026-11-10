# macOS client

The SwiftUI/AppKit app requires macOS 14 or later. Its connection state is shared by the main window and menu bar. The interface is currently in Chinese.

## Build

Use Rust 1.91 or later and an Xcode toolchain supporting Swift 6:

```sh
python3 scripts/build-macos.py
```

The script builds for the host architecture and creates `target/macos/Zion.app`, including `Contents/Helpers/zion-core` and the linked Rust packet engine. Signing is local ad hoc signing; Developer ID distribution, notarization, and NetworkExtension entitlements are not configured.

For a standalone Swift build:

```sh
swift build --package-path macos
```

The development app looks for `target/debug/zion`; packaged builds use their bundled core. `ZION_CORE_PATH` overrides either location. See [backends](backends.md) for static-library linking and native integration tests.

## Profiles

Add a name, server address, and password, or use a client certificate. Advanced password settings can include a certificate pair when both factors are required. Private CA files, certificate-name overrides, and outbound interfaces are supported.

The app imports JSON client configurations; the CLI also accepts YAML. Relative certificate paths are resolved from the imported file's directory. Import does not delete or redact the original file.

Profiles live in `~/Library/Application Support/Zion/profiles.json`. Passwords are stored in Keychain; selected private keys remain in their original files. Backend selection is saved separately in `connection.json`.

## App control

The [app control CLI](cli.md) manages profiles and connections through a same-user local socket. Changes appear in the running UI; passwords remain in Keychain. Restart an older app build before using these commands.

## Core process

The system-proxy backend launches:

```sh
zion-core client --config - --events-json
```

Configuration is sent as JSON through stdin, then the pipe is closed. Stdout carries newline-delimited lifecycle events; diagnostics go to stderr:

```json
{"event":"ready","listen":"127.0.0.1:49152"}
{"event":"stopped"}
```

Startup failure emits `{"event":"error","message":"..."}` and exits unsuccessfully. The core binds a random loopback port and authenticates a real QUIC session before reporting ready. This is a startup probe, not ongoing health monitoring.

The controller validates the loopback address, bounds output buffering and startup time, and rejects callbacks from old processes. The activity view retains up to 500 log entries; traffic counters and latency measurements are not implemented.

## System proxy and recovery

After core readiness, the app requests network-settings authorization and sets SOCKS on enabled network services in the current location. It temporarily disables HTTP, HTTPS, PAC, and autodiscovery, removes SOCKS credentials, and preserves bypass rules.

A mode-`0600` recovery journal, `proxy-recovery.plist`, is saved before settings change. It can contain previous proxy credentials. Disconnect restores the snapshot; services changed by another application are preserved. If restoration fails, the core stays running and reconnection is blocked until recovery succeeds. Normal app exit also attempts restoration.

The app does not continuously track new services or network-location changes. A forced exit can leave settings and the core process behind; recovery is available on the next launch. There is no independent cleanup daemon.

Only applications honoring system SOCKS settings are covered. This mode provides neither full-device capture nor a kill switch. NetworkExtension and helper-based TUN adapters are [unfinished](backends.md).

## Tests

```sh
swift test --package-path macos
```

Control tests use temporary files and substitute network settings, without writing system proxy preferences or Keychain. Optional real-core tests use a local QUIC server. They do not validate authorization dialogs, GUI layout, or live system-network takeover.
