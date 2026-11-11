# macOS client

Requires macOS 14+, Rust 1.91+, and an Xcode toolchain supporting Swift 6. The interface is in Chinese.

## Build and start

```sh
python3 scripts/build-macos.py
open target/macos/Zion.app
```

The host-architecture bundle includes `Contents/Helpers/zion-core` and the registration helper. It uses the supervised SOCKS core; the optional packet engine is not linked into the default app. Signing is local ad hoc signing unless `ZION_CODESIGN_IDENTITY` is supplied. Notarization is not part of the script.

Standalone development must explicitly select its core:

```sh
cargo build --locked --bin zion
ZION_CORE_PATH="$PWD/target/debug/zion" swift run --package-path macos ZionMac
```

Without `ZION_CORE_PATH`, the app only uses its bundled executable. It never searches the source tree for another core.

## Workspace

- **概览**: server selection, connection, and network recovery.
- **服务器**: profiles and JSON import. Optional CA, certificate-name, interface, and additional client-certificate fields are under Advanced.
- **进程流量**: per-process uploads, downloads, active connections, and connection decisions. Select a process to filter the resizable connection pane.
- **规则与策略**: exact process-name/path rules in explicit priority order, with proxy/direct/reject policies and a FINAL default.
- **日志**: searchable session events, severity filters, follow, clear, and copy diagnostics. Connection status stays on Overview and Settings.
- **设置**: connection backend, listener, configuration directory, setup guide, and version.

The workspace is full width and left aligned, with borderless controls and shared 8/16/32-point spacing. The sidebar contains navigation only.

The first-launch guide can be dismissed with **完成** without configuring a server or connecting. **启动时显示** controls future launches. Opening it only inspects network state; connection and component registration remain explicit actions. Enhanced-mode details are collapsed by default.

## Process routing and traffic

First enabled exact, case-sensitive match wins; unmatched or unidentified processes use FINAL. Proxy uses the selected server; direct uses the local network and resolver; reject denies the SOCKS command. A failed proxy does not switch to direct access. UDP uses the owner of its TCP association for all datagrams.

Disconnect before changing rules, then reconnect. The process table's policy menu adds the rule at highest priority, preferring the executable path and using the process name only when its path is unavailable. The rule page supports enable/disable, ordering, policy changes, and deletion.

Ownership is best effort on macOS: bounded `lsof` queries match the exact client-to-listener socket, then `ps` supplies the executable path. Four queries run concurrently, with a 750 ms deadline including queueing. Permission failures, exited processes, and timeouts appear as unknown ownership. Processes bypassing SOCKS are outside routing and statistics.

Traffic history is memory-only, capped at 500 connections. Totals cover retained connections, preserving active entries when evicting history. Updates arrive about once a second. TCP counts application data; UDP includes SOCKS envelopes; tunnel overhead is excluded. A new core clears history, and clearing completed connections preserves active counters.

## Storage and import

Metadata lives in `~/Library/Application Support/Zion/`:

| File | Content |
| --- | --- |
| `profiles.json` | Current profile schema and selection; stored profiles require an explicit transport |
| `routing.json` | Ordered global process rules and default policy |
| `connection.json` | Selected backend |
| `setup.json` | Setup preference |
| `proxy-recovery.plist` | Original network settings awaiting restoration |

Passwords are in Keychain; selected certificate/private-key files stay in their original locations. Unreadable configuration is preserved and blocks the affected operation.

UI import accepts server-profile JSON; the [CLI](cli.md) also accepts YAML. Both use the same profile field validation. Certificate paths resolve relative to the source file. `listen` is ignored because the app allocates its own port. Global `routing` is not imported into a server profile; configure it on the rules page. Import leaves the source file untouched.

## Supervision and recovery

The app sends configuration through stdin to `zion-core client --config - --events-json`. Stdout carries JSON lifecycle and traffic events; stderr carries diagnostics. The core binds a random IPv4 loopback port and verifies remote authentication before reporting ready, then the app requests system-proxy authorization.

System proxy activation sets SOCKS on enabled services, temporarily disables HTTP/HTTPS/PAC/autodiscovery, removes SOCKS credentials, and preserves bypass rules. Disconnect restores the recorded settings while preserving external changes. If restoration fails, the core stays running and recovery is required before reconnecting. Normal app exit also attempts restoration. A forced exit may leave settings behind; recover on the next launch.

Logs retain at most 500 entries in memory, roughly 1 KiB each. Known passwords, named secret fields, private-key blocks, and terminal escapes are filtered. Copied diagnostics include server addresses and system version. No log file is written.

Only applications honoring system SOCKS settings are covered. There is no full-device capture, kill switch, automatic network-location tracking, or live rule reload. Helper registration does not enable TUN routing; see [backend status](backends.md).

## Validation and cleanup

```sh
swift test --package-path macos
python3 scripts/clean-build.py
```

Tests use temporary storage and substitute system-network/Keychain services. Optional real-core and native-library tests are described in [backends](backends.md). They do not exercise GUI layout or authorization dialogs. Cleanup retains the packaged app; add `--all` to remove it too.
