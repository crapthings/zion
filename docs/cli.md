# App control CLI

`zion app` controls a running macOS app. The app owns profiles, Keychain access, and network settings; the CLI does not start another proxy or edit storage behind it.

Build with `python3 scripts/build-macos.py`, then restart the app to load the control service. The commands below use the built CLI directly; add `target/release` to your PATH if you prefer `zion`.

```sh
./target/release/zion app status
./target/release/zion app logs --limit 20
./target/release/zion app profile import --name Tokyo -c client.yaml
./target/release/zion app profile list
./target/release/zion app connect
./target/release/zion app disconnect
```

Import accepts CLI client JSON/YAML and adds a new profile, selecting it immediately. It resolves credential paths relative to the file, stores the password in Keychain, and returns the profile UUID. The app chooses its own local listener; an imported `listen` value is not used. Import limits are 64 profiles and 128 UTF-8 bytes for the name.

Use `-c -` for stdin JSON; credential paths then resolve from the working directory. Password arguments are intentionally absent. Keychain and network-settings authorization may still require user interaction.

```sh
./target/release/zion app profile select PROFILE_UUID
./target/release/zion app profile remove PROFILE_UUID
./target/release/zion app backend systemProxy
```

Profiles cannot change while connected, awaiting recovery, or being edited in the UI. Importing the same file again creates another profile. `networkExtension` and `helperTun` can be selected but remain unavailable for connection.

`connect` succeeds only after the core is ready and system proxy activation completes. Calling it while already connected returns current status. `disconnect` also retries pending network recovery. The app must remain running; the CLI does not launch it automatically.

## Agent contract

Responses are JSON on stdout, with version `1`. Exit code `0` means success; `1` means an operation or transport failure. CLI syntax errors use Clap's normal usage output and exit code `2`.

```json
{"version":1,"ok":true,"result":{"phase":"disconnected","selected_backend":"systemProxy","active_backend":null,"selected_profile":null,"endpoint":null,"needs_recovery":false,"can_connect":false}}
```

```json
{"version":1,"ok":false,"error":{"code":"no_profile","message":"Import and select a server first."}}
```

Branch on `ok`, `error.code`, and state fields rather than parsing messages. Phases are `disconnected`, `connecting`, `authorizing`, `connected`, `disconnecting`, `recovery_required`, and `failed`. Profile listing returns `profiles` and optional `selectedID`; passwords and private-key contents are never returned.

Error codes include `invalid_arguments`, `control_unavailable`, `unsupported_version`, `invalid_request`, `unknown_command`, `storage_unavailable`, `busy`, `not_found`, `no_profile`, `backend_unavailable`, `connection_failed`, `recovery_required`, `operation_failed`, and `response_too_large`.

`logs --limit N` reads the most recent 1–100 sanitized session entries (default 100). Its result contains `entries` with `id`, ISO 8601 `date`, `level`, and `message`, plus `retained` for the total buffered count. Reading logs does not alter the connection. Logs can contain destination or server addresses.

## Local protocol

The app listens at `/tmp/zion-UID/control.sock` in a private directory. Socket permissions are `0600`, and both peers verify the other endpoint's UID. An exclusive lock permits one app control owner. This trusts processes running as the same user; it does not isolate agents from other local applications.

Requests are one JSON line of at most 64 KiB; responses are at most 256 KiB. Eight clients may be in flight. Requests have a five-second input deadline; the CLI uses a 90-second socket read timeout. Closing a CLI does not cancel an action already accepted by the app. After a timeout, query status before retrying a mutation; imports are not idempotent.

```json
{"version":1,"command":"status","arguments":{}}
```

| Command | Arguments |
| --- | --- |
| `status`, `connect`, `disconnect`, `profiles.list` | Empty object |
| `logs.read` | `limit` (string integer, 1–100) |
| `profiles.import` | `name`, `config` (client JSON encoded as a string) |
| `profiles.select`, `profiles.remove` | `id` (UUID) |
| `backend.select` | `backend` (`systemProxy`, `networkExtension`, `helperTun`) |

`--socket PATH` overrides the endpoint for isolated tests. Tests use fake credentials and network settings; `ZION_CONTROL_CLI` enables the Rust-to-Swift socket integration test.
