//! App commands control the native client's single settings owner through a private local socket.

use anyhow::{Context, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::PathBuf};
use zeroize::Zeroizing;

/// App options expose explicit operations and an optional local endpoint for isolated testing.
#[derive(Args)]
pub struct AppArgs {
    /// Override the native app control socket path.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: AppCommand,
}

/// App commands keep connection actions separate from profile and backend selection.
#[derive(Subcommand)]
enum AppCommand {
    /// Return the live app connection state.
    Status,
    /// Read recent sanitized app logs without changing the connection.
    Logs {
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
    },
    /// Manage the bundled helper registration without claiming TUN readiness.
    Component {
        #[command(subcommand)]
        command: ComponentCommand,
    },
    /// Connect the selected profile using the selected backend.
    Connect,
    /// Disconnect and restore network settings, or retry pending recovery.
    Disconnect,
    /// Manage saved servers without exposing their passwords.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Select a backend while disconnected.
    Backend {
        #[arg(value_parser = ["systemProxy", "networkExtension", "helperTun"])]
        backend: String,
    },
}

/// Component commands preserve system approval as a separate step from registration.
#[derive(Subcommand)]
enum ComponentCommand {
    /// Read bundled payload and OS registration status.
    Status,
    /// Ask macOS to register the helper; administrator approval may still be required.
    Install,
    /// Remove the helper registration while disconnected.
    Uninstall,
}

/// Profile operations use stable UUIDs and import secrets through files or stdin rather than arguments.
#[derive(Subcommand)]
enum ProfileCommand {
    /// List server metadata and the selected profile ID.
    List,
    /// Add and select a server from client JSON/YAML; use '-' for stdin JSON.
    Import {
        #[arg(long)]
        name: String,
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Choose the carrier for a saved server without changing its credentials.
    Transport {
        id: String,
        #[arg(value_enum)]
        transport: crate::tunnel::Transport,
    },
    /// Select a saved server by UUID.
    Select { id: String },
    /// Remove a server and its Keychain password by UUID.
    Remove { id: String },
}

/// Execute one local request and always print a versioned JSON result with a meaningful exit code.
pub fn run(options: &AppArgs) -> i32 {
    let response = match request(options) {
        Err(_) => json!({"version":1,"ok":false,"error":{"code":"invalid_arguments","message":"Invalid command input; check configuration fields, paths, and size limits."}}),
        Ok(request) => exchange(options, &request).unwrap_or_else(|_| json!({"version":1,"ok":false,"error":{"code":"control_unavailable","message":"Cannot reach app control. Ensure Zion is running and the socket is owned by this user."}})),
    };
    println!("{response}");
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        0
    } else {
        1
    }
}

/// Convert typed CLI arguments into the shared control schema while resolving imported file paths.
fn request(options: &AppArgs) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut arguments = BTreeMap::<String, String>::new();
    let command = match &options.command {
        AppCommand::Status => "status",
        AppCommand::Component { command } => match command {
            ComponentCommand::Status => "component.status",
            ComponentCommand::Install => "component.install",
            ComponentCommand::Uninstall => "component.uninstall",
        },
        AppCommand::Logs { limit } => {
            arguments.insert("limit".into(), limit.to_string());
            "logs.read"
        }
        AppCommand::Connect => "connect",
        AppCommand::Disconnect => "disconnect",
        AppCommand::Backend { backend } => {
            arguments.insert("backend".into(), backend.clone());
            "backend.select"
        }
        AppCommand::Profile { command } => match command {
            ProfileCommand::List => "profiles.list",
            ProfileCommand::Transport { id, transport } => {
                arguments.insert("id".into(), id.clone());
                arguments.insert(
                    "transport".into(),
                    serde_json::to_value(transport)?
                        .as_str()
                        .expect("transport string")
                        .into(),
                );
                "profiles.transport"
            }
            ProfileCommand::Select { id } | ProfileCommand::Remove { id } => {
                arguments.insert("id".into(), id.clone());
                if matches!(command, ProfileCommand::Select { .. }) {
                    "profiles.select"
                } else {
                    "profiles.remove"
                }
            }
            ProfileCommand::Import { name, config } => {
                let mut source = Zeroizing::new(String::new());
                if config == std::path::Path::new("-") {
                    std::io::stdin().take(65537).read_to_string(&mut source)?;
                } else {
                    std::fs::File::open(config)?
                        .take(65537)
                        .read_to_string(&mut source)?;
                }
                ensure!(source.len() <= 65536, "configuration exceeds 64 KiB");
                let extension = config
                    .extension()
                    .and_then(|v| v.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let mut value: Value = if config == std::path::Path::new("-") || extension == "json"
                {
                    serde_json::from_str(&source).context("invalid JSON")?
                } else if extension == "yaml" || extension == "yml" {
                    serde_saphyr::from_str(&source).map_err(|_| anyhow::anyhow!("invalid YAML"))?
                } else {
                    anyhow::bail!("expected JSON or YAML")
                };
                let typed: crate::config::ClientConfig = serde_json::from_value(value.clone())
                    .context("invalid client configuration")?;
                typed.validate()?;
                let base = if config == std::path::Path::new("-") {
                    std::env::current_dir()?
                } else {
                    std::path::absolute(config)?
                        .parent()
                        .context("missing config directory")?
                        .to_owned()
                };
                for field in ["ca", "cert", "key"] {
                    if let Some(path) = value.get(field).and_then(Value::as_str) {
                        value[field] = json!(
                            base.join(path)
                                .to_str()
                                .context("invalid credential path")?
                        );
                    }
                }
                arguments.insert("name".into(), name.clone());
                arguments.insert("config".into(), serde_json::to_string(&value)?);
                "profiles.import"
            }
        },
    };
    let encoded = Zeroizing::new(serde_json::to_vec(
        &json!({"version":1,"command":command,"arguments":arguments}),
    )?);
    ensure!(encoded.len() < 65536, "control request exceeds 64 KiB");
    Ok(encoded)
}

/// Exchange one bounded message with a same-user macOS app and enforce read/write deadlines.
#[cfg(target_vendor = "apple")]
fn exchange(options: &AppArgs, request: &[u8]) -> anyhow::Result<Value> {
    use std::io::Write;
    use std::{
        os::unix::{io::AsRawFd, net::UnixStream},
        time::Duration,
    };
    // SAFETY: getuid has no preconditions and only returns this process's user identifier.
    let uid = unsafe { nix::libc::getuid() };
    let path = options
        .socket
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/zion-{uid}/control.sock")));
    let mut socket = UnixStream::connect(path)?;
    let mut peer_uid = 0;
    let mut peer_gid = 0;
    // SAFETY: the live socket descriptor and both output pointers remain valid during this call.
    ensure!(
        unsafe { nix::libc::getpeereid(socket.as_raw_fd(), &mut peer_uid, &mut peer_gid) } == 0
            && peer_uid == uid,
        "control peer belongs to another user"
    );
    socket.set_read_timeout(Some(Duration::from_secs(90)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.write_all(request)?;
    socket.write_all(b"\n")?;
    socket.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    socket.take(256 * 1024 + 1).read_to_end(&mut response)?;
    ensure!(response.len() <= 256 * 1024, "control response too large");
    let value: Value = serde_json::from_slice(&response)?;
    ensure!(
        value.get("version") == Some(&json!(1))
            && value.get("ok").and_then(Value::as_bool).is_some(),
        "invalid control response"
    );
    Ok(value)
}

/// Non-Apple builds retain the CLI schema but cannot control a native macOS application.
#[cfg(not(target_vendor = "apple"))]
fn exchange(_: &AppArgs, _: &[u8]) -> anyhow::Result<Value> {
    anyhow::bail!("native app control requires macOS")
}
