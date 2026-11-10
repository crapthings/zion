//! The CLI selects direct proxying, authenticated tunnel roles, or credential issuance.

use clap::{Args as ClapArgs, Parser, Subcommand};
use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use zion::{
    server::{Config, Server},
    tunnel::{
        Client, TunnelServer,
        tls::{self, Identity},
    },
};

/// Root options preserve direct SOCKS5 mode while exposing explicit tunnel subcommands.
#[derive(Parser)]
#[command(version, about = "TCP/UDP proxy with authenticated QUIC tunnels")]
struct Args {
    #[command(subcommand)]
    mode: Option<Mode>,
    #[command(flatten)]
    local: LocalArgs,
}

/// Subcommands select credential issuance or one authenticated tunnel role.
#[derive(Subcommand)]
enum Mode {
    /// Issue a fresh CA and client/server identities into a new directory.
    Credentials(CredentialArgs),
    /// Run the remote authenticated QUIC server.
    Server(ServerArgs),
    /// Run a local SOCKS5 listener using a remote QUIC server.
    Client(ClientArgs),
}

/// Resource budgets apply consistently to direct and tunneled sessions.
#[derive(ClapArgs)]
struct Limits {
    /// Maximum active sessions, including unauthenticated QUIC handshakes.
    #[arg(long, default_value = "256")]
    max_connections: NonZeroUsize,
    /// SOCKS5 or QUIC handshake deadline in seconds.
    #[arg(long, default_value = "10")]
    handshake_timeout: NonZeroU64,
    /// Destination connection and DNS deadline in seconds.
    #[arg(long, default_value = "10")]
    connect_timeout: NonZeroU64,
    /// UDP association inactivity timeout in seconds.
    #[arg(long, default_value = "60")]
    udp_idle_timeout: NonZeroU64,
}

/// Local options configure the unauthenticated loopback SOCKS5 listener.
#[derive(ClapArgs)]
struct LocalArgs {
    /// Loopback address for the local SOCKS5 listener.
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: SocketAddr,
    #[command(flatten)]
    limits: Limits,
}

/// Client options select a remote address and its required TLS identity.
#[derive(ClapArgs)]
struct ClientArgs {
    /// Emit JSON process events after verifying remote authentication and local readiness.
    #[arg(long)]
    events_json: bool,
    /// Minimal JSON or YAML configuration file.
    #[arg(short, long, conflicts_with_all = ["remote", "server_name", "credentials", "interface", "listen", "max_connections", "handshake_timeout", "connect_timeout", "udp_idle_timeout"])]
    config: Option<PathBuf>,
    #[command(flatten)]
    local: LocalArgs,
    /// Network interface used for QUIC egress on macOS or Linux.
    #[arg(long)]
    interface: Option<String>,
    /// Remote QUIC server IP address and UDP port.
    #[arg(long, required_unless_present = "config")]
    remote: Option<SocketAddr>,
    /// DNS name or IP address that must match the server certificate.
    #[arg(long, required_unless_present = "config")]
    server_name: Option<String>,
    /// Directory containing ca.pem, client.pem, and client.key.
    #[arg(long, required_unless_present = "config")]
    credentials: Option<PathBuf>,
}

/// Server options select the remote QUIC listener and its trust material.
#[derive(ClapArgs)]
struct ServerArgs {
    /// Minimal JSON or YAML configuration file.
    #[arg(short, long, conflicts_with_all = ["listen", "credentials", "max_connections", "handshake_timeout", "connect_timeout", "udp_idle_timeout"])]
    config: Option<PathBuf>,
    /// QUIC UDP listener address.
    #[arg(long, default_value = "[::]:8443")]
    listen: SocketAddr,
    /// Directory containing ca.pem, server.pem, and server.key.
    #[arg(long, required_unless_present = "config")]
    credentials: Option<PathBuf>,
    #[command(flatten)]
    limits: Limits,
}

/// Credential options select the issued server name and a new output directory.
#[derive(ClapArgs)]
struct CredentialArgs {
    /// DNS name or IP address included in the server certificate.
    #[arg(long)]
    server_name: String,
    /// New directory to create without overwriting any existing credentials.
    #[arg(long, default_value = "credentials")]
    output: PathBuf,
}

/// Budget conversion creates the shared immutable session settings.
impl Limits {
    /// Build server settings with explicit capacity and operation deadlines.
    fn config(self, listen: SocketAddr) -> Config {
        Config {
            listen,
            max_connections: self.max_connections,
            handshake_timeout: Duration::from_secs(self.handshake_timeout.get()),
            connect_timeout: Duration::from_secs(self.connect_timeout.get()),
            udp_idle_timeout: Duration::from_secs(self.udp_idle_timeout.get()),
            ..Config::default()
        }
    }
}

/// Initialize diagnostics and supervise the selected mode until Ctrl-C.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("zion=info")),
        )
        .init();
    let args = Args::parse();
    let machine = matches!(&args.mode, Some(Mode::Client(options)) if options.events_json);
    let shutdown = CancellationToken::new();
    let running = run(args, shutdown.clone());
    tokio::pin!(running);
    let result = tokio::select! {
        result = &mut running => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            shutdown.cancel();
            running.await
        }
    };
    if machine {
        match &result {
            Ok(()) => zion::control::Event::Stopped.write()?,
            Err(error) => zion::control::Event::Error {
                message: format!("{error:#}"),
            }
            .write()?,
        }
    }
    result
}

/// Start one selected role without changing the host's network or trust configuration.
async fn run(args: Args, shutdown: CancellationToken) -> anyhow::Result<()> {
    match args.mode {
        Some(Mode::Credentials(options)) => {
            tls::generate(&options.output, &options.server_name)?;
            println!("Credentials created in {}", options.output.display());
            Ok(())
        }
        Some(Mode::Server(options)) => {
            if let Some(path) = options.config {
                return zion::config::ServerConfig::load(&path)?
                    .build()?
                    .run(shutdown)
                    .await;
            }
            let credentials = options
                .credentials
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--credentials is required"))?;
            let identity = Identity::load(credentials, "server")?;
            let config = options.limits.config(options.listen);
            TunnelServer::bind(options.listen, identity, config)?
                .run(shutdown)
                .await
        }
        Some(Mode::Client(options)) => {
            if let Some(path) = options.config {
                let config = zion::config::ClientConfig::load(&path)?.build().await?;
                return run_client(config, shutdown, options.events_json).await;
            }
            let credentials = options
                .credentials
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--credentials is required"))?;
            let identity = Identity::load(credentials, "client")?;
            let mut config = options.local.limits.config(options.local.listen);
            config.tunnel = Some(Client::new_with_interface(
                options
                    .remote
                    .ok_or_else(|| anyhow::anyhow!("--remote is required"))?,
                options
                    .server_name
                    .ok_or_else(|| anyhow::anyhow!("--server-name is required"))?,
                identity,
                options.interface.as_deref(),
            )?);
            run_client(config, shutdown, options.events_json).await
        }
        None => {
            Server::bind(args.local.limits.config(args.local.listen))
                .await?
                .run(shutdown)
                .await
        }
    }
}

/// Confirm remote authentication before announcing a bound local listener to the GUI.
async fn run_client(
    config: Config,
    shutdown: CancellationToken,
    machine: bool,
) -> anyhow::Result<()> {
    let server = Server::bind(config.clone()).await?;
    if machine {
        let tunnel = config
            .tunnel
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("client tunnel is missing"))?;
        let session = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            session = tunnel.udp(config.connect_timeout) => session?,
        };
        drop(session);
        zion::control::Event::Ready {
            listen: server.local_addr()?,
        }
        .write()?;
    }
    server.run(shutdown).await
}
