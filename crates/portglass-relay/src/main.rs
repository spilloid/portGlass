use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use portglass_core::audit::AuditLog;
use portglass_core::identity::{Fingerprint, Identity};
use portglass_relay::config::{template, RelayConfig, RelayConfigFile};

#[derive(Parser)]
#[command(
    name = "portglass-relay",
    version,
    about = "PortGlass Relay - lets a probe and a controller that cannot reach each other meet; carries end-to-end encrypted bytes only"
)]
struct Cli {
    /// Configuration file. Default: %LOCALAPPDATA%\PortGlass\relay\relay.toml on Windows,
    /// ~/.config/portglass/relay/relay.toml elsewhere.
    #[arg(long, global = true, env = "PORTGLASS_RELAY_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a configuration template and this relay's identity.
    Init {
        #[arg(long)]
        name: Option<String>,
    },
    /// Run the relay in this console (default). Ctrl+C stops it.
    Run,
    /// Print this relay's fingerprint, for probes and technicians to pin.
    Fingerprint,
    /// Let a probe register with this relay.
    Authorize {
        #[arg(long)]
        name: String,
        #[arg(long)]
        fingerprint: String,
    },
    /// Check for a newer signed release and install it (takes effect at the next start).
    Update {
        /// Only report whether one is available.
        #[arg(long)]
        check: bool,
    },
    /// Validate the configuration and print it.
    CheckConfig,
}

fn default_config() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local)
            .join("PortGlass")
            .join("relay")
            .join("relay.toml");
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("portglass").join("relay").join("relay.toml")
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rustls=warn".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let config_path = cli.config.clone().unwrap_or_else(default_config);
    match cli.command.unwrap_or(Cmd::Run) {
        Cmd::Init { name } => init(&config_path, name),
        Cmd::Run => {
            if !config_path.exists() {
                init(&config_path, None)?;
                println!();
            }
            tokio::runtime::Runtime::new()?.block_on(run(&config_path))
        }
        Cmd::Fingerprint => {
            let cfg = RelayConfig::load(&config_path)?;
            let id = Identity::load(&cfg.identity_dir, "relay")?;
            println!("{}", id.fingerprint);
            Ok(())
        }
        Cmd::Authorize { name, fingerprint } => authorize(&config_path, &name, &fingerprint),
        Cmd::Update { check } => {
            portglass_core::update::run_cli("portglass-relay", env!("CARGO_PKG_VERSION"), check)
        }
        Cmd::CheckConfig => {
            let cfg = RelayConfig::load(&config_path)?;
            print_config(&cfg);
            Ok(())
        }
    }
}

fn init(path: &Path, name: Option<String>) -> Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let dir = path
        .parent()
        .context("config path has no parent directory")?;
    std::fs::create_dir_all(dir)?;
    let name = name.unwrap_or_else(|| {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "portglass-relay".into())
    });
    std::fs::write(path, template(&name))?;
    let cfg = RelayConfig::load(path)?;
    let id = Identity::create(&cfg.identity_dir, "relay", &name)?;
    println!("Created {}", path.display());
    println!("Relay identity: {}", cfg.identity_dir.display());
    println!();
    println!("Relay fingerprint (probes and technicians pin this):");
    println!("  {}", id.fingerprint);
    println!();
    println!("Next:");
    println!("  portglass-relay authorize --name <probe> --fingerprint <the probe's fingerprint>");
    println!("  portglass-relay run");
    Ok(())
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn authorize(path: &Path, name: &str, fingerprint: &str) -> Result<()> {
    let fp: Fingerprint = fingerprint.parse()?;
    let mut text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading {} (run `portglass-relay init` first)",
            path.display()
        )
    })?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!(
        "\n[[probe]]\nname = {}\nfingerprint = \"{fp}\"\n",
        toml_str(name)
    ));
    // Validate before writing, so a bad argument never leaves a broken file behind.
    let parsed: RelayConfigFile = toml::from_str(&text)?;
    RelayConfig::from_file(parsed, path.parent().unwrap_or(Path::new(".")))?;
    std::fs::write(path, text)?;
    println!("Authorized probe {name} ({fp}). A running relay picks this up within a few seconds.");
    Ok(())
}

fn print_config(cfg: &RelayConfig) {
    println!("Relay:        {}", cfg.name);
    println!("Listen:       {}", cfg.listen);
    println!("Probes:       {}", cfg.probes.len());
    for p in &cfg.probes {
        println!("  - {} {}", p.name, p.fingerprint.short());
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

async fn run(path: &Path) -> Result<()> {
    let cfg = RelayConfig::load(path).with_context(|| {
        format!(
            "loading {} (create one with `portglass-relay init`)",
            path.display()
        )
    })?;
    let identity = Identity::load(&cfg.identity_dir, "relay")?;
    let audit = Arc::new(AuditLog::open(&cfg.audit_log)?);

    println!("PortGlass Relay {}", env!("CARGO_PKG_VERSION"));
    println!("This program lets listed PortGlass probes and the technicians they authorize meet.");
    println!("It copies their end-to-end encrypted connection and cannot read or alter it.");
    println!("Press Ctrl+C to stop.");
    println!();
    print_config(&cfg);
    // In the background, so an offline server starts just as fast.
    tokio::task::spawn_blocking(|| {
        if let Some(notice) =
            portglass_core::update::startup_notice("portglass-relay", env!("CARGO_PKG_VERSION"))
        {
            tracing::info!("{notice}");
        }
    });
    println!("Fingerprint:  {}", identity.fingerprint);
    println!(
        "Config file:  {} (changes apply automatically)",
        path.display()
    );
    println!();
    if cfg.probes.is_empty() {
        println!("No probes are authorized yet. On this machine, run:");
        println!(
            "  portglass-relay authorize --name <probe> --fingerprint <the probe's fingerprint>"
        );
        println!();
    }

    let handle = portglass_relay::start(cfg, identity, audit).await?;
    println!("Listening on {}", handle.addr);

    let mut last_mtime = modified(path);
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let stop = shutdown_signal();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = tick.tick() => {
                let now = modified(path);
                if now != last_mtime {
                    last_mtime = now;
                    handle.reload_from(path);
                }
            }
        }
    }
    println!("Stopping...");
    handle.shutdown().await;
    Ok(())
}

/// Ctrl+C, or SIGTERM from a service manager such as systemd.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            },
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
