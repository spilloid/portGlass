use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use portglass_core::audit::AuditLog;
use portglass_core::identity::{Fingerprint, Identity};
use portglass_probe::config::{template, ProbeConfig};
use portglass_probe::policy;
use portglass_proto::TargetSpec;

#[derive(Parser)]
#[command(
    name = "portglass-probe",
    version,
    about = "PortGlass Probe - forwards authorized TCP sessions to approved LAN destinations, nothing else"
)]
struct Cli {
    /// Configuration file. Default: %LOCALAPPDATA%\PortGlass\probe\probe.toml
    #[arg(long, global = true, env = "PORTGLASS_PROBE_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a configuration template and this probe's identity.
    Init {
        /// Name shown to technicians.
        #[arg(long)]
        name: Option<String>,
    },
    /// Run the probe in this console (default). Ctrl+C stops it and ends every session.
    Run,
    /// Print this probe's fingerprint, for technicians to pin.
    Fingerprint,
    /// Authorize a technician's controller.
    Authorize {
        #[arg(long)]
        name: String,
        #[arg(long)]
        fingerprint: String,
    },
    /// Allow a destination, e.g. --network 192.168.1.50 --ports 80,443
    Allow {
        #[arg(long)]
        network: String,
        #[arg(long, value_delimiter = ',')]
        ports: Vec<String>,
        #[arg(long)]
        label: Option<String>,
    },
    /// Validate the configuration and print the effective policy.
    CheckConfig,
    /// Check a destination against the policy and test-connect to it from this machine.
    Diag {
        /// host:port, e.g. 192.168.1.50:80
        #[arg(long)]
        target: String,
    },
}

fn default_config() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("PortGlass").join("probe").join("probe.toml")
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
    let rt = tokio::runtime::Runtime::new()?;
    match cli.command.unwrap_or(Cmd::Run) {
        Cmd::Init { name } => init(&config_path, name),
        Cmd::Run => rt.block_on(run(&config_path)),
        Cmd::Fingerprint => {
            let cfg = ProbeConfig::load(&config_path)?;
            let id = Identity::load(&cfg.identity_dir, "probe")?;
            println!("{}", id.fingerprint);
            Ok(())
        }
        Cmd::Authorize { name, fingerprint } => authorize(&config_path, &name, &fingerprint),
        Cmd::Allow {
            network,
            ports,
            label,
        } => allow(&config_path, &network, &ports, label),
        Cmd::CheckConfig => {
            let cfg = ProbeConfig::load(&config_path)?;
            print_policy(&cfg);
            Ok(())
        }
        Cmd::Diag { target } => rt.block_on(diag(&config_path, &target)),
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
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "portglass-probe".into())
    });
    std::fs::write(path, template(&name))?;
    let cfg = ProbeConfig::load(path)?;
    let id = Identity::create(&cfg.identity_dir, "probe", &name)?;
    println!("Created {}", path.display());
    println!("Probe identity: {}", cfg.identity_dir.display());
    println!();
    println!("Probe fingerprint (give this to technicians):");
    println!("  {}", id.fingerprint);
    println!();
    println!("Next:");
    println!("  portglass-probe authorize --name <technician> --fingerprint <their fingerprint>");
    println!("  portglass-probe allow --network 192.168.1.50 --ports 80,443 --label \"Printer\"");
    println!("  portglass-probe run");
    Ok(())
}

fn append_block(path: &Path, block: &str) -> Result<()> {
    let mut text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading {} (run `portglass-probe init` first)",
            path.display()
        )
    })?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push('\n');
    text.push_str(block);
    // Validate before writing, so a bad argument never leaves a broken file behind.
    let parsed: portglass_probe::config::ProbeConfigFile = toml::from_str(&text)?;
    ProbeConfig::from_file(parsed, path.parent().unwrap_or(Path::new(".")))?;
    std::fs::write(path, text)?;
    Ok(())
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn authorize(path: &Path, name: &str, fingerprint: &str) -> Result<()> {
    let fp: Fingerprint = fingerprint.parse()?;
    append_block(
        path,
        &format!(
            "[[controller]]\nname = {}\nfingerprint = \"{fp}\"\n",
            toml_str(name)
        ),
    )?;
    println!("Authorized {name} ({fp}). A running probe picks this up within a few seconds.");
    Ok(())
}

fn allow(path: &Path, network: &str, ports: &[String], label: Option<String>) -> Result<()> {
    if ports.is_empty() {
        bail!("--ports is required, e.g. --ports 80,443");
    }
    let ports_toml: Vec<String> = ports
        .iter()
        .map(|p| match p.trim().parse::<u16>() {
            Ok(n) => n.to_string(),
            Err(_) => toml_str(p.trim()),
        })
        .collect();
    let mut block = format!(
        "[[allow]]\nnetwork = {}\nports = [{}]\n",
        toml_str(network),
        ports_toml.join(", ")
    );
    if let Some(l) = label {
        block.push_str(&format!("label = {}\n", toml_str(&l)));
    }
    append_block(path, &block)?;
    println!("Allowed {network} ports {}.", ports.join(","));
    Ok(())
}

fn print_policy(cfg: &ProbeConfig) {
    println!("Probe:        {}", cfg.name);
    println!("Listen:       {}", cfg.listen);
    println!("Audit log:    {}", cfg.audit_log.display());
    println!(
        "Limits:       sessions {}, streams/session {}, max TTL {}s, idle {}s",
        cfg.limits.max_sessions,
        cfg.limits.max_streams_per_session,
        cfg.limits.max_session_ttl_secs,
        cfg.limits.stream_idle_timeout_secs
    );
    println!("Controllers ({}):", cfg.controllers.len());
    for c in &cfg.controllers {
        println!("  {:<20} {}", c.name, c.fingerprint);
    }
    println!("Allowed destinations ({}):", cfg.allow.len());
    for r in &cfg.allow {
        println!(
            "  {:<20} ports {}{}",
            r.network.to_string(),
            r.ports.describe(),
            r.label
                .as_deref()
                .map(|l| format!("  ({l})"))
                .unwrap_or_default()
        );
    }
    if cfg.allow.is_empty() {
        println!("  (none - every session request will be rejected)");
    }
}

fn parse_target(s: &str) -> Result<TargetSpec> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").context("expected [ipv6]:port")?;
        (h.to_string(), p)
    } else {
        let (h, p) = s.rsplit_once(':').context("expected host:port")?;
        (h.to_string(), p)
    };
    Ok(TargetSpec {
        host,
        port: port.parse().context("invalid port")?,
    })
}

async fn diag(path: &Path, target: &str) -> Result<()> {
    let cfg = ProbeConfig::load(path)?;
    let target = parse_target(target)?;
    print!("Policy:  ");
    let (addr, label) = match policy::authorize(&cfg.allow, &target, Duration::from_secs(5)).await {
        Ok(x) => x,
        Err(d) => {
            println!("DENIED ({}) - {}", d.code.as_str(), d.message);
            return Ok(());
        }
    };
    println!(
        "allowed -> {addr}{}",
        label.map(|l| format!(" ({l})")).unwrap_or_default()
    );
    print!("Connect: ");
    let started = std::time::Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(cfg.limits.connect_timeout_secs as u64),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => println!("OK in {} ms", started.elapsed().as_millis()),
        Ok(Err(e)) => println!("FAILED - {e}"),
        Err(_) => println!("TIMED OUT after {}s", cfg.limits.connect_timeout_secs),
    }
    Ok(())
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

async fn run(path: &Path) -> Result<()> {
    let cfg = ProbeConfig::load(path).with_context(|| {
        format!(
            "loading {} (create one with `portglass-probe init`)",
            path.display()
        )
    })?;
    let identity = Identity::load(&cfg.identity_dir, "probe")?;
    let audit = Arc::new(AuditLog::open(&cfg.audit_log)?);

    println!("PortGlass Probe {}", env!("CARGO_PKG_VERSION"));
    println!("This program forwards TCP connections from authorized PortGlass controllers to the");
    println!("destinations listed in its configuration. It does not run commands, transfer files,");
    println!(
        "scan the network, or start automatically. Press Ctrl+C to stop and end all sessions."
    );
    println!();
    print_policy(&cfg);
    println!("Fingerprint:  {}", identity.fingerprint);
    println!(
        "Config file:  {} (changes apply automatically)",
        path.display()
    );
    println!();

    let handle = portglass_probe::start(cfg, identity, audit).await?;
    println!("Listening on {}", handle.addr);

    let mut last_mtime = modified(path);
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tick.tick() => {
                let now = modified(path);
                if now == last_mtime {
                    continue;
                }
                last_mtime = now;
                handle.reload_from(path);

            }
        }
    }
    println!("Stopping: ending all sessions...");
    handle.shutdown().await;
    Ok(())
}
