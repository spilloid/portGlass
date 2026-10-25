use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use portglass_controller::browser::{self, WindowPlacement};
use portglass_controller::client::ProbeLink;
use portglass_controller::config::{self, ControllerConfig};
use portglass_controller::diag::SchemePref;
use portglass_controller::session::{ConnectRequest, Controller, Options, Phase};
use portglass_core::audit::AuditLog;
use portglass_core::identity::{Fingerprint, Identity};

#[derive(Parser)]
#[command(
    name = "portglass",
    version,
    about = "PortGlass Controller - open an authorized remote web interface in a dedicated, isolated browser"
)]
struct Cli {
    /// Configuration file. Default: %APPDATA%\PortGlass\controller\controller.toml
    #[arg(long, global = true, env = "PORTGLASS_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create this controller's identity and configuration.
    Init {
        #[arg(long)]
        operator: Option<String>,
    },
    /// Open the PortGlass window (default).
    Ui {
        /// Print the window's URL instead of opening it.
        #[arg(long)]
        no_window: bool,
    },
    /// Print this controller's fingerprint, for probe administrators.
    Fingerprint,
    /// Manage pinned probes.
    Probe {
        #[command(subcommand)]
        action: ProbeCmd,
    },
    /// Open a session from the terminal. Ctrl+C ends it.
    Connect {
        #[arg(long)]
        probe: String,
        /// e.g. 192.168.1.50:80
        #[arg(long)]
        target: String,
        #[arg(long, value_enum, default_value = "auto")]
        scheme: SchemeArg,
        /// Don't open the session browser; print the local address instead.
        #[arg(long)]
        no_browser: bool,
        #[arg(long)]
        ttl_mins: Option<u32>,
    },
    /// Check configuration, browser, and every probe.
    Diag,
}

#[derive(Subcommand)]
enum ProbeCmd {
    Add {
        #[arg(long)]
        name: String,
        /// host:port, e.g. 10.0.5.20:47100
        #[arg(long)]
        address: String,
        #[arg(long)]
        fingerprint: String,
    },
    List,
    Remove {
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SchemeArg {
    Auto,
    Http,
    Https,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,portglass_controller=info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let path = cli.config.clone().unwrap_or_else(config::default_path);
    let rt = tokio::runtime::Runtime::new()?;
    match cli.command.unwrap_or(Cmd::Ui { no_window: false }) {
        Cmd::Init { operator } => init(&path, operator),
        Cmd::Fingerprint => {
            let cfg = ControllerConfig::load(&path)?;
            println!(
                "{}",
                Identity::load(&cfg.identity_dir, "controller")?.fingerprint
            );
            Ok(())
        }
        Cmd::Probe { action } => probe_cmd(&path, action),
        Cmd::Ui { no_window } => {
            // Double-clicked in Explorer: no console window behind the app, and errors in a
            // dialog box rather than a console that closes before anyone can read it.
            let standalone = !no_window && desktop::launched_from_explorer();
            if standalone {
                desktop::hide_console();
            }
            let result = (|| -> Result<()> {
                let operator = config::current_user();
                ControllerConfig::ensure_initialized(&path, &operator)?;
                rt.block_on(ui(&path, no_window, standalone))
            })();
            if let Err(e) = &result {
                if standalone {
                    desktop::error_box(&format!("PortGlass couldn't start.\n\n{e:#}"));
                }
            }
            result
        }
        Cmd::Connect {
            probe,
            target,
            scheme,
            no_browser,
            ttl_mins,
        } => rt.block_on(connect(&path, probe, target, scheme, no_browser, ttl_mins)),
        Cmd::Diag => rt.block_on(diag(&path)),
    }
}

fn init(path: &Path, operator: Option<String>) -> Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let dir = path.parent().context("config path has no parent")?;
    std::fs::create_dir_all(dir)?;
    let operator = operator.unwrap_or_else(config::current_user);
    std::fs::write(path, config::template(&operator))?;
    let cfg = ControllerConfig::load(path)?;
    let id = Identity::create(&cfg.identity_dir, "controller", &operator)?;
    println!("Created {}", path.display());
    println!();
    println!("Your controller fingerprint (send this to the probe's administrator):");
    println!("  {}", id.fingerprint);
    println!();
    println!("They authorize you with:");
    println!(
        "  portglass-probe authorize --name {operator} --fingerprint {}",
        id.fingerprint
    );
    println!();
    println!("Then pin their probe here:");
    println!("  portglass probe add --name <name> --address <host:47100> --fingerprint <probe fingerprint>");
    Ok(())
}

fn probe_cmd(path: &Path, action: ProbeCmd) -> Result<()> {
    let mut cfg = ControllerConfig::load(path)?;
    match action {
        ProbeCmd::Add {
            name,
            address,
            fingerprint,
        } => {
            let fingerprint: Fingerprint = fingerprint.parse()?;
            if cfg.probe(&name).is_some() {
                bail!("a probe named {name:?} already exists (remove it first)");
            }
            let address = if address.contains(':') {
                address
            } else {
                format!("{address}:{}", portglass_proto::DEFAULT_PROBE_PORT)
            };
            cfg.probes.push(config::ProbeEntry {
                name: name.clone(),
                address,
                fingerprint,
            });
            cfg.validate()?;
            cfg.save(path)?;
            println!("Pinned probe {name} ({fingerprint}).");
        }
        ProbeCmd::List => {
            if cfg.probes.is_empty() {
                println!("No probes. Add one with `portglass probe add`.");
            }
            for p in &cfg.probes {
                println!("{:<20} {:<24} {}", p.name, p.address, p.fingerprint);
            }
        }
        ProbeCmd::Remove { name } => {
            let before = cfg.probes.len();
            cfg.probes.retain(|p| !p.name.eq_ignore_ascii_case(&name));
            if cfg.probes.len() == before {
                bail!("no probe named {name:?}");
            }
            cfg.save(path)?;
            println!("Removed {name}.");
        }
    }
    Ok(())
}

fn load_controller(path: &Path, options: Options) -> Result<Arc<Controller>> {
    let cfg = ControllerConfig::load(path).with_context(|| {
        format!(
            "loading {} (create one with `portglass init`)",
            path.display()
        )
    })?;
    let identity = Identity::load(&cfg.identity_dir, "controller")?;
    let audit = Arc::new(AuditLog::open(&cfg.audit_log)?);
    Ok(Controller::new(cfg, identity, audit, options))
}

async fn ui(path: &Path, no_window: bool, standalone: bool) -> Result<()> {
    browser::sweep_stale_profiles();
    let ctrl = load_controller(path, Options::default())?;
    let server = portglass_controller::ui::serve(ctrl.clone()).await?;
    {
        let c = ctrl.clone();
        tokio::spawn(async move { c.check_probes().await });
    }
    println!("PortGlass Controller {}", env!("CARGO_PKG_VERSION"));
    let window = if no_window {
        None
    } else {
        match browser::find_chrome(&ctrl.config.browser) {
            Some(exe) => {
                let place = WindowPlacement {
                    x: 40,
                    y: 40,
                    width: 500,
                    height: 940,
                };
                match browser::launch_app_window(&exe, &server.url, &place).await {
                    Ok(w) => Some(w),
                    Err(e) => {
                        eprintln!("Couldn't open the PortGlass window: {e:#}");
                        None
                    }
                }
            }
            None => {
                eprintln!("Google Chrome was not found; open the URL below in any browser.");
                None
            }
        }
    };
    if window.is_none() && standalone {
        // Nobody can see a console URL after a double-click; say what is missing instead.
        desktop::error_box(
            "PortGlass needs Google Chrome for its window and for the session browser.\n\n\
             Install Chrome from google.com/chrome, then open PortGlass again.",
        );
        ctrl.disconnect().await;
        return Ok(());
    }
    if window.is_none() {
        println!("PortGlass is running at {}", server.url);
    } else {
        println!(
            "PortGlass window open. Close it (or press Ctrl+C) to end every session and exit."
        );
    }
    let closed = async {
        match &window {
            Some(w) => {
                let mut rx = w.exit_signal();
                let _ = rx.wait_for(|e| *e).await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = closed => {}
    }
    println!("Ending sessions...");
    ctrl.disconnect().await;
    if let Some(w) = window {
        w.close().await;
    }
    Ok(())
}

async fn connect(
    path: &Path,
    probe: String,
    target: String,
    scheme: SchemeArg,
    no_browser: bool,
    ttl_mins: Option<u32>,
) -> Result<()> {
    browser::sweep_stale_profiles();
    let options = Options {
        launch_browser: !no_browser,
        ..Options::default()
    };
    let ctrl = load_controller(path, options)?;
    let mut rx = ctrl.subscribe();
    ctrl.connect(ConnectRequest {
        probe,
        target,
        scheme: match scheme {
            SchemeArg::Auto => SchemePref::Auto,
            SchemeArg::Http => SchemePref::Http,
            SchemeArg::Https => SchemePref::Https,
        },
        ttl_mins,
    })
    .await
    .map_err(|f| anyhow::anyhow!("{}: {} - {}", f.title, f.detail, f.hint))?;

    let mut last = None;
    let mut printed_ready = false;
    loop {
        let s = rx.borrow_and_update().clone();
        if last != Some(s.phase) {
            println!("[{:?}] {} - {}", s.phase, s.headline, s.detail);
            last = Some(s.phase);
        }
        if s.phase == Phase::Ready && !printed_ready {
            printed_ready = true;
            if let Some(v) = &s.session {
                println!(
                    "  local tunnel: http://{}/",
                    v.local_addr.clone().unwrap_or_default()
                );
                if let Some(url) = &v.url {
                    println!("  browser URL:  {url}");
                }
                for d in &v.diagnostics {
                    println!("  check: {} - {}", d.title, d.text);
                }
            }
            println!("Press Ctrl+C to end the session.");
        }
        match s.phase {
            Phase::Failed => {
                if let Some(f) = s.failure {
                    eprintln!("What to do: {}", f.hint);
                }
                std::process::exit(2);
            }
            Phase::Disconnected if s.ended => return Ok(()),
            _ => {}
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                ctrl.disconnect().await;
                let s = ctrl.snapshot();
                println!("[{:?}] {}", s.phase, s.headline);
                return Ok(());
            }
            r = rx.changed() => if r.is_err() { return Ok(()); }
        }
    }
}

async fn diag(path: &Path) -> Result<()> {
    println!("PortGlass Controller {}", env!("CARGO_PKG_VERSION"));
    println!("Config:      {}", path.display());
    let cfg = match ControllerConfig::load(path) {
        Ok(c) => c,
        Err(e) => {
            println!("  FAILED - {e:#}\n  Run `portglass init` to create one.");
            return Ok(());
        }
    };
    let identity = match Identity::load(&cfg.identity_dir, "controller") {
        Ok(i) => {
            println!("Identity:    OK {}", i.fingerprint);
            i
        }
        Err(e) => {
            println!("Identity:    FAILED - {e:#}");
            return Ok(());
        }
    };
    match browser::find_chrome(&cfg.browser) {
        Some(p) => println!("Browser:     OK {}", p.display()),
        None => println!("Browser:     NOT FOUND - install Google Chrome or set [browser] path"),
    }
    println!(
        "Isolation:   {:?}, preserve address: {}",
        cfg.browser.isolation, cfg.browser.preserve_address
    );
    println!("Audit log:   {}", cfg.audit_log.display());
    if cfg.probes.is_empty() {
        println!("Probes:      none pinned");
    }
    for p in &cfg.probes {
        print!("Probe {:<14} {:<22} ", p.name, p.address);
        match tokio::time::timeout(
            Duration::from_secs(15),
            ProbeLink::connect(p, &identity, &cfg.operator),
        )
        .await
        {
            Ok(Ok(link)) => {
                let rtt = link.ping().await.map(|d| d.as_millis()).unwrap_or(0);
                println!(
                    "OK - authorized as {}, probe v{}, {} ms",
                    link.hello.authorized_as, link.hello.probe_version, rtt
                );
                for a in &link.hello.policy.allow {
                    println!(
                        "    allows {} ports {}{}",
                        a.network,
                        a.ports,
                        a.label
                            .as_deref()
                            .map(|l| format!(" ({l})"))
                            .unwrap_or_default()
                    );
                }
                link.shutdown();
            }
            Ok(Err(f)) => println!("FAILED - {}: {}\n    {}", f.title, f.detail, f.hint),
            Err(_) => println!("FAILED - timed out"),
        }
    }
    Ok(())
}

/// Behaviour when PortGlass is started from Explorer rather than a terminal.
mod desktop {
    /// True when this process is the only one attached to its console, i.e. Windows created
    /// the console for us because we were double-clicked.
    #[cfg(windows)]
    pub fn launched_from_explorer() -> bool {
        let mut pids = [0u32; 4];
        // SAFETY: writes at most pids.len() entries into a buffer we own.
        let n = unsafe {
            windows_sys::Win32::System::Console::GetConsoleProcessList(
                pids.as_mut_ptr(),
                pids.len() as u32,
            )
        };
        n == 1
    }

    #[cfg(windows)]
    pub fn hide_console() {
        // SAFETY: detaches from our own console; Windows closes the window it made for us.
        unsafe {
            windows_sys::Win32::System::Console::FreeConsole();
        }
    }

    #[cfg(windows)]
    pub fn error_box(text: &str) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        let wide = |s: &str| {
            s.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        };
        let (text, title) = (wide(text), wide("PortGlass"));
        // SAFETY: both strings are NUL-terminated UTF-16 buffers that outlive the call.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    #[cfg(not(windows))]
    pub fn launched_from_explorer() -> bool {
        false
    }
    #[cfg(not(windows))]
    pub fn hide_console() {}
    #[cfg(not(windows))]
    pub fn error_box(_: &str) {}
}
