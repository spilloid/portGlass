//! The controller's session state machine.
//!
//! ```text
//! DISCONNECTED → AUTHENTICATING → CONNECTING → VERIFYING → READY → CLOSING → DISCONNECTED
//!                       └──────────────┴────────────┴─────────┴──→ FAILED ──→ (connect again)
//! ```
//!
//! One task owns a session from AUTHENTICATING to teardown, so cleanup happens in exactly one
//! place no matter how the session ends: the technician closes it, the browser window closes,
//! the probe ends it (expiry, revocation, shutdown), or the network drops.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portglass_core::audit::AuditLog;
use portglass_core::bridge::{bridge, Counters};
use portglass_core::identity::Identity;
use portglass_proto::{ControlEvent, ErrorCode, PolicySummary, TargetSpec};
use serde::Serialize;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::browser::{self, BrowserHandle, BrowserInfo, WindowPlacement};
use crate::client::{ProbeLink, SessionGrant};
use crate::config::{ControllerConfig, ProbeEntry};
use crate::diag::{self, Diagnostic, Level, Scheme, SchemePref};
use crate::failure::{Failure, FailureKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Phase {
    Disconnected,
    Authenticating,
    Connecting,
    Verifying,
    Ready,
    Closing,
    Failed,
}

/// The only transitions the controller makes. Anything else is a bug.
pub fn allowed(from: Phase, to: Phase) -> bool {
    use Phase::*;
    matches!(
        (from, to),
        (Disconnected | Failed, Authenticating)
            | (Failed, Disconnected)
            | (Authenticating, Connecting)
            | (Connecting, Verifying)
            | (Verifying, Ready)
            | (Authenticating | Connecting | Verifying | Ready, Closing)
            | (
                Authenticating | Connecting | Verifying | Ready | Closing,
                Failed
            )
            | (Closing, Disconnected)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Indicator {
    Red,
    Amber,
    Green,
    Gray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Unknown,
    Checking,
    Online,
    Unreachable,
    AuthFailed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeView {
    pub name: String,
    pub address: String,
    pub fingerprint: String,
    pub status: ProbeStatus,
    pub message: Option<String>,
    pub authorized_as: Option<String>,
    pub probe_version: Option<String>,
    pub policy: Option<PolicySummary>,
    pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub id: String,
    pub probe: String,
    pub target: String,
    pub resolved: Option<String>,
    pub local_addr: Option<String>,
    pub url: Option<String>,
    pub scheme: Option<Scheme>,
    pub started_at: String,
    pub elapsed_secs: u64,
    pub expires_in_secs: Option<u64>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub rate_up: u64,
    pub rate_down: u64,
    pub history_up: Vec<u64>,
    pub history_down: Vec<u64>,
    pub active_conns: u32,
    pub total_conns: u64,
    pub failed_conns: u64,
    pub last_stream_error: Option<String>,
    pub rtt_ms: Option<u32>,
    pub target_reachable: Option<bool>,
    pub target_rtt_ms: Option<u32>,
    pub target_message: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub browser: Option<BrowserInfo>,
    pub browser_running: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEntry {
    pub at: String,
    pub phase: Phase,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub phase: Phase,
    pub indicator: Indicator,
    pub headline: String,
    pub detail: String,
    pub failure: Option<Failure>,
    /// The phase a failure interrupted, so the UI can mark the right step.
    pub failed_at: Option<Phase>,
    pub ended: bool,
    pub probes: Vec<ProbeView>,
    pub session: Option<SessionView>,
    pub timeline: Vec<TimelineEntry>,
    pub operator: String,
    pub fingerprint: String,
    pub version: String,
    pub browser_available: bool,
    pub default_ttl_mins: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ConnectRequest {
    pub probe: String,
    pub target: String,
    #[serde(default)]
    pub scheme: SchemePref,
    #[serde(default)]
    pub ttl_mins: Option<u32>,
}

pub struct Options {
    pub launch_browser: bool,
    pub browser_window: WindowPlacement,
    /// Extra Chrome arguments, for automated tests only (headless, DevTools). The CLI never sets it.
    pub browser_extra_args: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            launch_browser: true,
            browser_window: WindowPlacement {
                x: 560,
                y: 40,
                width: 1280,
                height: 900,
            },
            browser_extra_args: Vec::new(),
        }
    }
}

enum Cmd {
    OpenBrowser,
}

struct Active {
    cancel: CancellationToken,
    cmds: mpsc::Sender<Cmd>,
    task: tokio::task::JoinHandle<()>,
}

pub struct Controller {
    pub config: ControllerConfig,
    identity: Identity,
    audit: Arc<AuditLog>,
    state: watch::Sender<Snapshot>,
    active: tokio::sync::Mutex<Option<Active>>,
    options: Options,
}

#[derive(Default)]
struct Stats {
    counters: Arc<Counters>,
    active: AtomicU32,
    total: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<String>>,
}

enum End {
    Closed(&'static str),
    Failed(Failure),
}

impl Controller {
    pub fn new(
        config: ControllerConfig,
        identity: Identity,
        audit: Arc<AuditLog>,
        options: Options,
    ) -> Arc<Self> {
        let probes = config
            .probes
            .iter()
            .map(|p| ProbeView {
                name: p.name.clone(),
                address: p.address.clone(),
                fingerprint: p.fingerprint.to_string(),
                status: ProbeStatus::Unknown,
                message: None,
                authorized_as: None,
                probe_version: None,
                policy: None,
                rtt_ms: None,
            })
            .collect();
        let mut snap = Snapshot {
            phase: Phase::Disconnected,
            indicator: Indicator::Red,
            headline: String::new(),
            detail: String::new(),
            failure: None,
            failed_at: None,
            ended: false,
            probes,
            session: None,
            timeline: Vec::new(),
            operator: config.operator.clone(),
            fingerprint: identity.fingerprint.to_string(),
            version: env!("CARGO_PKG_VERSION").into(),
            browser_available: browser::find_chrome(&config.browser).is_some(),
            default_ttl_mins: config.default_ttl_mins,
        };
        derive_status(&mut snap);
        let (state, _) = watch::channel(snap);
        Arc::new(Controller {
            config,
            identity,
            audit,
            state,
            active: tokio::sync::Mutex::new(None),
            options,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<Snapshot> {
        self.state.subscribe()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.state.borrow().clone()
    }

    fn update(&self, f: impl FnOnce(&mut Snapshot)) {
        self.state.send_modify(|s| {
            f(s);
            derive_status(s);
        });
    }

    fn transition(&self, to: Phase, text: impl Into<String>) {
        let text = text.into();
        self.update(|s| {
            debug_assert!(
                allowed(s.phase, to),
                "illegal transition {:?} -> {:?}",
                s.phase,
                to
            );
            if !allowed(s.phase, to) {
                tracing::error!("illegal transition {:?} -> {:?}", s.phase, to);
            }
            if to == Phase::Failed {
                s.failed_at = Some(s.phase);
            } else if to == Phase::Authenticating {
                s.failed_at = None;
            }
            s.phase = to;
            s.timeline.push(TimelineEntry {
                at: portglass_core::now_rfc3339(),
                phase: to,
                text,
            });
            let excess = s.timeline.len().saturating_sub(40);
            s.timeline.drain(..excess);
        });
    }

    /// Start a session. Returns an error if one is already active or the request is invalid.
    pub async fn connect(self: &Arc<Self>, req: ConnectRequest) -> Result<(), Failure> {
        let mut active = self.active.lock().await;
        if let Some(a) = active.as_ref() {
            if !a.task.is_finished() {
                return Err(Failure::new(
                    FailureKind::Busy,
                    "A session is already open",
                    "End the current session first.",
                    "PortGlass opens one target at a time.",
                ));
            }
        }
        let entry = self
            .config
            .probe(&req.probe)
            .cloned()
            .ok_or_else(|| {
                Failure::new(
                    FailureKind::InvalidTarget,
                    "Unknown probe",
                    format!("No probe named {:?} is configured.", req.probe),
                    "Add it with: portglass probe add --name <name> --address <host:port> --fingerprint <sha256:...>",
                )
            })?;
        let (target, scheme) = parse_target_input(&req.target, req.scheme)?;
        let ttl_secs = req
            .ttl_mins
            .unwrap_or(self.config.default_ttl_mins)
            .clamp(1, 24 * 60)
            * 60;

        let cancel = CancellationToken::new();
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let me = self.clone();
        let c2 = cancel.clone();
        let started = Instant::now();
        self.update(|s| {
            s.failure = None;
            s.ended = false;
            s.session = Some(SessionView {
                id: String::new(),
                probe: entry.name.clone(),
                target: target.to_string(),
                resolved: None,
                local_addr: None,
                url: None,
                scheme: None,
                started_at: portglass_core::now_rfc3339(),
                elapsed_secs: 0,
                expires_in_secs: None,
                bytes_up: 0,
                bytes_down: 0,
                rate_up: 0,
                rate_down: 0,
                history_up: Vec::new(),
                history_down: Vec::new(),
                active_conns: 0,
                total_conns: 0,
                failed_conns: 0,
                last_stream_error: None,
                rtt_ms: None,
                target_reachable: None,
                target_rtt_ms: None,
                target_message: None,
                diagnostics: Vec::new(),
                browser: None,
                browser_running: false,
            });
        });
        let task = tokio::spawn(async move {
            me.run(entry, target, scheme, ttl_secs, c2, cmd_rx, started)
                .await;
        });
        *active = Some(Active {
            cancel,
            cmds: cmd_tx,
            task,
        });
        Ok(())
    }

    /// End the active session (or abort one that is still connecting) and wait for teardown.
    pub async fn disconnect(&self) {
        let active = self.active.lock().await.take();
        if let Some(a) = active {
            a.cancel.cancel();
            let _ = a.task.await;
        }
    }

    /// Clear a failure and return to DISCONNECTED.
    pub fn dismiss(&self) {
        if self.state.borrow().phase == Phase::Failed {
            self.transition(Phase::Disconnected, "Dismissed");
        }
    }

    pub async fn open_browser(&self) {
        if let Some(a) = self.active.lock().await.as_ref() {
            let _ = a.cmds.send(Cmd::OpenBrowser).await;
        }
    }

    /// Wait for the current session task (if any) to finish. Used by the CLI.
    pub async fn wait(&self) {
        let task = self
            .active
            .lock()
            .await
            .as_mut()
            .map(|a| std::mem::replace(&mut a.task, tokio::spawn(async {})));
        if let Some(t) = task {
            let _ = t.await;
        }
    }

    /// Authenticate to every configured probe and report what it allows.
    pub async fn check_probes(self: &Arc<Self>) {
        let mut tasks = Vec::new();
        for entry in self.config.probes.clone() {
            let me = self.clone();
            tasks.push(tokio::spawn(async move { me.check_probe(entry).await }));
        }
        for t in tasks {
            let _ = t.await;
        }
    }

    async fn check_probe(&self, entry: ProbeEntry) {
        self.set_probe(&entry.name, |p| {
            p.status = ProbeStatus::Checking;
            p.message = None;
        });
        match ProbeLink::connect(&entry, &self.identity, &self.config.operator).await {
            Ok(link) => {
                let rtt = link.ping().await.ok().map(|d| d.as_millis() as u32);
                let hello = link.hello.clone();
                link.shutdown();
                self.set_probe(&entry.name, |p| {
                    p.status = ProbeStatus::Online;
                    p.authorized_as = Some(hello.authorized_as);
                    p.probe_version = Some(hello.probe_version);
                    p.policy = Some(hello.policy);
                    p.rtt_ms = rtt;
                    p.message = None;
                });
            }
            Err(f) => self.set_probe(&entry.name, |p| {
                p.status = if f.kind == FailureKind::AuthFailed {
                    ProbeStatus::AuthFailed
                } else {
                    ProbeStatus::Unreachable
                };
                p.message = Some(format!("{} — {}", f.title, f.hint));
            }),
        }
    }

    fn set_probe(&self, name: &str, f: impl FnOnce(&mut ProbeView)) {
        self.update(|s| {
            if let Some(p) = s.probes.iter_mut().find(|p| p.name == name) {
                f(p);
            }
        });
    }

    fn set_session(&self, f: impl FnOnce(&mut SessionView)) {
        self.update(|s| {
            if let Some(v) = s.session.as_mut() {
                f(v);
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        self: Arc<Self>,
        entry: ProbeEntry,
        target: TargetSpec,
        pref: SchemePref,
        ttl_secs: u32,
        cancel: CancellationToken,
        mut cmds: mpsc::Receiver<Cmd>,
        started: Instant,
    ) {
        self.audit.record(
            "session_requested",
            &[
                ("operator", json!(self.config.operator)),
                ("probe", json!(entry.name)),
                ("probe_address", json!(entry.address)),
                ("probe_fingerprint", json!(entry.fingerprint.to_string())),
                ("target", json!(target.to_string())),
                ("ttl_secs", json!(ttl_secs)),
            ],
        );

        // AUTHENTICATING ------------------------------------------------------------------
        self.transition(
            Phase::Authenticating,
            format!("Authenticating with probe {}", entry.name),
        );
        let link = tokio::select! {
            r = ProbeLink::connect(&entry, &self.identity, &self.config.operator) => r,
            _ = cancel.cancelled() => return self.finish_cancelled(None).await,
        };
        let link = match link {
            Ok(l) => l,
            Err(f) => return self.fail(f, None).await,
        };
        self.set_probe(&entry.name, |p| {
            p.status = ProbeStatus::Online;
            p.authorized_as = Some(link.hello.authorized_as.clone());
            p.probe_version = Some(link.hello.probe_version.clone());
            p.policy = Some(link.hello.policy.clone());
            p.message = None;
        });

        // CONNECTING ----------------------------------------------------------------------
        self.transition(
            Phase::Connecting,
            format!(
                "Probe authenticated as {}; requesting {target}",
                link.hello.authorized_as
            ),
        );
        let grant = tokio::select! {
            r = link.open_session(&target, ttl_secs) => r,
            _ = cancel.cancelled() => return self.finish_cancelled(Some(&link)).await,
        };
        let grant = match grant {
            Ok(g) => g,
            Err(f) => return self.fail(f, Some(&link)).await,
        };
        let granted_at = Instant::now();
        self.set_session(|v| {
            v.id = grant.session_id.clone();
            v.resolved = Some(grant.resolved_addr.clone());
            v.expires_in_secs = Some(grant.expires_in_secs as u64);
        });

        // VERIFYING -----------------------------------------------------------------------
        self.transition(
            Phase::Verifying,
            format!(
                "Probe reached {} in {} ms; testing the tunnel",
                grant.resolved_addr, grant.connect_ms
            ),
        );
        let verified = tokio::select! {
            r = self.verify(&link, &grant, &target, pref) => r,
            _ = cancel.cancelled() => return self.finish_cancelled_session(&link, &grant).await,
        };
        let (listener, report) = match verified {
            Ok(v) => v,
            Err(f) => {
                link.close_session(&grant.session_id).await;
                return self.fail(f, Some(&link)).await;
            }
        };
        let local = listener
            .local_addr()
            .expect("bound listener has an address");
        let stats = Arc::new(Stats::default());
        let tunnel = cancel.child_token();
        tokio::spawn(accept_loop(
            listener,
            link.clone(),
            grant.clone(),
            stats.clone(),
            tunnel.clone(),
            Duration::from_secs(self.config.idle_timeout_secs as u64),
        ));

        let (url, rules) = browser::plan_navigation(
            &self.config.browser,
            report.scheme,
            &target.host,
            target.port,
            local.port(),
        );
        let mut diagnostics = report.items.clone();
        if !self.config.browser.preserve_address {
            if let Some(loc) = &report.self_redirect {
                diagnostics.push(Diagnostic {
                    level: Level::Warn,
                    title: "The device redirects to its own address".into(),
                    text: format!(
                        "It sends the browser to {loc}. With preserve_address off, the session \
                         browser would leave the tunnel and try that address on your own network. \
                         Turn preserve_address on in controller.toml."
                    ),
                    suggestion: None,
                });
            }
        }
        if rules.is_some() && self.options.launch_browser {
            diagnostics.push(Diagnostic {
                level: Level::Info,
                title: "Chrome shows a notice about --host-resolver-rules".into(),
                text: format!(
                    "That's PortGlass pointing {} at the encrypted tunnel, in this one window \
                     only. Nothing changes in your own Chrome, and PortGlass never hides the notice.",
                    target
                ),
                suggestion: None,
            });
        }
        let mut browser_handle = None;
        if self.options.launch_browser {
            match self.launch_browser(&grant.session_id, &url, rules.as_deref()).await {
                Ok(b) => browser_handle = Some(b),
                Err(e) => diagnostics.push(Diagnostic {
                    level: Level::Warn,
                    title: "The session browser didn't start".into(),
                    text: format!("{e}. The tunnel is open at http://{local}/ — but only the PortGlass browser maps the device's own address."),
                    suggestion: None,
                }),
            }
        }
        self.set_session(|v| {
            v.local_addr = Some(local.to_string());
            v.url = Some(url.clone());
            v.scheme = Some(report.scheme);
            v.diagnostics = diagnostics;
            v.browser = browser_handle.as_ref().map(|b| b.info.clone());
            v.browser_running = browser_handle.is_some();
        });

        // READY ---------------------------------------------------------------------------
        self.audit.record(
            "session_ready",
            &[
                ("operator", json!(self.config.operator)),
                ("probe", json!(entry.name)),
                ("session", json!(grant.session_id)),
                ("target", json!(target.to_string())),
                ("resolved", json!(grant.resolved_addr)),
                ("local", json!(local.to_string())),
                (
                    "browser_profile",
                    json!(browser_handle.as_ref().map(|b| b.info.profile_dir.clone())),
                ),
            ],
        );
        self.transition(
            Phase::Ready,
            format!("Tunnel ready on {local}; opening {url}"),
        );

        let end = self
            .monitor(
                &link,
                &grant,
                &stats,
                &cancel,
                &mut cmds,
                &mut browser_handle,
                granted_at,
                &url,
                rules.as_deref(),
            )
            .await;

        // CLOSING -------------------------------------------------------------------------
        let closing_text = match &end {
            End::Closed(why) => format!("Closing: {why}"),
            End::Failed(f) => format!("Closing: {}", f.title),
        };
        self.transition(Phase::Closing, closing_text);
        tunnel.cancel();
        link.close_session(&grant.session_id).await;
        if let Some(b) = browser_handle.take() {
            b.close().await;
        }
        link.shutdown();
        let (up, down) = stats.counters.snapshot();
        let (reason, failure) = match end {
            End::Closed(why) => (why.to_string(), None),
            End::Failed(f) => (f.title.clone(), Some(f)),
        };
        self.audit.record(
            "session_ended",
            &[
                ("operator", json!(self.config.operator)),
                ("probe", json!(entry.name)),
                ("session", json!(grant.session_id)),
                ("target", json!(target.to_string())),
                ("reason", json!(reason)),
                ("duration_secs", json!(started.elapsed().as_secs())),
                ("connections", json!(stats.total.load(Ordering::Relaxed))),
                (
                    "connections_failed",
                    json!(stats.failed.load(Ordering::Relaxed)),
                ),
                ("bytes_to_target", json!(up)),
                ("bytes_from_target", json!(down)),
            ],
        );
        match failure {
            None => {
                self.update(|s| s.ended = true);
                self.transition(
                    Phase::Disconnected,
                    "Session ended; tunnel closed and browser data deleted",
                );
            }
            Some(f) => {
                let title = f.title.clone();
                self.update(|s| s.failure = Some(f));
                self.transition(Phase::Failed, title);
            }
        }
    }

    async fn launch_browser(
        &self,
        session_id: &str,
        url: &str,
        rules: Option<&str>,
    ) -> anyhow::Result<BrowserHandle> {
        let exe = browser::find_chrome(&self.config.browser).ok_or_else(|| {
            anyhow::anyhow!("Google Chrome was not found (set [browser] path in controller.toml)")
        })?;
        BrowserHandle::launch(
            &exe,
            session_id,
            url,
            rules,
            &self.options.browser_window,
            &self.options.browser_extra_args,
        )
        .await
    }

    /// Prove the data path works end to end, then look at what the device serves.
    async fn verify(
        &self,
        link: &Arc<ProbeLink>,
        grant: &SessionGrant,
        target: &TargetSpec,
        pref: SchemePref,
    ) -> Result<(TcpListener, diag::Report), Failure> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| Failure::internal(format!("opening a local port: {e}")))?;
        match link
            .open_stream(&grant.session_id, &grant.stream_token)
            .await
        {
            Ok(s) => drop(s),
            Err((code, msg)) => {
                return Err(match code {
                    Some(code) => Failure::from_probe(code, &msg, &target.to_string()),
                    None => Failure::new(
                        FailureKind::NetworkInterrupted,
                        "The tunnel couldn't be opened",
                        msg,
                        "The probe accepted the session but the data connection failed. Check \
                         that nothing between you and the probe limits new connections.",
                    ),
                })
            }
        }
        let open = || {
            let link = link.clone();
            let sid = grant.session_id.clone();
            let tok = grant.stream_token.clone();
            async move { link.open_stream(&sid, &tok).await.map_err(|(_, m)| m) }
        };
        let report = diag::inspect(open, &target.host, target.port, pref).await;
        Ok((listener, report))
    }

    #[allow(clippy::too_many_arguments)]
    async fn monitor(
        &self,
        link: &Arc<ProbeLink>,
        grant: &SessionGrant,
        stats: &Arc<Stats>,
        cancel: &CancellationToken,
        cmds: &mut mpsc::Receiver<Cmd>,
        browser_handle: &mut Option<BrowserHandle>,
        granted_at: Instant,
        url: &str,
        rules: Option<&str>,
    ) -> End {
        let mut events = link.subscribe();
        let closed = link.closed();
        let (ping_tx, mut ping_rx) = mpsc::channel::<Option<u32>>(4);
        {
            let link = link.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_secs(3));
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = iv.tick() => {}
                    }
                    let r = link.ping().await.ok().map(|d| d.as_millis() as u32);
                    if ping_tx.send(r).await.is_err() {
                        return;
                    }
                }
            });
        }
        let mut check = tokio::time::interval(Duration::from_secs(10));
        let mut sample = tokio::time::interval(Duration::from_secs(1));
        let mut missed = 0u32;
        let mut last = stats.counters.snapshot();
        let mut exit_signal = browser_handle.as_ref().map(|b| b.exit_signal());
        let total = Duration::from_secs(grant.expires_in_secs as u64);

        loop {
            let browser_exit = async {
                match exit_signal.as_mut() {
                    Some(rx) => {
                        let _ = rx.wait_for(|e| *e).await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                _ = cancel.cancelled() => return End::Closed("closed by technician"),
                _ = closed.cancelled() => {
                    return End::Failed(Failure::new(
                        FailureKind::NetworkInterrupted,
                        "The connection to the probe was lost",
                        link.close_reason().unwrap_or_default(),
                        "Check the network between you and the probe, then connect again.",
                    ));
                }
                ev = events.recv() => match ev {
                    Ok(ControlEvent::SessionEnded { session_id, reason }) if session_id == grant.session_id => {
                        return match Failure::from_end(reason) {
                            Some(f) => End::Failed(f),
                            None => End::Closed("closed by technician"),
                        };
                    }
                    Ok(ControlEvent::TargetStatus { session_id, reachable, rtt_ms, message, .. }) if session_id == grant.session_id => {
                        self.set_session(|v| {
                            v.target_reachable = Some(reachable);
                            v.target_rtt_ms = rtt_ms;
                            v.target_message = message;
                        });
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return End::Failed(Failure::new(
                        FailureKind::NetworkInterrupted,
                        "The connection to the probe was lost",
                        "The control channel closed.",
                        "Connect again.",
                    )),
                },
                r = ping_rx.recv() => match r.flatten() {
                    Some(rtt) => {
                        missed = 0;
                        self.set_session(|v| v.rtt_ms = Some(rtt));
                    }
                    None => {
                        missed += 1;
                        if missed >= 2 {
                            return End::Failed(Failure::new(
                                FailureKind::NetworkInterrupted,
                                "The probe stopped responding",
                                "Two heartbeats in a row went unanswered.",
                                "Check the network between you and the probe, then connect again.",
                            ));
                        }
                    }
                },
                _ = check.tick() => {
                    let _ = link.check_target(&grant.session_id).await;
                }
                _ = sample.tick() => {
                    let now = stats.counters.snapshot();
                    let (du, dd) = (now.0 - last.0, now.1 - last.1);
                    last = now;
                    let remaining = total.saturating_sub(granted_at.elapsed());
                    let error = stats.last_error.lock().unwrap().clone();
                    let running = browser_handle.as_ref().map(|b| b.is_running()).unwrap_or(false);
                    self.set_session(|v| {
                        v.bytes_up = now.0;
                        v.bytes_down = now.1;
                        v.rate_up = du;
                        v.rate_down = dd;
                        push_capped(&mut v.history_up, du);
                        push_capped(&mut v.history_down, dd);
                        v.active_conns = stats.active.load(Ordering::Relaxed);
                        v.total_conns = stats.total.load(Ordering::Relaxed);
                        v.failed_conns = stats.failed.load(Ordering::Relaxed);
                        v.last_stream_error = error;
                        v.elapsed_secs = granted_at.elapsed().as_secs();
                        v.expires_in_secs = Some(remaining.as_secs());
                        v.browser_running = running;
                    });
                }
                _ = browser_exit => {
                    exit_signal = None;
                    self.set_session(|v| v.browser_running = false);
                    if self.config.browser.end_session_on_close {
                        return End::Closed("session browser closed");
                    }
                }
                cmd = cmds.recv() => match cmd {
                    Some(Cmd::OpenBrowser) => {
                        let running = browser_handle.as_ref().map(|b| b.is_running()).unwrap_or(false);
                        if !running {
                            if let Some(old) = browser_handle.take() {
                                old.close().await;
                            }
                            match self.launch_browser(&grant.session_id, url, rules).await {
                                Ok(b) => {
                                    exit_signal = Some(b.exit_signal());
                                    let info = b.info.clone();
                                    *browser_handle = Some(b);
                                    self.set_session(|v| {
                                        v.browser = Some(info);
                                        v.browser_running = true;
                                    });
                                }
                                Err(e) => tracing::warn!("reopening the browser failed: {e:#}"),
                            }
                        }
                    }
                    None => {}
                },
            }
        }
    }

    async fn fail(&self, failure: Failure, link: Option<&Arc<ProbeLink>>) {
        if let Some(l) = link {
            l.shutdown();
        }
        self.audit.record(
            "session_failed",
            &[
                ("operator", json!(self.config.operator)),
                ("kind", json!(failure.kind)),
                ("title", json!(failure.title)),
                ("detail", json!(failure.detail)),
            ],
        );
        let title = failure.title.clone();
        self.update(|s| s.failure = Some(failure));
        self.transition(Phase::Failed, title);
    }

    async fn finish_cancelled(&self, link: Option<&Arc<ProbeLink>>) {
        self.transition(Phase::Closing, "Cancelled");
        if let Some(l) = link {
            l.shutdown();
        }
        self.update(|s| s.ended = true);
        self.transition(
            Phase::Disconnected,
            "Cancelled before the session was ready",
        );
    }

    async fn finish_cancelled_session(&self, link: &Arc<ProbeLink>, grant: &SessionGrant) {
        link.close_session(&grant.session_id).await;
        self.finish_cancelled(Some(link)).await;
    }
}

fn push_capped(v: &mut Vec<u64>, x: u64) {
    v.push(x);
    let excess = v.len().saturating_sub(60);
    v.drain(..excess);
}

async fn accept_loop(
    listener: TcpListener,
    link: Arc<ProbeLink>,
    grant: SessionGrant,
    stats: Arc<Stats>,
    cancel: CancellationToken,
    idle: Duration,
) {
    loop {
        let (local, _) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(_) => continue,
            },
        };
        let _ = local.set_nodelay(true);
        let link = link.clone();
        let grant = grant.clone();
        let stats = stats.clone();
        let cancel = cancel.child_token();
        tokio::spawn(async move { forward_one(local, link, grant, stats, cancel, idle).await });
    }
}

async fn forward_one(
    local: TcpStream,
    link: Arc<ProbeLink>,
    grant: SessionGrant,
    stats: Arc<Stats>,
    cancel: CancellationToken,
    idle: Duration,
) {
    stats.active.fetch_add(1, Ordering::Relaxed);
    let remote = tokio::select! {
        r = link.open_stream(&grant.session_id, &grant.stream_token) => r,
        _ = cancel.cancelled() => Err((None, "session closed".into())),
    };
    match remote {
        Ok(remote) => {
            stats.total.fetch_add(1, Ordering::Relaxed);
            bridge(local, remote, idle, cancel, stats.counters.clone()).await;
        }
        Err((code, msg)) => {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            let text = match code {
                Some(ErrorCode::TooManyStreams) => format!("Connection limit reached: {msg}"),
                Some(c) => format!("{}: {msg}", c.as_str()),
                None => msg,
            };
            *stats.last_error.lock().unwrap() = Some(text);
        }
    }
    stats.active.fetch_sub(1, Ordering::Relaxed);
}

/// Parse what the technician typed: `192.168.1.50:80`, `192.168.1.50`, `printer.lan:8080`,
/// `http://192.168.1.50:8080/`, `https://printer.lan`, `[fe80::1]:80`.
pub fn parse_target_input(
    input: &str,
    pref: SchemePref,
) -> Result<(TargetSpec, SchemePref), Failure> {
    let bad = |why: &str| {
        Failure::new(
            FailureKind::InvalidTarget,
            "That target isn't valid",
            why.to_string(),
            "Enter an IP address or host name and a port, like 192.168.1.50:80.",
        )
    };
    let mut s = input.trim();
    let mut pref = pref;
    if let Some((scheme, rest)) = s.split_once("://") {
        pref = match scheme.to_ascii_lowercase().as_str() {
            "http" => SchemePref::Http,
            "https" => SchemePref::Https,
            _ => return Err(bad("Only http:// and https:// addresses can be opened.")),
        };
        s = rest;
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or_default();
    if s.is_empty() {
        return Err(bad("Enter a target."));
    }
    if s.contains('@') {
        return Err(bad("Don't include a user name in the target."));
    }
    let default_port = if pref == SchemePref::Https { 443 } else { 80 };
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| bad("Missing ']' after the IPv6 address."))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| bad("The port must be a number from 1 to 65535."))?,
            None if after.is_empty() => default_port,
            None => return Err(bad("Unexpected text after the IPv6 address.")),
        };
        (h.to_string(), port)
    } else if s.matches(':').count() > 1 {
        (s.to_string(), default_port)
    } else if let Some((h, p)) = s.rsplit_once(':') {
        (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| bad("The port must be a number from 1 to 65535."))?,
        )
    } else {
        (s.to_string(), default_port)
    };
    if port == 0 {
        return Err(bad("The port must be a number from 1 to 65535."));
    }
    if host.is_empty() || host.chars().any(|c| c.is_whitespace()) {
        return Err(bad("Enter an IP address or host name."));
    }
    Ok((TargetSpec { host, port }, pref))
}

/// The indicator and headline come from state, never from separate flags that could disagree.
fn derive_status(s: &mut Snapshot) {
    let target = s
        .session
        .as_ref()
        .map(|v| v.target.clone())
        .unwrap_or_default();
    let probe = s
        .session
        .as_ref()
        .map(|v| v.probe.clone())
        .unwrap_or_default();
    let (ind, head, detail) = match s.phase {
        Phase::Disconnected if s.ended => (
            Indicator::Gray,
            "Session ended".to_string(),
            "The tunnel is closed and the session browser's data was deleted.".to_string(),
        ),
        Phase::Disconnected => (
            Indicator::Red,
            "Not connected".into(),
            "Choose a probe, enter the device's address, and connect.".into(),
        ),
        Phase::Authenticating => (
            Indicator::Amber,
            "Authenticating".into(),
            format!("Checking probe {probe}'s identity and presenting yours."),
        ),
        Phase::Connecting => (
            Indicator::Amber,
            "Connecting".into(),
            format!("Probe {probe} is checking that {target} is allowed and answering."),
        ),
        Phase::Verifying => (
            Indicator::Amber,
            "Verifying".into(),
            "Testing the encrypted tunnel end to end.".into(),
        ),
        Phase::Ready => {
            let reachable = s.session.as_ref().and_then(|v| v.target_reachable);
            if reachable == Some(false) {
                (
                    Indicator::Red,
                    "Device not responding".into(),
                    format!("The tunnel is up, but {target} stopped answering probe {probe}."),
                )
            } else {
                (
                    Indicator::Green,
                    "Connected".into(),
                    format!("{target} through probe {probe}. Nothing else on that network is reachable."),
                )
            }
        }
        Phase::Closing => (
            Indicator::Gray,
            "Closing".into(),
            "Ending the session and deleting the browser's data.".into(),
        ),
        Phase::Failed => {
            let f = s.failure.as_ref();
            (
                Indicator::Red,
                f.map(|f| f.title.clone())
                    .unwrap_or_else(|| "Disconnected".into()),
                f.map(|f| f.detail.clone()).unwrap_or_default(),
            )
        }
    };
    s.indicator = ind;
    s.headline = head;
    s.detail = detail;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_allows_only_the_documented_path() {
        use Phase::*;
        let happy = [
            Disconnected,
            Authenticating,
            Connecting,
            Verifying,
            Ready,
            Closing,
            Disconnected,
        ];
        for w in happy.windows(2) {
            assert!(allowed(w[0], w[1]), "{:?} -> {:?}", w[0], w[1]);
        }
        for from in [Authenticating, Connecting, Verifying, Ready, Closing] {
            assert!(allowed(from, Failed));
        }
        assert!(allowed(Failed, Authenticating));
        assert!(!allowed(Disconnected, Ready));
        assert!(!allowed(Authenticating, Ready));
        assert!(!allowed(Ready, Authenticating));
        assert!(!allowed(Disconnected, Failed));
    }

    #[test]
    fn target_input_forms() {
        let p =
            |s: &str| parse_target_input(s, SchemePref::Auto).map(|(t, pr)| (t.host, t.port, pr));
        assert_eq!(
            p("192.168.1.50:80").unwrap(),
            ("192.168.1.50".into(), 80, SchemePref::Auto)
        );
        assert_eq!(p("192.168.1.50").unwrap().1, 80);
        assert_eq!(
            p("https://printer.lan").unwrap(),
            ("printer.lan".into(), 443, SchemePref::Https)
        );
        assert_eq!(p("http://10.0.0.5:8080/admin").unwrap().1, 8080);
        assert_eq!(
            p("[fe80::1]:8443").unwrap(),
            ("fe80::1".into(), 8443, SchemePref::Auto)
        );
        assert!(p("").is_err());
        assert!(p("1.2.3.4:0").is_err());
        assert!(p("1.2.3.4:99999").is_err());
        assert!(p("ftp://x").is_err());
        assert!(p("http://user@1.2.3.4/").is_err());
    }
}
