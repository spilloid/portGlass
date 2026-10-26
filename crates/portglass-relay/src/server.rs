//! The relay's network service.
//!
//! Three connection kinds, all TLS 1.3 to the relay (selected by ALPN, see
//! [`portglass_proto::relay`]):
//!
//! * **Register** — a probe listed in `relay.toml` keeps one open, publishing the controller
//!   fingerprints its own allowlist accepts.
//! * **Connect** — a controller names a probe by fingerprint. If that probe is registered and
//!   lists this controller, the relay hands the probe a one-time ticket and waits.
//! * **Accept** — the probe answers the ticket on a new connection; the relay splices it to the
//!   waiting controller and copies bytes until either side closes.
//!
//! The relay never terminates the PortGlass connection that runs inside a splice: controller and
//! probe authenticate each other end to end, pinned at both ends, so the relay sees ciphertext
//! and connection metadata only. Its own checks are an admission filter in front of that, not a
//! substitute for it.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use portglass_core::audit::AuditLog;
use portglass_core::bridge::{bridge, Counters};
use portglass_core::identity::{Fingerprint, Identity};
use portglass_core::tls::{self, ControllerAllowlist};
use portglass_proto::relay::{
    Accept, Connect, ConnectReply, ProbeEvent, ProbeRequest, ALPN_ACCEPT, ALPN_CONNECT,
    ALPN_REGISTER, MAX_PUBLISHED_CONTROLLERS, RELAY_PROTOCOL_VERSION,
};
use portglass_proto::{read_frame, write_frame};
use serde_json::json;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::RelayConfig;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections that have not finished the TLS handshake. Anyone may attempt one.
const MAX_PENDING_HANDSHAKES: usize = 128;
const MAX_PENDING_PER_IP: u32 = 16;
/// Controller connections past the handshake that have not been paired yet. Any certificate can
/// get this far, so the pool is also capped per source address.
const MAX_UNPAIRED: usize = 512;
const MAX_UNPAIRED_PER_IP: u32 = 32;
/// Probe answers (accept connections) waiting to be matched. Listed probes only, and a separate
/// pool, so strangers holding controller connections cannot starve probes' answers.
const MAX_ANSWERS: usize = 512;
/// Listed-probe registrations that have not sent `Register` yet.
const MAX_REGISTERING: usize = 64;
/// Of those, per probe. A probe needs one registration at a time; a few allow for reconnects.
const MAX_REGISTERING_PER_PROBE: u32 = 4;
/// Audit records of refused registrations, per minute.
const MAX_REJECT_AUDITS_PER_MIN: u32 = 20;

type Stream = TlsStream<TcpStream>;

struct Registration {
    name: String,
    conn: u64,
    controllers: RwLock<HashSet<Fingerprint>>,
    events: mpsc::Sender<ProbeEvent>,
    cancel: CancellationToken,
    pairs: AtomicU32,
    waiting: AtomicU32,
}

struct Ticket {
    probe: Fingerprint,
    deliver: oneshot::Sender<Stream>,
}

struct Shared {
    config: RwLock<Arc<RelayConfig>>,
    probes: Mutex<HashMap<Fingerprint, Arc<Registration>>>,
    tickets: Mutex<HashMap<String, Ticket>>,
    next_conn: AtomicU64,
    audit: Arc<AuditLog>,
    shutdown: CancellationToken,
    pending_by_ip: Mutex<HashMap<IpAddr, u32>>,
    unpaired_by_ip: Mutex<HashMap<IpAddr, u32>>,
    unpaired: Arc<Semaphore>,
    answers: Arc<Semaphore>,
    registering: Arc<Semaphore>,
    reject_window: Mutex<(Instant, u32)>,
    /// Per-probe shares of `registering` and `answers`, so one listed probe cannot starve the rest.
    pending_by_probe: Mutex<HashMap<(Fingerprint, bool), u32>>,
}

impl Shared {
    fn config(&self) -> Arc<RelayConfig> {
        self.config
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Every certificate may complete the handshake; what it may do is decided per connection kind
/// (registration and accept: listed probes only; connect: controllers a registered probe lists).
#[derive(Debug)]
struct AnyCertificate;

impl ControllerAllowlist for AnyCertificate {
    fn is_allowed(&self, _: &Fingerprint) -> bool {
        true
    }
}

#[derive(Clone, Copy)]
enum SlotKind {
    Handshake,
    Unpaired,
}

/// Holds one per-source-address slot of `kind` until dropped.
struct IpSlot {
    shared: Arc<Shared>,
    ip: IpAddr,
    kind: SlotKind,
}

impl IpSlot {
    fn map(shared: &Shared, kind: SlotKind) -> &Mutex<HashMap<IpAddr, u32>> {
        match kind {
            SlotKind::Handshake => &shared.pending_by_ip,
            SlotKind::Unpaired => &shared.unpaired_by_ip,
        }
    }

    fn take(shared: &Arc<Shared>, ip: IpAddr, kind: SlotKind) -> Option<IpSlot> {
        let max = match kind {
            SlotKind::Handshake => MAX_PENDING_PER_IP,
            SlotKind::Unpaired => MAX_UNPAIRED_PER_IP,
        };
        let mut map = IpSlot::map(shared, kind).lock().unwrap();
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(IpSlot {
            shared: shared.clone(),
            ip,
            kind,
        })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut map = IpSlot::map(&self.shared, self.kind).lock().unwrap();
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Holds one per-probe slot of the registration (`answer == false`) or answer pool.
struct ProbeSlot {
    shared: Arc<Shared>,
    key: (Fingerprint, bool),
}

impl ProbeSlot {
    fn take(shared: &Arc<Shared>, fp: Fingerprint, answer: bool, max: u32) -> Option<ProbeSlot> {
        let mut map = shared.pending_by_probe.lock().unwrap();
        let n = map.entry((fp, answer)).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(ProbeSlot {
            shared: shared.clone(),
            key: (fp, answer),
        })
    }
}

impl Drop for ProbeSlot {
    fn drop(&mut self) {
        let mut map = self.shared.pending_by_probe.lock().unwrap();
        if let Some(n) = map.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

/// A running relay.
pub struct RelayHandle {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl RelayHandle {
    /// Apply a new configuration. Probes it no longer lists lose their registration and every
    /// connection spliced through it.
    pub fn apply_config(&self, config: RelayConfig) {
        apply_config(&self.shared, config);
    }

    /// Re-read the configuration file. An invalid file fails closed: every probe is dropped
    /// until it is fixed. Returns whether it loaded.
    pub fn reload_from(&self, path: &std::path::Path) -> bool {
        match RelayConfig::load(path) {
            Ok(new) => {
                if new.listen != self.shared.config().listen {
                    tracing::warn!("`listen` changed; restart the relay to apply it");
                }
                tracing::info!("configuration reloaded");
                self.apply_config(new);
                true
            }
            Err(e) => {
                tracing::error!(
                    "configuration is invalid, dropping every probe until it is fixed: {e:#}"
                );
                let mut locked = (*self.shared.config()).clone();
                locked.probes.clear();
                self.apply_config(locked);
                self.shared.audit.record(
                    "config_invalid",
                    &[(
                        "error",
                        json!(format!("{e:#}").chars().take(500).collect::<String>()),
                    )],
                );
                false
            }
        }
    }

    /// Names of the probes registered right now.
    pub fn registered(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .shared
            .probes
            .lock()
            .unwrap()
            .values()
            .map(|r| r.name.clone())
            .collect();
        v.sort();
        v
    }

    pub async fn shutdown(self) {
        self.shared.shutdown.cancel();
        for r in self.shared.probes.lock().unwrap().values() {
            r.cancel.cancel();
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), self.task).await;
        self.shared.audit.record("relay_stopped", &[]);
    }
}

pub async fn start(
    config: RelayConfig,
    identity: Identity,
    audit: Arc<AuditLog>,
) -> Result<RelayHandle> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("listening on {}", config.listen))?;
    let addr = listener.local_addr()?;
    let server_config = tls::server_config(
        &identity,
        Arc::new(AnyCertificate),
        &[ALPN_REGISTER, ALPN_ACCEPT, ALPN_CONNECT],
    )?;
    audit.record(
        "relay_started",
        &[
            ("relay", json!(config.name)),
            ("listen", json!(addr.to_string())),
            ("fingerprint", json!(identity.fingerprint.to_string())),
            ("probes", json!(config.probes.len())),
        ],
    );
    let shared = Arc::new(Shared {
        config: RwLock::new(Arc::new(config)),
        probes: Mutex::new(HashMap::new()),
        tickets: Mutex::new(HashMap::new()),
        next_conn: AtomicU64::new(1),
        audit,
        shutdown: CancellationToken::new(),
        pending_by_ip: Mutex::new(HashMap::new()),
        unpaired_by_ip: Mutex::new(HashMap::new()),
        unpaired: Arc::new(Semaphore::new(MAX_UNPAIRED)),
        answers: Arc::new(Semaphore::new(MAX_ANSWERS)),
        registering: Arc::new(Semaphore::new(MAX_REGISTERING)),
        reject_window: Mutex::new((Instant::now(), 0)),
        pending_by_probe: Mutex::new(HashMap::new()),
    });
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let task = tokio::spawn(accept_loop(listener, acceptor, shared.clone()));
    Ok(RelayHandle { addr, shared, task })
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let accepted = tokio::select! {
            _ = shared.shutdown.cancelled() => return,
            a = listener.accept() => a,
        };
        let (tcp, peer) = match accepted {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some(slot) = IpSlot::take(&shared, peer.ip(), SlotKind::Handshake) else {
            tracing::debug!("dropping {peer}: too many pending handshakes from that address");
            continue;
        };
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            tracing::warn!("dropping {peer}: too many pending handshakes");
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                _ => return,
            };
            drop(permit);
            drop(slot);
            let (_, conn) = tls.get_ref();
            let alpn = conn.alpn_protocol().map(|a| a.to_vec());
            let Some(fp) = tls::peer_fingerprint(conn) else {
                return;
            };
            let listed = shared.config().probe_name(&fp).is_some();
            match alpn.as_deref() {
                Some(a) if a == ALPN_REGISTER => {
                    if !listed {
                        reject_probe(&shared, tls, fp, peer).await;
                        return;
                    }
                    let Some(share) =
                        ProbeSlot::take(&shared, fp, false, MAX_REGISTERING_PER_PROBE)
                    else {
                        return;
                    };
                    let Ok(registering) = shared.registering.clone().try_acquire_owned() else {
                        return;
                    };
                    run_register(shared, tls, fp, peer, (registering, share)).await
                }
                Some(a) if a == ALPN_CONNECT => {
                    let Some(ip_slot) = IpSlot::take(&shared, peer.ip(), SlotKind::Unpaired) else {
                        return;
                    };
                    let Ok(unpaired) = shared.unpaired.clone().try_acquire_owned() else {
                        return;
                    };
                    run_connect(shared, tls, fp, peer, (unpaired, ip_slot)).await
                }
                // Answers come only from listed probes, from a pool strangers cannot reach.
                Some(a) if a == ALPN_ACCEPT && listed => {
                    let max = shared.config().limits.max_waiting_per_probe;
                    let Some(share) = ProbeSlot::take(&shared, fp, true, max) else {
                        return;
                    };
                    let Ok(answer) = shared.answers.clone().try_acquire_owned() else {
                        return;
                    };
                    run_accept(shared, tls, fp, (answer, share)).await
                }
                _ => {}
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Registration (probe)
// ---------------------------------------------------------------------------------------------

fn parse_controllers(list: &[String]) -> Option<HashSet<Fingerprint>> {
    if list.len() > MAX_PUBLISHED_CONTROLLERS {
        return None;
    }
    list.iter().map(|s| s.parse().ok()).collect()
}

async fn send_refused<S: AsyncWrite + Unpin>(stream: &mut S, message: &str) {
    let ev = ProbeEvent::Refused {
        message: message.into(),
    };
    let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
        let _ = write_frame(stream, &ev).await;
        let _ = stream.shutdown().await;
    })
    .await;
}

/// Refuse a registration from a certificate `relay.toml` does not list. Anyone can trigger this,
/// so its audit record is rate-limited.
async fn reject_probe(shared: &Shared, mut stream: Stream, fp: Fingerprint, peer: SocketAddr) {
    let audit = {
        let mut w = shared
            .reject_window
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if w.0.elapsed() > Duration::from_secs(60) {
            *w = (Instant::now(), 0);
        }
        w.1 += 1;
        w.1 <= MAX_REJECT_AUDITS_PER_MIN
    };
    if audit {
        shared.audit.record(
            "probe_rejected",
            &[
                ("fingerprint", json!(fp.to_string())),
                ("peer", json!(peer.to_string())),
            ],
        );
    }
    send_refused(
        &mut stream,
        &format!(
            "this relay does not list probe {fp}; ask its administrator to run: \
             portglass-relay authorize --name <probe> --fingerprint {fp}"
        ),
    )
    .await;
}

async fn run_register(
    shared: Arc<Shared>,
    mut stream: Stream,
    fp: Fingerprint,
    peer: SocketAddr,
    registering: impl Send,
) {
    let Some(name) = shared.config().probe_name(&fp).map(str::to_owned) else {
        reject_probe(&shared, stream, fp, peer).await;
        return;
    };
    let first = tokio::time::timeout(
        FIRST_FRAME_TIMEOUT,
        read_frame::<_, ProbeRequest>(&mut stream),
    )
    .await;
    let controllers = match first {
        Ok(Ok(ProbeRequest::Register {
            protocol,
            controllers,
        })) if protocol == RELAY_PROTOCOL_VERSION => match parse_controllers(&controllers) {
            Some(c) => c,
            None => {
                send_refused(&mut stream, "the controller list is malformed or too long").await;
                return;
            }
        },
        Ok(Ok(ProbeRequest::Register { .. })) => {
            send_refused(&mut stream, "unsupported relay protocol version").await;
            return;
        }
        _ => return,
    };

    let (tx, mut rx) = mpsc::channel::<ProbeEvent>(64);
    let conn = shared.next_conn.fetch_add(1, Ordering::Relaxed);
    let reg = Arc::new(Registration {
        name: name.clone(),
        conn,
        controllers: RwLock::new(controllers),
        events: tx.clone(),
        cancel: CancellationToken::new(),
        pairs: AtomicU32::new(0),
        waiting: AtomicU32::new(0),
    });
    // Queued before the registration is visible, so it is always the first event.
    let _ = tx
        .send(ProbeEvent::Registered {
            relay_name: shared.config().name.clone(),
        })
        .await;
    drop(tx);
    // Publish only if the probe is still listed, checked under the same lock `apply_config`
    // sweeps under (after it has replaced the configuration). Either this sees the new
    // configuration and refuses, or the sweep runs after the insert and removes it, so a
    // configuration change while `Register` was in flight cannot leave a revoked probe
    // registered.
    let published = {
        let mut probes = shared.probes.lock().unwrap();
        if shared.config().probe_name(&fp).is_some() {
            // A probe that reconnects replaces its previous registration (and the splices made
            // through it, which belonged to the connection that is now gone).
            if let Some(old) = probes.insert(fp, reg.clone()) {
                old.cancel.cancel();
            }
            true
        } else {
            false
        }
    };
    if !published {
        send_refused(&mut stream, "this relay no longer lists this probe").await;
        return;
    }
    drop(registering);
    let (rd, mut wr) = tokio::io::split(stream);
    shared.audit.record(
        "probe_registered",
        &[
            ("probe", json!(name)),
            ("peer", json!(peer.to_string())),
            ("controllers", json!(reg.controllers.read().unwrap().len())),
        ],
    );
    tracing::info!("probe {name} registered from {peer}");

    let cancel = reg.cancel.clone();
    let writer = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            loop {
                let ev = tokio::select! {
                    _ = cancel.cancelled() => break,
                    ev = rx.recv() => match ev { Some(ev) => ev, None => break },
                };
                match tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut wr, &ev)).await {
                    Ok(Ok(())) => {}
                    _ => break,
                }
            }
            let _ = tokio::time::timeout(Duration::from_secs(1), wr.shutdown()).await;
            cancel.cancel();
        }
    });

    let silence = Duration::from_secs(shared.config().limits.registration_timeout_secs as u64);
    let reader = {
        let reg = reg.clone();
        async move {
            let mut rd = rd;
            loop {
                match tokio::time::timeout(silence, read_frame::<_, ProbeRequest>(&mut rd)).await {
                    Ok(Ok(ProbeRequest::Ping { nonce })) => {
                        if reg.events.try_send(ProbeEvent::Pong { nonce }).is_err() {
                            return "the probe stopped reading";
                        }
                    }
                    Ok(Ok(ProbeRequest::Register { controllers, .. })) => {
                        match parse_controllers(&controllers) {
                            Some(c) => *reg.controllers.write().unwrap() = c,
                            None => return "the probe sent a malformed controller list",
                        }
                    }
                    Ok(Err(_)) => return "the probe closed the registration",
                    Err(_) => return "the probe went silent",
                }
            }
        }
    };
    let why = tokio::select! {
        why = reader => why,
        _ = cancel.cancelled() => "registration ended",
        _ = shared.shutdown.cancelled() => "relay stopping",
    };
    cancel.cancel();
    let _ = writer.await;
    {
        let mut probes = shared.probes.lock().unwrap();
        if probes.get(&fp).is_some_and(|r| r.conn == conn) {
            probes.remove(&fp);
        }
    }
    shared.audit.record(
        "probe_unregistered",
        &[("probe", json!(name)), ("reason", json!(why))],
    );
    tracing::info!("probe {name} unregistered: {why}");
}

// ---------------------------------------------------------------------------------------------
// Connect (controller) and accept (probe)
// ---------------------------------------------------------------------------------------------

const UNAVAILABLE: &str = "that probe is not available to this controller through this relay";

async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, r: &ConnectReply) -> bool {
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, write_frame(stream, r)).await,
        Ok(Ok(()))
    )
}

/// Decrements a counter when dropped.
struct Count<'a>(&'a AtomicU32);
impl Drop for Count<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Increments `counter` if it is below `max`.
fn claim(counter: &AtomicU32, max: u32) -> Option<Count<'_>> {
    let mut n = counter.load(Ordering::Acquire);
    loop {
        if n >= max {
            return None;
        }
        match counter.compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(Count(counter)),
            Err(now) => n = now,
        }
    }
}

async fn run_connect(
    shared: Arc<Shared>,
    mut stream: Stream,
    controller: Fingerprint,
    peer: SocketAddr,
    unpaired: impl Send,
) {
    let req = match tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_frame::<_, Connect>(&mut stream))
        .await
    {
        Ok(Ok(c)) => c,
        _ => return,
    };
    let unavailable = ConnectReply::Unavailable {
        message: UNAVAILABLE.into(),
    };
    let probe_fp: Option<Fingerprint> = req.probe.parse().ok();
    let reg = probe_fp.and_then(|p| shared.probes.lock().unwrap().get(&p).cloned());
    let reg = match reg {
        Some(r)
            if req.protocol == RELAY_PROTOCOL_VERSION
                && probe_fp.is_some_and(|p| shared.config().probe_name(&p).is_some())
                && r.controllers.read().unwrap().contains(&controller) =>
        {
            r
        }
        _ => {
            reply(&mut stream, &unavailable).await;
            return;
        }
    };
    let probe_fp = probe_fp.expect("registration found by fingerprint");
    let limits = shared.config().limits.clone();
    let Some(_waiting) = claim(&reg.waiting, limits.max_waiting_per_probe) else {
        reply(&mut stream, &unavailable).await;
        return;
    };
    let Some(pair_slot) = claim(&reg.pairs, limits.max_pairs_per_probe) else {
        reply(&mut stream, &unavailable).await;
        return;
    };

    let ticket = hex::encode(portglass_core::random_bytes::<16>());
    let (deliver, delivered) = oneshot::channel();
    shared.tickets.lock().unwrap().insert(
        ticket.clone(),
        Ticket {
            probe: probe_fp,
            deliver,
        },
    );
    let probe_stream = if reg
        .events
        .try_send(ProbeEvent::Incoming {
            ticket: ticket.clone(),
        })
        .is_ok()
    {
        let answer = Duration::from_secs(limits.answer_timeout_secs as u64);
        tokio::select! {
            r = tokio::time::timeout(answer, delivered) => r.ok().and_then(Result::ok),
            _ = reg.cancel.cancelled() => None,
        }
    } else {
        None
    };
    shared.tickets.lock().unwrap().remove(&ticket);
    drop(_waiting);
    let Some(probe_stream) = probe_stream else {
        reply(&mut stream, &unavailable).await;
        return;
    };
    if !reply(&mut stream, &ConnectReply::Connected).await {
        return;
    }
    drop(unpaired);

    let started = Instant::now();
    let counters = Arc::new(Counters::default());
    let end = bridge(
        stream,
        probe_stream,
        Duration::from_secs(limits.idle_timeout_secs as u64),
        reg.cancel.child_token(),
        counters.clone(),
    )
    .await;
    drop(pair_slot);
    let (up, down) = counters.snapshot();
    shared.audit.record(
        "pair_ended",
        &[
            ("probe", json!(reg.name)),
            ("controller", json!(controller.to_string())),
            ("peer", json!(peer.to_string())),
            ("bytes_up", json!(up)),
            ("bytes_down", json!(down)),
            ("secs", json!(started.elapsed().as_secs())),
            ("end", json!(end.as_str())),
        ],
    );
}

async fn run_accept(
    shared: Arc<Shared>,
    mut stream: Stream,
    probe: Fingerprint,
    _answer: impl Send,
) {
    let Ok(Ok(Accept { ticket })) =
        tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_frame::<_, Accept>(&mut stream)).await
    else {
        return;
    };
    let mut tickets = shared.tickets.lock().unwrap();
    // A ticket is answerable only by the probe it was issued to.
    if tickets.get(&ticket).is_some_and(|t| t.probe == probe) {
        if let Some(t) = tickets.remove(&ticket) {
            let _ = t.deliver.send(stream);
        }
    }
}

// ---------------------------------------------------------------------------------------------

fn apply_config(shared: &Arc<Shared>, config: RelayConfig) {
    let config = Arc::new(config);
    // Hold `probes` across the swap and the sweep (the same `probes -> config` order the
    // registration path uses), so two concurrent applies cannot sweep with a stale file.
    let mut probes = shared.probes.lock().unwrap();
    *shared.config.write().unwrap() = config.clone();
    probes.retain(|fp, reg| {
        let keep = config.probe_name(fp).is_some();
        if !keep {
            reg.cancel.cancel();
        }
        keep
    });
    shared
        .audit
        .record("config_applied", &[("probes", json!(config.probes.len()))]);
}
