//! The probe's network service.
//!
//! Two connection kinds, both mutually authenticated TLS 1.3 (selected by ALPN):
//!
//! * **Control** — the controller asks to open, check and close sessions. A session names one
//!   destination, approved by [`crate::policy`] and pinned to one resolved address.
//! * **Data** — one per forwarded TCP connection. It presents a session id and token; the probe
//!   connects it to that session's destination. A data stream cannot choose a destination.
//!
//! Sessions end when the controller closes them, when their TTL expires, when an administrator's
//! configuration change revokes them, when their control connection drops, or when the probe
//! stops. Ending a session cancels every one of its forwarded connections immediately.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use portglass_core::audit::AuditLog;
use portglass_core::bridge::{bridge, Counters};
use portglass_core::identity::{Fingerprint, Identity};
use portglass_core::tls::{self, ControllerAllowlist};
use portglass_proto::{
    read_frame, write_frame, ControlEvent, ControlRequest, EndReason, ErrorCode, FrameError,
    PolicySummary, StreamOpen, StreamReply, ALPN_CONTROL, ALPN_DATA, PROTOCOL_VERSION,
};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::ProbeConfig;
use crate::policy;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections that have not finished authenticating. Bounds the cost of unauthenticated peers.
const MAX_PENDING_HANDSHAKES: usize = 64;

pub struct Session {
    pub id: String,
    token: [u8; 32],
    pub owner: Fingerprint,
    pub operator: String,
    pub requested: String,
    pub target: SocketAddr,
    pub expires_at: Instant,
    pub opened_at: Instant,
    cancel: CancellationToken,
    events: mpsc::Sender<ControlEvent>,
    owner_conn: u64,
    active_streams: AtomicU32,
    total_streams: AtomicU64,
    failed_streams: AtomicU64,
    counters: Arc<Counters>,
    ended: Mutex<Option<EndReason>>,
}

struct Connection {
    fingerprint: Fingerprint,
    cancel: CancellationToken,
}

struct Shared {
    config: RwLock<Arc<ProbeConfig>>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    connections: Mutex<HashMap<u64, Connection>>,
    next_conn: AtomicU64,
    audit: Arc<AuditLog>,
    shutdown: CancellationToken,
    auth_fail_window: Mutex<(Instant, u32)>,
}

impl Shared {
    fn config(&self) -> Arc<ProbeConfig> {
        self.config
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// The TLS layer's view of who may connect: the live configuration, so a revoked controller
/// cannot complete another handshake.
#[derive(Clone)]
struct LiveAllowlist(Arc<Shared>);

impl std::fmt::Debug for LiveAllowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LiveAllowlist")
    }
}

impl ControllerAllowlist for LiveAllowlist {
    fn is_allowed(&self, fp: &Fingerprint) -> bool {
        let allowed = self.0.config().controller_name(fp).is_some();
        if !allowed {
            // Rate-limited so unauthenticated peers cannot flood the audit log.
            let mut w = self
                .0
                .auth_fail_window
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if w.0.elapsed() > Duration::from_secs(60) {
                *w = (Instant::now(), 0);
            }
            w.1 += 1;
            if w.1 <= 20 {
                self.0.audit.record(
                    "auth_rejected",
                    &[
                        ("fingerprint", json!(fp.to_string())),
                        (
                            "reason",
                            json!("controller certificate is not in this probe's allowlist"),
                        ),
                    ],
                );
            }
        }
        allowed
    }
}

/// A running probe.
pub struct ProbeHandle {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl ProbeHandle {
    /// Apply a new configuration and revoke whatever it no longer permits.
    pub fn apply_config(&self, config: ProbeConfig) {
        apply_config(&self.shared, config);
    }

    pub fn active_sessions(&self) -> usize {
        self.shared.sessions.lock().unwrap().len()
    }

    pub fn config(&self) -> Arc<ProbeConfig> {
        self.shared.config()
    }

    /// End every session, close every connection, stop listening.
    pub async fn shutdown(self) {
        let sessions: Vec<_> = self
            .shared
            .sessions
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for s in sessions {
            end_session(&self.shared, &s, EndReason::ProbeShutdown);
        }
        self.shared.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.task).await;
        self.shared.audit.record("probe_stopped", &[]);
    }
}

pub async fn start(
    config: ProbeConfig,
    identity: Identity,
    audit: Arc<AuditLog>,
) -> Result<ProbeHandle> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("listening on {}", config.listen))?;
    let addr = listener.local_addr()?;
    let shared = Arc::new(Shared {
        config: RwLock::new(Arc::new(config)),
        sessions: Mutex::new(HashMap::new()),
        connections: Mutex::new(HashMap::new()),
        next_conn: AtomicU64::new(1),
        audit,
        shutdown: CancellationToken::new(),
        auth_fail_window: Mutex::new((Instant::now(), 0)),
    });
    let server_config = tls::server_config(
        &identity,
        Arc::new(LiveAllowlist(shared.clone())),
        &[ALPN_CONTROL, ALPN_DATA],
    )?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let cfg = shared.config();
    shared.audit.record(
        "probe_started",
        &[
            ("probe", json!(cfg.name)),
            ("listen", json!(addr.to_string())),
            ("fingerprint", json!(identity.fingerprint.to_string())),
            ("controllers", json!(cfg.controllers.len())),
            ("allow_rules", json!(cfg.allow.len())),
        ],
    );
    let task = tokio::spawn(accept_loop(listener, acceptor, shared.clone()));
    Ok(ProbeHandle { addr, shared, task })
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
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            tracing::warn!("dropping connection from {peer}: too many pending handshakes");
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::info!("TLS handshake with {peer} failed: {e}");
                    return;
                }
                Err(_) => {
                    tracing::info!("TLS handshake with {peer} timed out");
                    return;
                }
            };
            drop(permit);
            let (_, conn) = tls.get_ref();
            let alpn = conn.alpn_protocol().map(|a| a.to_vec());
            let Some(fp) = tls::peer_fingerprint(conn) else {
                return;
            };
            let Some(operator) = shared.config().controller_name(&fp).map(str::to_owned) else {
                return;
            };
            match alpn.as_deref() {
                Some(a) if a == ALPN_CONTROL => run_control(shared, tls, fp, operator, peer).await,
                Some(a) if a == ALPN_DATA => run_data(shared, tls, fp, peer).await,
                _ => tracing::info!("{peer} negotiated no PortGlass protocol; closing"),
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Control connections
// ---------------------------------------------------------------------------------------------

async fn run_control<S>(
    shared: Arc<Shared>,
    stream: S,
    fp: Fingerprint,
    operator: String,
    peer: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<ControlEvent>(64);
    let writer = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if write_frame(&mut wr, &ev).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let hello = tokio::time::timeout(
        FIRST_FRAME_TIMEOUT,
        read_frame::<_, ControlRequest>(&mut rd),
    )
    .await;
    let (client_version, operator_hint) = match hello {
        Ok(Ok(ControlRequest::Hello {
            protocol,
            client_version,
            operator_hint,
        })) => {
            if protocol != PROTOCOL_VERSION {
                let _ = tx
                    .send(ControlEvent::Error {
                        code: ErrorCode::VersionMismatch,
                        message: format!(
                            "probe speaks protocol {PROTOCOL_VERSION}, controller sent {protocol}"
                        ),
                    })
                    .await;
                drop(tx);
                let _ = writer.await;
                return;
            }
            (client_version, operator_hint)
        }
        _ => {
            let _ = tx
                .send(ControlEvent::Error {
                    code: ErrorCode::ProtocolViolation,
                    message: "expected hello".into(),
                })
                .await;
            drop(tx);
            let _ = writer.await;
            return;
        }
    };

    let conn_id = shared.next_conn.fetch_add(1, Ordering::Relaxed);
    let conn_cancel = shared.shutdown.child_token();
    shared.connections.lock().unwrap().insert(
        conn_id,
        Connection {
            fingerprint: fp,
            cancel: conn_cancel.clone(),
        },
    );
    let cfg = shared.config();
    shared.audit.record(
        "controller_connected",
        &[
            ("operator", json!(operator)),
            ("fingerprint", json!(fp.to_string())),
            ("peer", json!(peer.to_string())),
            ("client_version", json!(client_version)),
            ("operator_hint", json!(operator_hint)),
        ],
    );
    let _ = tx
        .send(ControlEvent::HelloOk {
            protocol: PROTOCOL_VERSION,
            probe_name: cfg.name.clone(),
            probe_version: env!("CARGO_PKG_VERSION").into(),
            authorized_as: operator.clone(),
            policy: policy_summary(&cfg),
        })
        .await;

    let ctx = Arc::new(ControlCtx {
        shared: shared.clone(),
        fp,
        operator: operator.clone(),
        tx: tx.clone(),
        conn_id,
    });
    let control_timeout = Duration::from_secs(cfg.limits.control_timeout_secs as u64);
    let reason = loop {
        let frame = tokio::select! {
            _ = conn_cancel.cancelled() => {
                break if shared.shutdown.is_cancelled() { "probe_shutdown" } else { "revoked" };
            }
            r = tokio::time::timeout(control_timeout, read_frame::<_, ControlRequest>(&mut rd)) => r,
        };
        match frame {
            Err(_) => break "heartbeat_timeout",
            Ok(Err(FrameError::Closed)) => break "closed",
            Ok(Err(FrameError::Malformed(_))) | Ok(Err(FrameError::TooLarge(_))) => {
                let _ = tx
                    .send(ControlEvent::Error {
                        code: ErrorCode::Unsupported,
                        message: "unsupported or malformed command; this probe only opens, checks \
                                  and closes forwarding sessions"
                            .into(),
                    })
                    .await;
                shared.audit.record(
                    "command_rejected",
                    &[
                        ("operator", json!(operator)),
                        ("fingerprint", json!(fp.to_string())),
                        ("reason", json!("unsupported or malformed command")),
                    ],
                );
                break "unsupported_command";
            }
            Ok(Err(_)) => break "io_error",
            Ok(Ok(req)) => {
                if let Err(why) = handle_request(&ctx, req).await {
                    let _ = tx
                        .send(ControlEvent::Error {
                            code: ErrorCode::ProtocolViolation,
                            message: why.into(),
                        })
                        .await;
                    break "protocol_violation";
                }
            }
        }
    };

    // Sessions never outlive their control connection.
    shared.connections.lock().unwrap().remove(&conn_id);
    let owned: Vec<_> = shared
        .sessions
        .lock()
        .unwrap()
        .values()
        .filter(|s| s.conn_id() == conn_id)
        .cloned()
        .collect();
    let end = match reason {
        "revoked" => EndReason::Revoked,
        "probe_shutdown" => EndReason::ProbeShutdown,
        _ => EndReason::ControllerDisconnected,
    };
    for s in owned {
        end_session(&shared, &s, end);
    }
    shared.audit.record(
        "controller_disconnected",
        &[
            ("operator", json!(operator)),
            ("fingerprint", json!(fp.to_string())),
            ("peer", json!(peer.to_string())),
            ("reason", json!(reason)),
        ],
    );
    drop(ctx);
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
}

struct ControlCtx {
    shared: Arc<Shared>,
    fp: Fingerprint,
    operator: String,
    tx: mpsc::Sender<ControlEvent>,
    conn_id: u64,
}

impl Session {
    /// The control connection that opened this session; the session ends with it.
    fn conn_id(&self) -> u64 {
        self.owner_conn
    }
}

async fn handle_request(ctx: &Arc<ControlCtx>, req: ControlRequest) -> Result<(), &'static str> {
    match req {
        ControlRequest::Hello { .. } => return Err("hello sent twice"),
        ControlRequest::Ping { nonce } => {
            let _ = ctx.tx.send(ControlEvent::Pong { nonce }).await;
        }
        ControlRequest::OpenSession {
            request_id,
            target,
            ttl_secs,
        } => {
            let ctx = ctx.clone();
            tokio::spawn(async move { open_session(&ctx, request_id, target, ttl_secs).await });
        }
        ControlRequest::CheckTarget { session_id } => {
            let Some(session) = owned_session(ctx, &session_id) else {
                let _ = ctx
                    .tx
                    .send(ControlEvent::TargetStatus {
                        session_id,
                        reachable: false,
                        rtt_ms: None,
                        code: Some(ErrorCode::SessionNotFound),
                        message: Some("no such session".into()),
                    })
                    .await;
                return Ok(());
            };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let timeout =
                    Duration::from_secs(ctx.shared.config().limits.connect_timeout_secs as u64);
                let started = Instant::now();
                let ev = match connect_target(session.target, timeout).await {
                    Ok(_) => ControlEvent::TargetStatus {
                        session_id: session.id.clone(),
                        reachable: true,
                        rtt_ms: Some(started.elapsed().as_millis() as u32),
                        code: None,
                        message: None,
                    },
                    Err((code, message)) => ControlEvent::TargetStatus {
                        session_id: session.id.clone(),
                        reachable: false,
                        rtt_ms: None,
                        code: Some(code),
                        message: Some(message),
                    },
                };
                let _ = ctx.tx.send(ev).await;
            });
        }
        ControlRequest::CloseSession { session_id } => {
            if let Some(session) = owned_session(ctx, &session_id) {
                end_session(&ctx.shared, &session, EndReason::ClosedByController);
            }
        }
    }
    Ok(())
}

fn owned_session(ctx: &ControlCtx, id: &str) -> Option<Arc<Session>> {
    ctx.shared
        .sessions
        .lock()
        .unwrap()
        .get(id)
        .filter(|s| s.owner == ctx.fp && s.conn_id() == ctx.conn_id)
        .cloned()
}

async fn open_session(
    ctx: &ControlCtx,
    request_id: u64,
    target: portglass_proto::TargetSpec,
    ttl_secs: u32,
) {
    let cfg = ctx.shared.config();
    let requested = target.to_string();
    let reject = |code: ErrorCode, message: String| {
        ctx.shared.audit.record(
            "session_denied",
            &[
                ("operator", json!(ctx.operator)),
                ("fingerprint", json!(ctx.fp.to_string())),
                ("target", json!(requested)),
                ("code", json!(code.as_str())),
                ("message", json!(message)),
            ],
        );
        ControlEvent::SessionRejected {
            request_id,
            code,
            message,
        }
    };

    if ttl_secs == 0 {
        let _ = ctx
            .tx
            .send(reject(
                ErrorCode::InvalidRequest,
                "ttl must be positive".into(),
            ))
            .await;
        return;
    }
    let ttl = ttl_secs.min(cfg.limits.max_session_ttl_secs);

    let (addr, label) = match policy::authorize(&cfg.allow, &target, Duration::from_secs(5)).await {
        Ok(x) => x,
        Err(d) => {
            let _ = ctx.tx.send(reject(d.code, d.message)).await;
            return;
        }
    };

    let connect_timeout = Duration::from_secs(cfg.limits.connect_timeout_secs as u64);
    let started = Instant::now();
    match connect_target(addr, connect_timeout).await {
        Ok(stream) => drop(stream),
        Err((code, message)) => {
            let _ = ctx.tx.send(reject(code, message)).await;
            return;
        }
    }
    let connect_ms = started.elapsed().as_millis() as u32;

    let id = hex::encode(portglass_core::random_bytes::<16>());
    let token = portglass_core::random_bytes::<32>();
    let now = Instant::now();
    let session = Arc::new(Session {
        id: id.clone(),
        token,
        owner: ctx.fp,
        operator: ctx.operator.clone(),
        requested: requested.clone(),
        target: addr,
        expires_at: now + Duration::from_secs(ttl as u64),
        opened_at: now,
        cancel: ctx.shared.shutdown.child_token(),
        events: ctx.tx.clone(),
        owner_conn: ctx.conn_id,
        active_streams: AtomicU32::new(0),
        total_streams: AtomicU64::new(0),
        failed_streams: AtomicU64::new(0),
        counters: Arc::new(Counters::default()),
        ended: Mutex::new(None),
    });

    // Re-check everything that may have changed while we were connecting, then register the
    // session under the same lock. (Lock order: sessions, then connections.)
    let refused: Option<(ErrorCode, String)> = {
        let mut sessions = ctx.shared.sessions.lock().unwrap();
        let still_connected = ctx
            .shared
            .connections
            .lock()
            .unwrap()
            .contains_key(&ctx.conn_id);
        let now_cfg = ctx.shared.config();
        let still_allowed = now_cfg.controller_name(&ctx.fp).is_some()
            && policy::check(&now_cfg.allow, addr.ip(), addr.port()).is_ok();
        if !still_connected || !still_allowed {
            Some((
                ErrorCode::UnauthorizedTarget,
                "the probe's configuration changed while the session was opening".into(),
            ))
        } else if sessions.len() >= now_cfg.limits.max_sessions as usize {
            Some((
                ErrorCode::TooManySessions,
                format!(
                    "this probe allows {} concurrent sessions",
                    now_cfg.limits.max_sessions
                ),
            ))
        } else {
            sessions.insert(id.clone(), session.clone());
            None
        }
    };
    if let Some((code, message)) = refused {
        let _ = ctx.tx.send(reject(code, message)).await;
        return;
    }

    ctx.shared.audit.record(
        "session_opened",
        &[
            ("session", json!(id)),
            ("operator", json!(ctx.operator)),
            ("fingerprint", json!(ctx.fp.to_string())),
            ("target", json!(requested)),
            ("resolved", json!(addr.to_string())),
            ("rule_label", json!(label)),
            ("ttl_secs", json!(ttl)),
            ("connect_ms", json!(connect_ms)),
        ],
    );

    let shared = ctx.shared.clone();
    let s = session.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep_until(s.expires_at.into()) => end_session(&shared, &s, EndReason::Expired),
            _ = s.cancel.cancelled() => {}
        }
    });

    let _ = ctx
        .tx
        .send(ControlEvent::SessionOpened {
            request_id,
            session_id: id,
            stream_token: hex::encode(token),
            resolved_addr: addr.to_string(),
            expires_in_secs: ttl,
            connect_ms,
        })
        .await;
}

/// End a session exactly once: cancel its streams, forget it, tell the controller, audit it.
fn end_session(shared: &Shared, session: &Arc<Session>, reason: EndReason) {
    {
        let mut ended = session.ended.lock().unwrap();
        if ended.is_some() {
            return;
        }
        *ended = Some(reason);
    }
    session.cancel.cancel();
    shared.sessions.lock().unwrap().remove(&session.id);
    let _ = session.events.try_send(ControlEvent::SessionEnded {
        session_id: session.id.clone(),
        reason,
    });
    let (up, down) = session.counters.snapshot();
    shared.audit.record(
        "session_ended",
        &[
            ("session", json!(session.id)),
            ("operator", json!(session.operator)),
            ("fingerprint", json!(session.owner.to_string())),
            ("target", json!(session.requested)),
            ("resolved", json!(session.target.to_string())),
            ("reason", json!(reason.as_str())),
            (
                "duration_secs",
                json!(session.opened_at.elapsed().as_secs()),
            ),
            (
                "streams",
                json!(session.total_streams.load(Ordering::Relaxed)),
            ),
            (
                "streams_failed",
                json!(session.failed_streams.load(Ordering::Relaxed)),
            ),
            ("bytes_to_target", json!(up)),
            ("bytes_from_target", json!(down)),
        ],
    );
}

fn policy_summary(cfg: &ProbeConfig) -> PolicySummary {
    PolicySummary {
        allow: cfg.allow.iter().map(|r| r.summary()).collect(),
        max_session_ttl_secs: cfg.limits.max_session_ttl_secs,
        max_streams_per_session: cfg.limits.max_streams_per_session,
    }
}

async fn connect_target(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, (ErrorCode, String)> {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Err((
            ErrorCode::ConnectionRefused,
            format!(
                "{addr} refused the connection: nothing is listening on port {}",
                addr.port()
            ),
        )),
        Ok(Err(e)) => Err((
            ErrorCode::TargetUnreachable,
            format!("the probe cannot reach {addr}: {e}"),
        )),
        Err(_) => Err((
            ErrorCode::TargetTimeout,
            format!("{addr} did not answer within {}s", timeout.as_secs()),
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Data connections
// ---------------------------------------------------------------------------------------------

async fn run_data<S>(shared: Arc<Shared>, mut stream: S, fp: Fingerprint, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let open = match tokio::time::timeout(
        FIRST_FRAME_TIMEOUT,
        read_frame::<_, StreamOpen>(&mut stream),
    )
    .await
    {
        Ok(Ok(o)) => o,
        _ => return,
    };
    let cfg = shared.config();
    let session = shared
        .sessions
        .lock()
        .unwrap()
        .get(&open.session_id)
        .cloned();
    let token_ok = |s: &Session| {
        hex::decode(&open.stream_token)
            .map(|t| portglass_core::ct_eq(&t, &s.token))
            .unwrap_or(false)
    };
    // Unknown session, wrong owner and wrong token are indistinguishable to the caller.
    let session = match session {
        Some(s) if s.owner == fp && token_ok(&s) => s,
        _ => {
            reject_stream(&mut stream, ErrorCode::SessionNotFound, "no such session").await;
            tracing::info!("data stream from {peer} presented an unknown session or token");
            return;
        }
    };
    if session.cancel.is_cancelled() || Instant::now() >= session.expires_at {
        reject_stream(
            &mut stream,
            ErrorCode::SessionExpired,
            "the session has ended",
        )
        .await;
        return;
    }
    let max = cfg.limits.max_streams_per_session;
    if session.active_streams.fetch_add(1, Ordering::AcqRel) >= max {
        session.active_streams.fetch_sub(1, Ordering::AcqRel);
        session.failed_streams.fetch_add(1, Ordering::Relaxed);
        reject_stream(
            &mut stream,
            ErrorCode::TooManyStreams,
            &format!("this probe allows {max} concurrent connections per session"),
        )
        .await;
        return;
    }
    let _guard = StreamGuard(&session);

    let connect_timeout = Duration::from_secs(cfg.limits.connect_timeout_secs as u64);
    let target = tokio::select! {
        r = connect_target(session.target, connect_timeout) => r,
        _ = session.cancel.cancelled() => Err((ErrorCode::SessionExpired, "the session has ended".into())),
    };
    let target = match target {
        Ok(t) => t,
        Err((code, message)) => {
            session.failed_streams.fetch_add(1, Ordering::Relaxed);
            shared.audit.record(
                "stream_failed",
                &[
                    ("session", json!(session.id)),
                    ("operator", json!(session.operator)),
                    ("target", json!(session.target.to_string())),
                    ("code", json!(code.as_str())),
                ],
            );
            reject_stream(&mut stream, code, &message).await;
            return;
        }
    };
    if write_frame(&mut stream, &StreamReply::Accepted)
        .await
        .is_err()
    {
        return;
    }
    session.total_streams.fetch_add(1, Ordering::Relaxed);
    let idle = Duration::from_secs(cfg.limits.stream_idle_timeout_secs as u64);
    let end = bridge(
        stream,
        target,
        idle,
        session.cancel.child_token(),
        session.counters.clone(),
    )
    .await;
    tracing::debug!(session = %session.id, "stream ended: {}", end.as_str());
}

struct StreamGuard<'a>(&'a Session);
impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        self.0.active_streams.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn reject_stream<S: AsyncWrite + Unpin>(stream: &mut S, code: ErrorCode, message: &str) {
    let _ = write_frame(
        stream,
        &StreamReply::Rejected {
            code,
            message: message.into(),
        },
    )
    .await;
    let _ = stream.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Configuration changes
// ---------------------------------------------------------------------------------------------

fn apply_config(shared: &Arc<Shared>, config: ProbeConfig) {
    let config = Arc::new(config);
    *shared.config.write().unwrap() = config.clone();

    // Controllers no longer listed lose their connections (and with them, their sessions).
    for c in shared.connections.lock().unwrap().values() {
        if config.controller_name(&c.fingerprint).is_none() {
            c.cancel.cancel();
        }
    }
    // Sessions whose destination is no longer allowed end now.
    let sessions: Vec<_> = shared.sessions.lock().unwrap().values().cloned().collect();
    for s in sessions {
        let owner_ok = config.controller_name(&s.owner).is_some();
        let target_ok = policy::check(&config.allow, s.target.ip(), s.target.port()).is_ok();
        if !owner_ok || !target_ok {
            end_session(shared, &s, EndReason::Revoked);
        }
    }
    shared.audit.record(
        "config_applied",
        &[
            ("controllers", json!(config.controllers.len())),
            ("allow_rules", json!(config.allow.len())),
        ],
    );
}
