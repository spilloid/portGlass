//! The controller's connection to one probe.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portglass_core::identity::{Fingerprint, Identity};
use portglass_core::tls;
use portglass_proto::{
    read_frame, write_frame, ControlEvent, ControlRequest, ErrorCode, FrameError, PolicySummary,
    StreamOpen, StreamReply, TargetSpec, ALPN_CONTROL, ALPN_DATA, PROTOCOL_VERSION,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::config::ProbeEntry;
use crate::failure::{Failure, FailureKind};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const KEEPALIVE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, serde::Serialize)]
pub struct HelloInfo {
    pub probe_name: String,
    pub probe_version: String,
    pub authorized_as: String,
    pub policy: PolicySummary,
}

#[derive(Debug, Clone)]
pub struct SessionGrant {
    pub session_id: String,
    pub stream_token: String,
    pub resolved_addr: String,
    pub expires_in_secs: u32,
    pub connect_ms: u32,
}

pub struct ProbeLink {
    pub entry: ProbeEntry,
    pub hello: HelloInfo,
    own_fingerprint: Fingerprint,
    tx: mpsc::Sender<ControlRequest>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<ControlEvent>>>>,
    pings: Arc<Mutex<HashMap<u64, oneshot::Sender<()>>>>,
    events: broadcast::Sender<ControlEvent>,
    next_id: AtomicU64,
    closed: CancellationToken,
    close_reason: Arc<Mutex<Option<String>>>,
    data_connector: TlsConnector,
}

impl ProbeLink {
    /// Open the control connection and authenticate. This is the AUTHENTICATING phase.
    pub async fn connect(
        entry: &ProbeEntry,
        identity: &Identity,
        operator_hint: &str,
    ) -> Result<Arc<ProbeLink>, Failure> {
        let control_cfg = tls::client_config(identity, entry.fingerprint, ALPN_CONTROL)
            .map_err(|e| Failure::internal(format!("TLS setup: {e}")))?;
        let data_cfg = tls::client_config(identity, entry.fingerprint, ALPN_DATA)
            .map_err(|e| Failure::internal(format!("TLS setup: {e}")))?;
        let mut stream =
            connect_tls(&TlsConnector::from(Arc::new(control_cfg)), entry, identity).await?;

        let hello = ControlRequest::Hello {
            protocol: PROTOCOL_VERSION,
            client_version: env!("CARGO_PKG_VERSION").into(),
            operator_hint: operator_hint.into(),
        };
        let first = async {
            write_frame(&mut stream, &hello).await?;
            read_frame::<_, ControlEvent>(&mut stream).await
        };
        let reply =
            match tokio::time::timeout(REPLY_TIMEOUT, first).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(classify_frame_error(&e, entry, identity)),
                Err(_) => return Err(Failure::new(
                    FailureKind::ProbeUnreachable,
                    "The probe didn't answer",
                    format!(
                        "{} accepted a connection but did not respond in time.",
                        entry.address
                    ),
                    "Check that the address is a PortGlass Probe and that it is not overloaded.",
                )),
            };
        let hello = match reply {
            ControlEvent::HelloOk {
                protocol,
                probe_name,
                probe_version,
                authorized_as,
                policy,
            } if protocol == PROTOCOL_VERSION => HelloInfo {
                probe_name,
                probe_version,
                authorized_as,
                policy,
            },
            ControlEvent::Error { code, message } => {
                return Err(Failure::from_probe(code, &message, &entry.address))
            }
            other => {
                return Err(Failure::internal(format!(
                    "unexpected first message from probe: {other:?}"
                )))
            }
        };

        let (rd, wr) = tokio::io::split(stream);
        let (tx, rx) = mpsc::channel::<ControlRequest>(64);
        let (events, _) = broadcast::channel(256);
        let link = Arc::new(ProbeLink {
            entry: entry.clone(),
            hello,
            own_fingerprint: identity.fingerprint,
            tx,
            pending: Default::default(),
            pings: Default::default(),
            events,
            next_id: AtomicU64::new(1),
            closed: CancellationToken::new(),
            close_reason: Default::default(),
            data_connector: TlsConnector::from(Arc::new(data_cfg)),
        });
        tokio::spawn(writer_task(wr, rx, link.closed.clone()));
        tokio::spawn(reader_task(
            rd,
            Arc::downgrade(&link),
            link.closed.clone(),
            link.close_reason.clone(),
        ));
        // Keep the control connection alive from the moment it authenticates: the probe drops
        // (and revokes the sessions of) any control connection that goes quiet.
        {
            let tx = link.tx.clone();
            let closed = link.closed.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(KEEPALIVE);
                iv.tick().await;
                let mut nonce = u64::MAX / 2;
                loop {
                    tokio::select! {
                        _ = closed.cancelled() => return,
                        _ = iv.tick() => {}
                    }
                    nonce += 1;
                    if tx.send(ControlRequest::Ping { nonce }).await.is_err() {
                        return;
                    }
                }
            });
        }
        Ok(link)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ControlEvent> {
        self.events.subscribe()
    }

    pub fn closed(&self) -> CancellationToken {
        self.closed.clone()
    }

    pub fn close_reason(&self) -> Option<String> {
        self.close_reason.lock().unwrap().clone()
    }

    async fn send(&self, req: ControlRequest) -> Result<(), Failure> {
        self.tx.send(req).await.map_err(|_| self.lost())
    }

    fn lost(&self) -> Failure {
        Failure::new(
            FailureKind::NetworkInterrupted,
            "The connection to the probe was lost",
            self.close_reason()
                .unwrap_or_else(|| "The control connection closed.".into()),
            "Check the network between you and the probe, then connect again.",
        )
    }

    /// Ask the probe for a session to `target`. This is the CONNECTING phase: the probe applies
    /// its policy and test-connects to the target before granting anything.
    pub async fn open_session(
        &self,
        target: &TargetSpec,
        ttl_secs: u32,
    ) -> Result<SessionGrant, Failure> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(request_id, tx);
        self.send(ControlRequest::OpenSession {
            request_id,
            target: target.clone(),
            ttl_secs,
        })
        .await?;
        let reply = tokio::select! {
            r = tokio::time::timeout(REPLY_TIMEOUT, rx) => r,
            _ = self.closed.cancelled() => return Err(self.lost()),
        };
        self.pending.lock().unwrap().remove(&request_id);
        match reply {
            Ok(Ok(ControlEvent::SessionOpened {
                session_id,
                stream_token,
                resolved_addr,
                expires_in_secs,
                connect_ms,
                ..
            })) if is_hex(&session_id, 32) && is_hex(&stream_token, 64) => Ok(SessionGrant {
                session_id,
                stream_token,
                resolved_addr,
                expires_in_secs,
                connect_ms,
            }),
            Ok(Ok(ControlEvent::SessionOpened { .. })) => Err(Failure::new(
                FailureKind::Internal,
                "The probe sent a malformed session",
                "The session id or token was not in the expected format, so it was refused.",
                "Check that the probe runs a matching PortGlass version. If it does, treat the \
                 probe as untrusted until it is investigated.",
            )),
            Ok(Ok(ControlEvent::SessionRejected { code, message, .. })) => {
                Err(Failure::from_probe(code, &message, &target.to_string()))
            }
            Ok(Ok(other)) => Err(Failure::internal(format!("unexpected reply: {other:?}"))),
            Ok(Err(_)) => Err(self.lost()),
            Err(_) => Err(Failure::new(
                FailureKind::ProbeUnreachable,
                "The probe didn't answer the session request",
                "No reply within 20 seconds.",
                "Try again; if it persists, check the probe's console for errors.",
            )),
        }
    }

    pub async fn ping(&self) -> Result<Duration, Failure> {
        let nonce = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pings.lock().unwrap().insert(nonce, tx);
        let started = Instant::now();
        self.send(ControlRequest::Ping { nonce }).await?;
        let r = tokio::time::timeout(Duration::from_secs(5), rx).await;
        self.pings.lock().unwrap().remove(&nonce);
        match r {
            Ok(Ok(())) => Ok(started.elapsed()),
            _ => Err(self.lost()),
        }
    }

    pub async fn check_target(&self, session_id: &str) -> Result<(), Failure> {
        self.send(ControlRequest::CheckTarget {
            session_id: session_id.into(),
        })
        .await
    }

    pub async fn close_session(&self, session_id: &str) {
        let _ = self
            .send(ControlRequest::CloseSession {
                session_id: session_id.into(),
            })
            .await;
    }

    /// Close the control connection. The probe ends any session still open on it.
    pub fn shutdown(&self) {
        self.closed.cancel();
    }

    /// Open one data stream for a session. The probe connects it to the session's target.
    pub async fn open_stream(
        &self,
        session_id: &str,
        token: &str,
    ) -> Result<TlsStream<TcpStream>, (Option<ErrorCode>, String)> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.entry.address))
            .await
            .map_err(|_| (None, "connecting to the probe timed out".to_string()))?
            .map_err(|e| (None, format!("connecting to the probe: {e}")))?;
        let _ = tcp.set_nodelay(true);
        let mut tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.data_connector.connect(tls::server_name(), tcp),
        )
        .await
        .map_err(|_| (None, "TLS handshake with the probe timed out".to_string()))?
        .map_err(|e| (None, format!("TLS handshake with the probe: {e}")))?;
        let open = StreamOpen {
            session_id: session_id.into(),
            stream_token: token.into(),
        };
        let exchange = async {
            write_frame(&mut tls, &open).await?;
            read_frame::<_, StreamReply>(&mut tls).await
        };
        match tokio::time::timeout(REPLY_TIMEOUT, exchange).await {
            Ok(Ok(StreamReply::Accepted)) => Ok(tls),
            Ok(Ok(StreamReply::Rejected { code, message })) => Err((Some(code), message)),
            Ok(Err(e)) => Err((None, format!("probe closed the stream: {e}"))),
            Err(_) => Err((None, "the probe did not answer the stream request".into())),
        }
    }

    pub fn own_fingerprint(&self) -> Fingerprint {
        self.own_fingerprint
    }
}

/// Everything a probe sends is untrusted input. Session ids and tokens are fixed-length
/// lowercase hex, which also guarantees they can never act as a path or command fragment.
pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Drop for ProbeLink {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

async fn connect_tls(
    connector: &TlsConnector,
    entry: &ProbeEntry,
    identity: &Identity,
) -> Result<TlsStream<TcpStream>, Failure> {
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&entry.address)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let hint = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                "The computer answered but PortGlass Probe isn't listening. Is the probe running? \
                 Is the port right?"
            } else {
                "Check the address, that the probe is running, and that Windows Firewall on the \
                 probe allows its port from your address (see docs/deployment.md)."
            };
            return Err(Failure::new(
                FailureKind::ProbeUnreachable,
                format!("Can't reach probe {}", entry.name),
                format!("{}: {e}", entry.address),
                hint,
            ));
        }
        Err(_) => {
            return Err(Failure::new(
                FailureKind::ProbeUnreachable,
                format!("Can't reach probe {}", entry.name),
                format!(
                    "No answer from {} within {}s.",
                    entry.address,
                    CONNECT_TIMEOUT.as_secs()
                ),
                "The probe may be offline, or a firewall is silently dropping the connection.",
            ))
        }
    };
    let _ = tcp.set_nodelay(true);
    match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(tls::server_name(), tcp)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(classify_io(&e, entry, identity)),
        Err(_) => Err(Failure::new(
            FailureKind::TlsError,
            "The secure handshake with the probe timed out",
            entry.address.clone(),
            "Check that the address belongs to a PortGlass Probe.",
        )),
    }
}

/// Errors while exchanging hello, i.e. after our certificate was sent. A TLS 1.3 server rejects a
/// client certificate after the client considers the handshake complete, so the rejection shows
/// up here — as an alert, or (on Windows, when the socket is closed with unread data) a reset.
fn classify_frame_error(e: &FrameError, entry: &ProbeEntry, identity: &Identity) -> Failure {
    let closed_during_auth = || {
        Failure::new(
            FailureKind::AuthFailed,
            format!("Probe {} doesn't recognize this controller", entry.name),
            "The probe closed the connection while checking this controller's certificate.",
            format!(
                "Ask the probe's administrator to run: portglass-probe authorize --name <you> \
                 --fingerprint {}",
                identity.fingerprint
            ),
        )
    };
    match e {
        FrameError::Closed => closed_during_auth(),
        FrameError::Io(io) => {
            let is_tls = io
                .get_ref()
                .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some());
            let abrupt = matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            );
            if !is_tls && abrupt {
                closed_during_auth()
            } else {
                classify_io(io, entry, identity)
            }
        }
        other => Failure::internal(other.to_string()),
    }
}

fn classify_io(e: &std::io::Error, entry: &ProbeEntry, identity: &Identity) -> Failure {
    let tls_err = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match tls_err {
        Some(rustls::Error::InvalidCertificate(_)) => Failure::new(
            FailureKind::AuthFailed,
            format!("Probe {} presented the wrong identity", entry.name),
            format!(
                "The computer at {} is not the probe you pinned (expected {}).",
                entry.address,
                entry.fingerprint.short()
            ),
            "Check the address. If the probe was reinstalled, get its new fingerprint from its \
             administrator (portglass-probe fingerprint) and update this probe. Don't proceed if \
             you didn't expect a change.",
        ),
        Some(rustls::Error::AlertReceived(_)) => Failure::new(
            FailureKind::AuthFailed,
            format!("Probe {} doesn't recognize this controller", entry.name),
            "The probe rejected this controller's certificate.",
            format!(
                "Ask the probe's administrator to run: portglass-probe authorize --name <you> \
                 --fingerprint {}",
                identity.fingerprint
            ),
        ),
        Some(other) => Failure::new(
            FailureKind::TlsError,
            "The secure connection to the probe failed",
            other.to_string(),
            "Check that the address belongs to a PortGlass Probe of the same version.",
        ),
        None => Failure::new(
            FailureKind::NetworkInterrupted,
            format!("The connection to probe {} failed", entry.name),
            e.to_string(),
            "Check the network and try again.",
        ),
    }
}

async fn writer_task<W>(
    mut wr: W,
    mut rx: mpsc::Receiver<ControlRequest>,
    closed: CancellationToken,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        let req = tokio::select! {
            _ = closed.cancelled() => break,
            r = rx.recv() => match r { Some(r) => r, None => break },
        };
        if write_frame(&mut wr, &req).await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
    closed.cancel();
}

async fn reader_task<R>(
    mut rd: R,
    link: std::sync::Weak<ProbeLink>,
    closed: CancellationToken,
    reason: Arc<Mutex<Option<String>>>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let why = loop {
        let ev = tokio::select! {
            _ = closed.cancelled() => break "closed by controller".to_string(),
            r = read_frame::<_, ControlEvent>(&mut rd) => r,
        };
        let ev = match ev {
            Ok(ev) => ev,
            Err(FrameError::Closed) => break "the probe closed the control connection".into(),
            Err(e) => break format!("control connection error: {e}"),
        };
        let Some(link) = link.upgrade() else {
            break "controller released the link".into();
        };
        match &ev {
            ControlEvent::SessionOpened { request_id, .. }
            | ControlEvent::SessionRejected { request_id, .. } => {
                if let Some(tx) = link.pending.lock().unwrap().remove(request_id) {
                    let _ = tx.send(ev.clone());
                }
            }
            ControlEvent::Pong { nonce } => {
                if let Some(tx) = link.pings.lock().unwrap().remove(nonce) {
                    let _ = tx.send(());
                }
            }
            ControlEvent::Error { message, .. } => {
                *reason.lock().unwrap() = Some(format!("probe reported: {message}"));
            }
            _ => {}
        }
        let _ = link.events.send(ev);
    };
    {
        let mut r = reason.lock().unwrap();
        if r.is_none() {
            *r = Some(why);
        }
    }
    closed.cancel();
}

#[cfg(test)]
mod tests {
    #[test]
    fn probe_supplied_ids_must_be_exact_lowercase_hex() {
        use super::is_hex;
        assert!(is_hex(&"a1".repeat(16), 32));
        for bad in [
            "..\\..\\Documents",
            "C:\\x",
            &"A1".repeat(16),
            &"a1".repeat(17),
            "",
        ] {
            assert!(!is_hex(bad, 32), "{bad}");
        }
    }
}
