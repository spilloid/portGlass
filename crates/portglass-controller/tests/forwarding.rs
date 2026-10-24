//! End-to-end tests: a real probe, a real controller and a mock device, all on loopback.
//! The browser is not launched here (see scripts/e2e-browser.ps1 for the real-browser check).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use portglass_controller::client::ProbeLink;
use portglass_controller::config::{ControllerConfig, ProbeEntry};
use portglass_controller::diag::SchemePref;
use portglass_controller::failure::FailureKind;
use portglass_controller::session::{ConnectRequest, Controller, Options, Phase, Snapshot};
use portglass_core::audit::AuditLog;
use portglass_core::identity::Identity;
use portglass_probe::config::{ProbeConfig, ProbeConfigFile};
use portglass_probe::ProbeHandle;
use portglass_proto::{ControlEvent, EndReason, ErrorCode, TargetSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Harness {
    probe: Option<ProbeHandle>,
    probe_id: Identity,
    ctl_id: Identity,
    entry: ProbeEntry,
    mock: std::net::SocketAddr,
    dir: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Harness {
        Harness::with_extra_allow("").await
    }

    async fn with_extra_allow(extra: &str) -> Harness {
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock = mock_listener.local_addr().unwrap();
        tokio::spawn(portglass_mock_target::serve_http(mock_listener));
        let (probe_id, _, _) = Identity::generate("probe", "test-probe").unwrap();
        let (ctl_id, _, _) = Identity::generate("controller", "alice").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cfg = probe_config(&ctl_id, &[mock.port()], extra, dir.path());
        let audit = Arc::new(AuditLog::open(&dir.path().join("probe-audit.jsonl")).unwrap());
        let probe = portglass_probe::start(cfg, probe_id.clone(), audit)
            .await
            .unwrap();
        let entry = ProbeEntry {
            name: "lab".into(),
            address: probe.addr.to_string(),
            fingerprint: probe_id.fingerprint,
        };
        Harness {
            probe: Some(probe),
            probe_id,
            ctl_id,
            entry,
            mock,
            dir,
        }
    }

    fn probe(&self) -> &ProbeHandle {
        self.probe.as_ref().unwrap()
    }

    fn controller_with(&self, identity: &Identity, entry: ProbeEntry) -> Arc<Controller> {
        let toml = format!(
            "operator = 'alice'\naudit_log = '{}'\n",
            self.dir
                .path()
                .join("controller-audit.jsonl")
                .display()
                .to_string()
                .replace('\\', "/")
        );
        let mut cfg: ControllerConfig = toml::from_str(&toml).unwrap();
        cfg.probes = vec![entry];
        let audit = Arc::new(AuditLog::open(&cfg.audit_log).unwrap());
        Controller::new(
            cfg,
            identity.clone(),
            audit,
            Options {
                launch_browser: false,
                ..Options::default()
            },
        )
    }

    fn controller(&self) -> Arc<Controller> {
        self.controller_with(&self.ctl_id, self.entry.clone())
    }

    fn audit_text(&self) -> String {
        let mut s = String::new();
        for f in ["probe-audit.jsonl", "controller-audit.jsonl"] {
            s.push_str(&std::fs::read_to_string(self.dir.path().join(f)).unwrap_or_default());
        }
        s
    }
}

fn probe_config(ctl: &Identity, ports: &[u16], extra: &str, dir: &std::path::Path) -> ProbeConfig {
    let ports: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    let text = format!(
        "[probe]\nname = 'test-probe'\nlisten = '127.0.0.1:0'\n\
         [limits]\nmax_session_ttl_secs = 600\nmax_streams_per_session = 16\ncontrol_timeout_secs = 10\n\
         [[controller]]\nname = 'alice'\nfingerprint = '{}'\n\
         [[allow]]\nnetwork = '127.0.0.1/32'\nports = [{}]\nlabel = 'mock device'\n{extra}",
        ctl.fingerprint,
        ports.join(", ")
    );
    let file: ProbeConfigFile = toml::from_str(&text).unwrap();
    ProbeConfig::from_file(file, dir).unwrap()
}

async fn wait_for(ctrl: &Controller, pred: impl Fn(&Snapshot) -> bool) -> Snapshot {
    let mut rx = ctrl.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let s = rx.borrow_and_update().clone();
        if pred(&s) {
            return s;
        }
        tokio::select! {
            r = rx.changed() => r.unwrap(),
            _ = tokio::time::sleep_until(deadline) => panic!("timed out; last phase {:?}, failure {:?}", s.phase, s.failure),
        }
    }
}

async fn connect_ready(ctrl: &Arc<Controller>, target: String) -> std::net::SocketAddr {
    ctrl.connect(ConnectRequest {
        probe: "lab".into(),
        target,
        scheme: SchemePref::Auto,
        ttl_mins: Some(5),
    })
    .await
    .unwrap();
    let s = wait_for(ctrl, |s| matches!(s.phase, Phase::Ready | Phase::Failed)).await;
    assert_eq!(s.phase, Phase::Ready, "failure: {:?}", s.failure);
    s.session.unwrap().local_addr.unwrap().parse().unwrap()
}

/// Minimal HTTP/1.1 client with `Connection: close`. Returns (status line + headers, body).
async fn http(
    addr: std::net::SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    (head, buf[split + 4..].to_vec())
}

#[tokio::test(flavor = "multi_thread")]
async fn http_forms_cookies_and_reload_through_the_tunnel() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    let local = connect_ready(&ctrl, format!("127.0.0.1:{}", h.mock.port())).await;
    let host = format!("127.0.0.1:{}", h.mock.port());

    let (head, body) = http(local, &host, "GET", "/", None).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = String::from_utf8_lossy(&body);
    assert!(page.contains("MockJet 9000"));
    assert!(
        page.contains(&format!("<code id=\"host\">{host}</code>")),
        "Host header passes through unchanged"
    );

    let (head, _) = http(
        local,
        &host,
        "POST",
        "/settings",
        Some("device_name=Lab+Printer&location=Room+2&tray=A4"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 303"), "{head}");
    let (_, body) = http(local, &host, "GET", "/?saved=1", None).await;
    let page = String::from_utf8_lossy(&body);
    assert!(
        page.contains("value=\"Lab Printer\"") && page.contains("<option selected>A4</option>")
    );
    assert!(page.contains("Settings saved."));

    let (head, _) = http(
        local,
        &host,
        "POST",
        "/login",
        Some("user=admin&password=SECRET-PASSWORD-123"),
    )
    .await;
    assert!(head
        .to_ascii_lowercase()
        .contains("set-cookie: mock_session=ok"));

    let (_, js) = http(local, &host, "GET", "/app.js", None).await;
    assert!(String::from_utf8_lossy(&js).contains("new WebSocket"));

    let s = wait_for(&ctrl, |s| {
        s.session.as_ref().is_some_and(|v| v.total_conns >= 5)
    })
    .await;
    let v = s.session.unwrap();
    assert!(v.bytes_down > 0 && v.bytes_up > 0);
    assert!(
        v.diagnostics
            .iter()
            .any(|d| d.title.contains("answered (200)")),
        "{:?}",
        v.diagnostics
    );
    ctrl.disconnect().await;

    let audit = h.audit_text();
    assert!(audit.contains("session_opened") && audit.contains("session_ended"));
    assert!(
        !audit.contains("SECRET-PASSWORD-123"),
        "credentials must never reach the audit log"
    );
    assert!(
        !audit.contains("Lab Printer"),
        "payload must never reach the audit log"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_upgrade_and_bidirectional_frames() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    let local = connect_ready(&ctrl, format!("127.0.0.1:{}", h.mock.port())).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{local}/ws"))
        .await
        .unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::text(
        "hello-through-portglass",
    ))
    .await
    .unwrap();
    let mut saw_echo = false;
    let mut saw_push = false;
    for _ in 0..20 {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = msg.to_text().unwrap().to_string();
        saw_echo |= text == "echo:hello-through-portglass";
        saw_push |= text.starts_with("toner:");
        if saw_echo && saw_push {
            break;
        }
    }
    assert!(saw_echo && saw_push);
    ctrl.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_binary_downloads_are_byte_exact() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    let local = connect_ready(&ctrl, format!("127.0.0.1:{}", h.mock.port())).await;
    let host = format!("127.0.0.1:{}", h.mock.port());
    let n = 3 * 1024 * 1024 + 17;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let host = host.clone();
        tasks.push(tokio::spawn(async move {
            let (head, body) = http(local, &host, "GET", &format!("/big?bytes={n}"), None).await;
            assert!(head.starts_with("HTTP/1.1 200"));
            assert_eq!(body.len(), n);
            assert!(
                body.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8),
                "corrupted bytes"
            );
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let s = wait_for(&ctrl, |s| {
        s.session
            .as_ref()
            .is_some_and(|v| v.bytes_down >= 8 * n as u64)
    })
    .await;
    assert!(s.session.unwrap().total_conns >= 8);
    ctrl.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn half_closed_connections_still_deliver_the_reply() {
    // A target that reads until EOF, then answers. Only works if the client's half-close is
    // propagated through both TLS legs while the reverse direction stays open.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.unwrap();
                s.write_all(format!("got {} bytes", buf.len()).as_bytes())
                    .await
                    .unwrap();
                s.shutdown().await.unwrap();
            });
        }
    });
    let h = Harness::with_extra_allow(&format!(
        "[[allow]]\nnetwork = '127.0.0.1'\nports = [{port}]\n"
    ))
    .await;
    let ctrl = h.controller();
    let local = connect_ready(&ctrl, format!("127.0.0.1:{port}")).await;
    let mut s = TcpStream::connect(local).await.unwrap();
    s.write_all(&vec![1u8; 100_000]).await.unwrap();
    s.shutdown().await.unwrap();
    let mut reply = String::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, "got 100000 bytes");
    ctrl.disconnect().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_target_is_rejected_by_the_probe() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    // Same host, different port: not in the allowlist.
    let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = other.local_addr().unwrap().port();
    ctrl.connect(ConnectRequest {
        probe: "lab".into(),
        target: format!("127.0.0.1:{port}"),
        scheme: SchemePref::Http,
        ttl_mins: None,
    })
    .await
    .unwrap();
    let s = wait_for(&ctrl, |s| s.phase == Phase::Failed).await;
    assert_eq!(s.failure.unwrap().kind, FailureKind::UnauthorizedTarget);

    // And directly at the protocol level, bypassing the controller's UI entirely.
    let link = ProbeLink::connect(&h.entry, &h.ctl_id, "test")
        .await
        .unwrap();
    for host in ["10.0.0.1", "169.254.169.254", "0.0.0.0", "localhost"] {
        let err = link
            .open_session(
                &TargetSpec {
                    host: host.into(),
                    port: 80,
                },
                60,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind, FailureKind::UnauthorizedTarget, "{host}: {err:?}");
    }
    assert!(h.audit_text().contains("session_denied"));
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_need_the_right_session_token_and_end_with_the_session() {
    let h = Harness::new().await;
    let link = ProbeLink::connect(&h.entry, &h.ctl_id, "test")
        .await
        .unwrap();
    let grant = link
        .open_session(
            &TargetSpec {
                host: "127.0.0.1".into(),
                port: h.mock.port(),
            },
            60,
        )
        .await
        .unwrap();
    let wrong = hex::encode([7u8; 32]);
    let (code, _) = link
        .open_stream(&grant.session_id, &wrong)
        .await
        .unwrap_err();
    assert_eq!(code, Some(ErrorCode::SessionNotFound));
    let (code, _) = link
        .open_stream("not-a-session", &grant.stream_token)
        .await
        .unwrap_err();
    assert_eq!(code, Some(ErrorCode::SessionNotFound));

    let mut stream = link
        .open_stream(&grant.session_id, &grant.stream_token)
        .await
        .unwrap();
    link.close_session(&grant.session_id).await;
    // The open stream is cut...
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "stream must be closed when its session ends");
    // ...and the token is dead.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(link
        .open_stream(&grant.session_id, &grant.stream_token)
        .await
        .is_err());
    assert_eq!(h.probe().active_sessions(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn ending_the_session_terminates_the_tunnel() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    let local = connect_ready(&ctrl, format!("127.0.0.1:{}", h.mock.port())).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{local}/ws"))
        .await
        .unwrap();
    assert!(ws.next().await.is_some());
    assert_eq!(h.probe().active_sessions(), 1);

    ctrl.disconnect().await;
    let s = ctrl.snapshot();
    assert_eq!(s.phase, Phase::Disconnected);
    assert!(s.ended);
    // The long-lived WebSocket is cut.
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) => return,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "open connections must be terminated");
    // The local port no longer accepts.
    assert!(
        TcpStream::connect(local).await.is_err(),
        "local listener must be gone"
    );
    // The probe has forgotten the session.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.probe().active_sessions(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_expire_on_the_probe() {
    let h = Harness::new().await;
    let link = ProbeLink::connect(&h.entry, &h.ctl_id, "test")
        .await
        .unwrap();
    let mut events = link.subscribe();
    let grant = link
        .open_session(
            &TargetSpec {
                host: "127.0.0.1".into(),
                port: h.mock.port(),
            },
            1,
        )
        .await
        .unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(ControlEvent::SessionEnded { session_id, reason }) = events.recv().await {
                if session_id == grant.session_id {
                    return reason;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(ended, EndReason::Expired);
    let (code, _) = link
        .open_stream(&grant.session_id, &grant.stream_token)
        .await
        .unwrap_err();
    assert_eq!(code, Some(ErrorCode::SessionNotFound));
}

#[tokio::test(flavor = "multi_thread")]
async fn administrator_revocation_ends_the_session_immediately() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    connect_ready(&ctrl, format!("127.0.0.1:{}", h.mock.port())).await;
    // The administrator removes the allow rule.
    let cfg = probe_config(&h.ctl_id, &[1], "", h.dir.path());
    h.probe().apply_config(cfg);
    let s = wait_for(&ctrl, |s| s.phase == Phase::Failed).await;
    assert_eq!(s.failure.unwrap().kind, FailureKind::SessionRevoked);
    assert_eq!(h.probe().active_sessions(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_controller_disconnects_it() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    connect_ready(&ctrl, format!("127.0.0.1:{}", h.mock.port())).await;
    let (other, _, _) = Identity::generate("controller", "bob").unwrap();
    let cfg = probe_config(&other, &[h.mock.port()], "", h.dir.path());
    h.probe().apply_config(cfg);
    let s = wait_for(&ctrl, |s| s.phase == Phase::Failed).await;
    assert!(matches!(
        s.failure.unwrap().kind,
        FailureKind::SessionRevoked | FailureKind::NetworkInterrupted
    ));
    // And it cannot authenticate again.
    let err = ProbeLink::connect(&h.entry, &h.ctl_id, "test")
        .await
        .err()
        .expect("must be refused");
    assert_eq!(err.kind, FailureKind::AuthFailed);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_controllers_and_impostor_probes_are_refused() {
    let h = Harness::new().await;
    let (stranger, _, _) = Identity::generate("controller", "mallory").unwrap();
    let ctrl = h.controller_with(&stranger, h.entry.clone());
    ctrl.connect(ConnectRequest {
        probe: "lab".into(),
        target: format!("127.0.0.1:{}", h.mock.port()),
        scheme: SchemePref::Http,
        ttl_mins: None,
    })
    .await
    .unwrap();
    let s = wait_for(&ctrl, |s| s.phase == Phase::Failed).await;
    let f = s.failure.unwrap();
    assert_eq!(f.kind, FailureKind::AuthFailed);
    assert!(
        f.hint.contains(&stranger.fingerprint.to_string()),
        "hint tells the admin what to authorize: {}",
        f.hint
    );

    let (impostor, _, _) = Identity::generate("probe", "impostor").unwrap();
    let mut pinned_wrong = h.entry.clone();
    pinned_wrong.fingerprint = impostor.fingerprint;
    let err = ProbeLink::connect(&pinned_wrong, &h.ctl_id, "test")
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind, FailureKind::AuthFailed);
    assert!(err.title.contains("wrong identity"), "{}", err.title);
    let _ = &h.probe_id;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_commands_are_rejected_and_audited() {
    use portglass_core::tls;
    let h = Harness::new().await;
    let cfg = tls::client_config(
        &h.ctl_id,
        h.probe_id.fingerprint,
        portglass_proto::ALPN_CONTROL,
    )
    .unwrap();
    let tcp = TcpStream::connect(h.probe().addr).await.unwrap();
    let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(tls::server_name(), tcp)
        .await
        .unwrap();
    portglass_proto::write_frame(
        &mut s,
        &serde_json::json!({"type":"hello","protocol":1,"client_version":"x","operator_hint":"x"}),
    )
    .await
    .unwrap();
    let _: ControlEvent = portglass_proto::read_frame(&mut s).await.unwrap();
    portglass_proto::write_frame(
        &mut s,
        &serde_json::json!({"type":"exec","command":"cmd.exe /c whoami"}),
    )
    .await
    .unwrap();
    let reply: ControlEvent = portglass_proto::read_frame(&mut s).await.unwrap();
    assert!(
        matches!(
            reply,
            ControlEvent::Error {
                code: ErrorCode::Unsupported,
                ..
            }
        ),
        "{reply:?}"
    );
    let next = portglass_proto::read_frame::<_, ControlEvent>(&mut s).await;
    assert!(
        next.is_err(),
        "the probe closes the connection after an unsupported command"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(h.audit_text().contains("command_rejected"));
}

#[tokio::test(flavor = "multi_thread")]
async fn losing_the_control_connection_revokes_sessions() {
    let h = Harness::new().await;
    let link = ProbeLink::connect(&h.entry, &h.ctl_id, "test")
        .await
        .unwrap();
    let grant = link
        .open_session(
            &TargetSpec {
                host: "127.0.0.1".into(),
                port: h.mock.port(),
            },
            600,
        )
        .await
        .unwrap();
    let mut stream = link
        .open_stream(&grant.session_id, &grant.stream_token)
        .await
        .unwrap();
    assert_eq!(h.probe().active_sessions(), 1);
    link.shutdown();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.probe().active_sessions(), 0);
    assert!(h.audit_text().contains("controller_disconnected"));
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_shutdown_is_reported_as_probe_terminated() {
    let mut h = Harness::new().await;
    let ctrl = h.controller();
    connect_ready(&ctrl, format!("127.0.0.1:{}", h.mock.port())).await;
    h.probe.take().unwrap().shutdown().await;
    let s = wait_for(&ctrl, |s| s.phase == Phase::Failed).await;
    assert!(matches!(
        s.failure.unwrap().kind,
        FailureKind::ProbeTerminated | FailureKind::NetworkInterrupted
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_probe_and_refused_target_are_distinguished() {
    let h = Harness::new().await;
    let mut gone = h.entry.clone();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    gone.address = l.local_addr().unwrap().to_string();
    drop(l);
    let err = ProbeLink::connect(&gone, &h.ctl_id, "t")
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind, FailureKind::ProbeUnreachable);

    // An allowed port with nothing listening.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap().port();
    drop(l);
    let h2 = Harness::with_extra_allow(&format!(
        "[[allow]]\nnetwork = '127.0.0.1'\nports = [{dead}]\n"
    ))
    .await;
    let link = ProbeLink::connect(&h2.entry, &h2.ctl_id, "t")
        .await
        .unwrap();
    let err = link
        .open_session(
            &TargetSpec {
                host: "127.0.0.1".into(),
                port: dead,
            },
            60,
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind, FailureKind::ConnectionRefused);
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_server_refuses_foreign_hosts_origins_and_missing_tokens() {
    let h = Harness::new().await;
    let ctrl = h.controller();
    let server = portglass_controller::ui::serve(ctrl).await.unwrap();
    let token = server.url.split("t=").nth(1).unwrap().to_string();
    let addr = server.addr;
    let raw = |req: String| async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out.lines().next().unwrap_or_default().to_string()
    };
    let ok = raw(format!("GET /api/state HTTP/1.1\r\nHost: {addr}\r\nx-portglass-token: {token}\r\nConnection: close\r\n\r\n")).await;
    assert!(ok.contains("200"), "{ok}");
    let no_token = raw(format!(
        "GET /api/state HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    ))
    .await;
    assert!(no_token.contains("401"), "{no_token}");
    let rebinding = raw(format!("GET /api/state HTTP/1.1\r\nHost: evil.example:{}\r\nx-portglass-token: {token}\r\nConnection: close\r\n\r\n", addr.port())).await;
    assert!(rebinding.contains("421"), "{rebinding}");
    let cross = raw(format!(
        "POST /api/disconnect HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://evil.example\r\nx-portglass-token: {token}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    ))
    .await;
    assert!(cross.contains("403"), "{cross}");
    let form = raw(format!(
        "POST /api/disconnect HTTP/1.1\r\nHost: {addr}\r\nx-portglass-token: {token}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    ))
    .await;
    assert!(form.contains("415"), "{form}");
}

#[allow(dead_code)]
fn unused(_: PathBuf) {}
