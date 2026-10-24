//! Real-browser end-to-end test. Needs Google Chrome; run with `cargo test -- --ignored`.
//!
//! Goes through the product's own browser launcher (isolated profile, resolver mapping, job
//! object, cleanup) and only adds headless + DevTools flags so the test can drive the page.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use portglass_controller::config::{ControllerConfig, ProbeEntry};
use portglass_controller::diag::SchemePref;
use portglass_controller::session::{ConnectRequest, Controller, Options, Phase};
use portglass_core::audit::AuditLog;
use portglass_core::identity::Identity;
use portglass_probe::config::{ProbeConfig, ProbeConfigFile};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

struct Cdp {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
}

impl Cdp {
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.ws
            .send(Message::text(
                json!({"id": id, "method": method, "params": params}).to_string(),
            ))
            .await
            .unwrap();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(20), self.ws.next())
                .await
                .expect("CDP reply timed out")
                .unwrap()
                .unwrap();
            let v: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
            if v["id"] == id {
                return v["result"].clone();
            }
        }
    }

    async fn eval(&mut self, expr: &str) -> Value {
        let r = self
            .call(
                "Runtime.evaluate",
                json!({"expression": expr, "returnByValue": true, "awaitPromise": true}),
            )
            .await;
        r["result"]["value"].clone()
    }

    async fn wait_eval(&mut self, expr: &str, want: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..100 {
            let v = self.eval(expr).await;
            if want(&v) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        panic!(
            "condition never held: {expr} (last value {:?})",
            self.eval(expr).await
        );
    }
}

async fn http_get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    // DevTools' HTTP endpoint keeps the connection open; read exactly Content-Length bytes.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().to_string())
                })
                .and_then(|v| v.parse::<usize>().ok());
            if len.is_some_and(|len| body.len() >= len) {
                return body.to_string();
            }
        }
    }
    String::from_utf8_lossy(&buf)
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Google Chrome"]
async fn real_browser_session_through_the_tunnel() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("portglass_controller=debug")
        .with_test_writer()
        .try_init();
    // The "device" lives at 127.0.0.2 so the browser's address bar shows something other than
    // the tunnel's own 127.0.0.1 endpoint.
    let mock_listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let mock = mock_listener.local_addr().unwrap();
    tokio::spawn(portglass_mock_target::serve_http(mock_listener));

    let dir = tempfile::tempdir().unwrap();
    let (probe_id, _, _) = Identity::generate("probe", "p").unwrap();
    let (ctl_id, _, _) = Identity::generate("controller", "alice").unwrap();
    let text = format!(
        "[probe]\nname='p'\nlisten='127.0.0.1:0'\n[[controller]]\nname='alice'\nfingerprint='{}'\n\
         [[allow]]\nnetwork='127.0.0.2/32'\nports=[{}]\n",
        ctl_id.fingerprint,
        mock.port()
    );
    let file: ProbeConfigFile = toml::from_str(&text).unwrap();
    let probe = portglass_probe::start(
        ProbeConfig::from_file(file, dir.path()).unwrap(),
        probe_id.clone(),
        Arc::new(AuditLog::disabled()),
    )
    .await
    .unwrap();

    let mut cfg: ControllerConfig = toml::from_str("operator='alice'").unwrap();
    cfg.probes = vec![ProbeEntry {
        name: "lab".into(),
        address: probe.addr.to_string(),
        fingerprint: probe_id.fingerprint,
    }];
    let ctrl = Controller::new(
        cfg,
        ctl_id,
        Arc::new(AuditLog::disabled()),
        Options {
            launch_browser: true,
            browser_extra_args: vec!["--headless=new".into(), "--remote-debugging-port=0".into()],
            ..Options::default()
        },
    );
    ctrl.connect(ConnectRequest {
        probe: "lab".into(),
        target: mock.to_string(),
        scheme: SchemePref::Auto,
        ttl_mins: Some(5),
    })
    .await
    .unwrap();
    let mut rx = ctrl.subscribe();
    let snap = loop {
        let s = rx.borrow_and_update().clone();
        if matches!(s.phase, Phase::Ready | Phase::Failed) {
            break s;
        }
        tokio::time::timeout(Duration::from_secs(30), rx.changed())
            .await
            .unwrap()
            .unwrap();
    };
    assert_eq!(snap.phase, Phase::Ready, "{:?}", snap.failure);
    let session = snap.session.unwrap();
    let browser = session.browser.expect("browser launched");
    assert_eq!(
        session.url.as_deref(),
        Some(format!("http://{mock}/").as_str())
    );

    // Isolated profile, not the technician's.
    let profile = std::path::PathBuf::from(&browser.profile_dir);
    assert!(profile.starts_with(portglass_controller::browser::sessions_root()));
    assert!(!browser
        .profile_dir
        .to_lowercase()
        .contains(r"google\chrome\user data"));

    // Attach over DevTools.
    let port_file = profile.join("DevToolsActivePort");
    let mut port = None;
    for _ in 0..100 {
        if let Ok(t) = std::fs::read_to_string(&port_file) {
            port = t.lines().next().and_then(|l| l.trim().parse::<u16>().ok());
            if port.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let port = port.expect("DevTools port");
    let mut page_ws = None;
    for _ in 0..50 {
        let list: Value =
            serde_json::from_str(&http_get(port, "/json/list").await).unwrap_or(Value::Null);
        page_ws = list
            .as_array()
            .and_then(|a| a.iter().find(|t| t["type"] == "page"))
            .and_then(|t| t["webSocketDebuggerUrl"].as_str().map(str::to_owned));
        if page_ws.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (ws, _) = tokio_tungstenite::connect_async(page_ws.expect("page target"))
        .await
        .unwrap();
    let mut cdp = Cdp { ws, next: 0 };

    // 1. The device's real page, at the device's own address (Host header preserved).
    let host = cdp
        .wait_eval(
            "document.getElementById('host') && document.getElementById('host').textContent",
            |v| v.is_string(),
        )
        .await;
    assert_eq!(host, json!(mock.to_string()));
    assert_eq!(cdp.eval("location.host").await, json!(mock.to_string()));

    // 2. JavaScript and a WebSocket upgrade over the same forwarded port.
    cdp.wait_eval("document.getElementById('wsstate').textContent", |v| {
        v == "open"
    })
    .await;
    cdp.wait_eval("document.getElementById('toner').textContent", |v| {
        v.as_str().is_some_and(|s| s.ends_with('%'))
    })
    .await;
    cdp.wait_eval("document.getElementById('echo').textContent", |v| {
        v == "echo:ping-from-page"
    })
    .await;

    // 3. A form submission (POST + redirect) and a reload.
    cdp.eval("document.getElementById('device_name').value = 'Edited Through PortGlass'; document.getElementById('save').click(); true").await;
    cdp.wait_eval("!!document.getElementById('saved')", |v| v == true)
        .await;
    cdp.eval("location.reload(); true").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    cdp.wait_eval(
        "document.getElementById('device_name') && document.getElementById('device_name').value",
        |v| v == "Edited Through PortGlass",
    )
    .await;

    // 4. Strict isolation: nothing but the forwarded endpoint is reachable from this browser.
    let outside = cdp
        .eval("fetch('http://example.com/', {mode: 'no-cors'}).then(() => 'reached').catch(() => 'blocked')")
        .await;
    assert_eq!(outside, json!("blocked"));
    let other_port = cdp
        .eval(&format!("fetch('http://{}:1/', {{mode: 'no-cors'}}).then(() => 'reached').catch(() => 'blocked')", mock.ip()))
        .await;
    assert_eq!(other_port, json!("blocked"));

    // Counters are published by a once-a-second sampler.
    let mut conns = 0;
    for _ in 0..30 {
        conns = ctrl.snapshot().session.map(|s| s.total_conns).unwrap_or(0);
        if conns >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        conns >= 3,
        "the browser's connections went through the tunnel ({conns})"
    );

    // 5. Ending the session closes the browser and deletes its profile.
    drop(cdp);
    ctrl.disconnect().await;
    let after = ctrl.snapshot();
    assert_eq!(
        after.phase,
        Phase::Disconnected,
        "{:?} {:?}",
        after.failure,
        after.timeline
    );
    for _ in 0..40 {
        if !profile.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(!profile.exists(), "session profile must be deleted");
    assert!(
        TcpStream::connect(("127.0.0.1", port)).await.is_err(),
        "browser must be gone"
    );
    probe.shutdown().await;
}
