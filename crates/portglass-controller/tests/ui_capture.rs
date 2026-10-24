//! STD-008 UI capture & validation for the controller window. Needs Google Chrome; run with
//! `cargo test -p portglass-controller --test ui_capture -- --ignored`.
//!
//! Renders every state of the window (idle, connected, failed, ended) in both color schemes at
//! the minimum window, a laptop window, and a phone-width viewport, and fails on horizontal
//! overflow, any browser error, or a status light whose settled color disagrees with the state.
//! Screenshots go to `target/ui-capture/`; with `PORTGLASS_PUBLISH_SCREENSHOTS=1` the dark-theme
//! minimum-window shots are also copied to `docs/img/` for the README and site.

use std::path::PathBuf;
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

const SIZES: [(u32, u32, &str); 3] = [
    (500, 940, "min"),
    (1280, 800, "laptop"),
    (390, 844, "narrow"),
];
const THEMES: [&str; 2] = ["dark", "light"];

struct Cdp {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    next: u64,
    errors: Vec<String>,
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
                .expect("CDP timeout")
                .unwrap()
                .unwrap();
            let v: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
            match v["method"].as_str() {
                Some("Runtime.exceptionThrown") => self
                    .errors
                    .push(v["params"]["exceptionDetails"].to_string()),
                Some("Runtime.consoleAPICalled") if v["params"]["type"] == "error" => {
                    self.errors.push(v["params"]["args"].to_string())
                }
                Some("Log.entryAdded") if v["params"]["entry"]["level"] == "error" => {
                    self.errors.push(v["params"]["entry"]["text"].to_string())
                }
                _ => {}
            }
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
}

async fn http_json(port: u16, path: &str) -> Value {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().to_owned())
                })
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(usize::MAX);
            if body.len() >= len || n == 0 {
                return serde_json::from_str(body).unwrap_or(Value::Null);
            }
        }
    }
}

async fn wait_phase(ctrl: &Controller, want: Phase) {
    let mut rx = ctrl.subscribe();
    loop {
        if rx.borrow_and_update().phase == want {
            return;
        }
        tokio::time::timeout(Duration::from_secs(30), rx.changed())
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Google Chrome"]
async fn controller_window_renders_cleanly_in_every_state() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/ui-capture");
    std::fs::create_dir_all(&out_dir).unwrap();
    let publish = std::env::var("PORTGLASS_PUBLISH_SCREENSHOTS").as_deref() == Ok("1");
    let docs_img = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/img");

    // A probe with a mock printer behind it.
    let mock_listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let mock = mock_listener.local_addr().unwrap();
    tokio::spawn(portglass_mock_target::serve_http(mock_listener));
    let dir = tempfile::tempdir().unwrap();
    let (probe_id, _, _) = Identity::generate("probe", "p").unwrap();
    let (ctl_id, _, _) = Identity::generate("controller", "alice").unwrap();
    let text = format!(
        "[probe]\nname='front-office'\nlisten='127.0.0.1:0'\n[[controller]]\nname='alice'\nfingerprint='{}'\n\
         [[allow]]\nnetwork='127.0.0.2/32'\nports=[{}]\nlabel='Front office printer'\n",
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
    cfg.probes = vec![
        ProbeEntry {
            name: "front-office".into(),
            address: probe.addr.to_string(),
            fingerprint: probe_id.fingerprint,
        },
        ProbeEntry {
            name: "warehouse".into(),
            address: "127.0.0.1:9".into(),
            fingerprint: probe_id.fingerprint,
        },
    ];
    let ctrl = Controller::new(
        cfg,
        ctl_id,
        Arc::new(AuditLog::disabled()),
        Options {
            launch_browser: false,
            ..Options::default()
        },
    );
    ctrl.check_probes().await;
    let server = portglass_controller::ui::serve(ctrl.clone()).await.unwrap();

    // A headless Chrome to look at it.
    let chrome =
        portglass_controller::browser::find_chrome(&Default::default()).expect("Google Chrome");
    let profile = tempfile::tempdir().unwrap();
    let mut child = tokio::process::Command::new(chrome)
        .arg("--headless=new")
        .arg("--remote-debugging-port=0")
        .arg("--hide-scrollbars")
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut port = None;
    for _ in 0..100 {
        if let Ok(t) = std::fs::read_to_string(profile.path().join("DevToolsActivePort")) {
            port = t.lines().next().and_then(|l| l.trim().parse::<u16>().ok());
            if port.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let port = port.expect("DevTools port");
    let mut ws_url = None;
    for _ in 0..50 {
        ws_url = http_json(port, "/json/list")
            .await
            .as_array()
            .and_then(|a| a.iter().find(|t| t["type"] == "page").cloned())
            .and_then(|t| t["webSocketDebuggerUrl"].as_str().map(str::to_owned));
        if ws_url.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (ws, _) = tokio_tungstenite::connect_async(ws_url.unwrap())
        .await
        .unwrap();
    let mut cdp = Cdp {
        ws,
        next: 0,
        errors: Vec::new(),
    };
    cdp.call("Runtime.enable", json!({})).await;
    cdp.call("Log.enable", json!({})).await;
    cdp.call("Page.enable", json!({})).await;
    let mut failures = Vec::new();

    let target = format!("{mock}");
    // First run: no probes yet, the setup card is the whole window.
    {
        let (fresh_id, _, _) = Identity::generate("controller", "new").unwrap();
        let fresh_cfg: ControllerConfig = toml::from_str("operator='new'").unwrap();
        let fresh = Controller::new(
            fresh_cfg,
            fresh_id,
            Arc::new(AuditLog::disabled()),
            Options {
                launch_browser: false,
                ..Options::default()
            },
        );
        let fresh_server = portglass_controller::ui::serve(fresh).await.unwrap();
        for theme in THEMES {
            for (w, h, size) in SIZES {
                cdp.call(
                    "Emulation.setDeviceMetricsOverride",
                    json!({"width": w, "height": h, "deviceScaleFactor": 1, "mobile": false}),
                )
                .await;
                cdp.call(
                    "Emulation.setEmulatedMedia",
                    json!({"features": [{"name": "prefers-color-scheme", "value": theme}]}),
                )
                .await;
                cdp.call("Page.navigate", json!({"url": fresh_server.url}))
                    .await;
                let mut shown = false;
                for _ in 0..60 {
                    if cdp.eval("!!document.getElementById('setupCard') && !document.getElementById('setupCard').hidden && document.getElementById('formCard').hidden && document.getElementById('myFp').textContent.startsWith('sha256:')").await == json!(true) {
                        shown = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let tag = format!("firstrun-{theme}-{size}");
                if !shown {
                    failures.push(format!("{tag}: setup card not shown"));
                    continue;
                }
                tokio::time::sleep(Duration::from_millis(600)).await;
                let overflow = cdp.eval("document.documentElement.scrollWidth - document.documentElement.clientWidth").await;
                if overflow.as_i64().unwrap_or(1) > 0 {
                    failures.push(format!("{tag}: page scrolls sideways by {overflow}px"));
                }
                let shot = cdp
                    .call(
                        "Page.captureScreenshot",
                        json!({"format": "png", "captureBeyondViewport": true}),
                    )
                    .await;
                let png = decode_base64(shot["data"].as_str().unwrap());
                std::fs::write(out_dir.join(format!("{tag}.png")), &png).unwrap();
                if publish && size == "min" {
                    std::fs::create_dir_all(&docs_img).unwrap();
                    std::fs::write(
                        docs_img.join(format!("controller-firstrun-{theme}.png")),
                        &png,
                    )
                    .unwrap();
                }
            }
        }
    }

    for state in ["idle", "connected", "failed", "ended"] {
        let expect = match state {
            "idle" => "red",
            "connected" => {
                ctrl.connect(ConnectRequest {
                    probe: "front-office".into(),
                    target: target.clone(),
                    scheme: SchemePref::Auto,
                    ttl_mins: Some(60),
                })
                .await
                .unwrap();
                wait_phase(&ctrl, Phase::Ready).await;
                // Let a little traffic flow so the throughput graph has something on it.
                for _ in 0..6 {
                    let local = ctrl.snapshot().session.unwrap().local_addr.unwrap();
                    if let Ok(mut s) = TcpStream::connect(&local).await {
                        let _ = s.write_all(format!("GET /big?bytes=400000 HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).await;
                        let mut sink = Vec::new();
                        let _ = s.read_to_end(&mut sink).await;
                    }
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                "green"
            }
            "failed" => {
                ctrl.disconnect().await;
                ctrl.connect(ConnectRequest {
                    probe: "front-office".into(),
                    target: "10.20.30.40:80".into(),
                    scheme: SchemePref::Auto,
                    ttl_mins: None,
                })
                .await
                .unwrap();
                wait_phase(&ctrl, Phase::Failed).await;
                "red"
            }
            _ => {
                ctrl.connect(ConnectRequest {
                    probe: "front-office".into(),
                    target: target.clone(),
                    scheme: SchemePref::Auto,
                    ttl_mins: Some(60),
                })
                .await
                .unwrap();
                wait_phase(&ctrl, Phase::Ready).await;
                ctrl.disconnect().await;
                "gray"
            }
        };
        for theme in THEMES {
            for (w, h, size) in SIZES {
                cdp.call(
                    "Emulation.setDeviceMetricsOverride",
                    json!({"width": w, "height": h, "deviceScaleFactor": 1, "mobile": false}),
                )
                .await;
                cdp.call(
                    "Emulation.setEmulatedMedia",
                    json!({"features": [{"name": "prefers-color-scheme", "value": theme}]}),
                )
                .await;
                cdp.call("Page.navigate", json!({"url": server.url})).await;
                let mut ready = false;
                for _ in 0..60 {
                    let v = cdp.eval("document.getElementById('hero') ? document.getElementById('hero').dataset.ind + '|' + document.getElementById('headline').textContent : ''").await;
                    if v.as_str()
                        .is_some_and(|s| s.starts_with(&format!("{expect}|")) && !s.ends_with('|'))
                    {
                        ready = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let tag = format!("{state}-{theme}-{size}");
                if !ready {
                    failures.push(format!("{tag}: indicator never became {expect}"));
                    continue;
                }
                // Let transitions settle before judging colors.
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let check = cdp
                    .eval(&format!(
                        "(() => {{
                            const probe = document.createElement('div');
                            probe.style.color = 'var(--{expect})'; document.body.appendChild(probe);
                            const want = getComputedStyle(probe).color; probe.remove();
                            const orb = getComputedStyle(document.querySelector('.orb')).backgroundColor;
                            const overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
                            const clipped = [...document.querySelectorAll('button, .chip, .headline, .metric, .probe, .diag')]
                              .filter(e => e.offsetParent && e.getBoundingClientRect().right > document.documentElement.clientWidth + 1)
                              .map(e => e.className || e.tagName);
                            return {{ want, orb, overflow, clipped }};
                        }})()"
                    ))
                    .await;
                if check["overflow"].as_i64().unwrap_or(1) > 0 {
                    failures.push(format!(
                        "{tag}: page scrolls sideways by {}px",
                        check["overflow"]
                    ));
                }
                if check["clipped"].as_array().is_some_and(|a| !a.is_empty()) {
                    failures.push(format!(
                        "{tag}: elements past the right edge: {}",
                        check["clipped"]
                    ));
                }
                if check["orb"] != check["want"] {
                    failures.push(format!(
                        "{tag}: status light is {} but {expect} is {}",
                        check["orb"], check["want"]
                    ));
                }
                let shot = cdp
                    .call(
                        "Page.captureScreenshot",
                        json!({"format": "png", "captureBeyondViewport": true}),
                    )
                    .await;
                let png = decode_base64(shot["data"].as_str().unwrap());
                std::fs::write(out_dir.join(format!("{tag}.png")), &png).unwrap();
                if publish && size == "min" {
                    std::fs::create_dir_all(&docs_img).unwrap();
                    std::fs::write(
                        docs_img.join(format!("controller-{state}-{theme}.png")),
                        &png,
                    )
                    .unwrap();
                }
            }
        }
    }
    ctrl.disconnect().await;
    let _ = child.kill().await;
    assert!(cdp.errors.is_empty(), "browser errors: {:#?}", cdp.errors);
    assert!(
        failures.is_empty(),
        "UI validation failed:\n{}",
        failures.join("\n")
    );
}

fn decode_base64(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, c) in T.iter().enumerate() {
        map[*c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in s.bytes().filter(|b| *b != b'=') {
        acc = (acc << 6) | map[b as usize] as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
