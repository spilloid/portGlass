//! A pretend printer web interface for exercising PortGlass end to end: HTML, a script, a form
//! that saves settings, a cookie login, a WebSocket (echo plus pushed status), a large binary
//! download, and redirects. Optionally HTTPS with a throwaway self-signed certificate.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Default)]
struct AppState {
    settings: Arc<Mutex<Settings>>,
}

#[derive(Clone, Deserialize)]
struct Settings {
    device_name: String,
    location: String,
    tray: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            device_name: "Front Office Printer".into(),
            location: "Reception".into(),
            tray: "Letter".into(),
        }
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/settings", post(save_settings))
        .route("/login", post(login))
        .route("/api/status", get(status))
        .route("/ws", get(ws))
        .route("/big", get(big))
        .route("/to-https", get(to_https))
        .with_state(AppState::default())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn index(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Html<String> {
    let s = st.settings.lock().unwrap().clone();
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("?")
        .to_string();
    let signed_in = headers
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .is_some_and(|c| c.contains("mock_session=ok"));
    let saved = if q.contains_key("saved") {
        r#"<p id="saved" class="ok">Settings saved.</p>"#
    } else {
        ""
    };
    Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>{name} — Mock Printer</title>
<style>body{{font:15px system-ui;margin:0;background:#f3f4f6;color:#111}}header{{background:#203a5c;color:#fff;padding:14px 20px}}
main{{padding:20px;max-width:720px}}fieldset{{border:1px solid #ccc;border-radius:8px;margin:0 0 16px;background:#fff}}
label{{display:block;margin:8px 0}}input,select{{font:inherit;padding:4px}}.ok{{color:#0a7a3a}}code{{background:#e5e7eb;padding:1px 4px}}</style></head>
<body><header><b>MockJet 9000</b> · device web interface</header><main>
<p>Request Host header: <code id="host">{host}</code> · Signed in: <code id="signed">{signed}</code></p>
{saved}
<fieldset><legend>Device settings</legend>
<form method="post" action="/settings">
<label>Device name <input name="device_name" id="device_name" value="{name}"></label>
<label>Location <input name="location" id="location" value="{location}"></label>
<label>Paper tray <select name="tray" id="tray">{trays}</select></label>
<button type="submit" id="save">Save</button></form></fieldset>
<fieldset><legend>Sign in</legend><form method="post" action="/login"><input name="user" value="admin"> <input type="password" name="password"> <button id="signin">Sign in</button></form></fieldset>
<fieldset><legend>Live status</legend>
<p>Toner: <b id="toner">…</b> · Pages: <b id="pages">…</b> · WebSocket: <b id="wsstate">connecting</b></p>
<p>Echo test: <b id="echo">…</b></p></fieldset>
<script src="/app.js"></script></main></body></html>"#,
        name = esc(&s.device_name),
        location = esc(&s.location),
        signed = signed_in,
        trays = ["Letter", "A4", "Legal"]
            .iter()
            .map(|t| format!(
                "<option{}>{t}</option>",
                if *t == s.tray { " selected" } else { "" }
            ))
            .collect::<String>(),
    ))
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        r#"(function(){
  fetch('/api/status').then(r=>r.json()).then(s=>{document.getElementById('pages').textContent=s.pages;});
  var proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
  var ws = new WebSocket(proto + location.host + '/ws');
  ws.onopen = function(){ document.getElementById('wsstate').textContent='open'; ws.send('ping-from-page'); };
  ws.onmessage = function(e){
    if (e.data.indexOf('toner:') === 0) document.getElementById('toner').textContent = e.data.slice(6) + '%';
    else document.getElementById('echo').textContent = e.data;
  };
  ws.onclose = function(){ document.getElementById('wsstate').textContent='closed'; };
})();"#,
    )
}

async fn save_settings(State(st): State<AppState>, Form(s): Form<Settings>) -> Redirect {
    *st.settings.lock().unwrap() = s;
    Redirect::to("/?saved=1")
}

#[derive(Deserialize)]
struct LoginForm {
    #[allow(dead_code)]
    user: String,
    #[allow(dead_code)]
    password: String,
}

async fn login(Form(_f): Form<LoginForm>) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/"),
            (header::SET_COOKIE, "mock_session=ok; Path=/; HttpOnly"),
        ],
    )
        .into_response()
}

async fn status(State(st): State<AppState>) -> Json<serde_json::Value> {
    let s = st.settings.lock().unwrap().clone();
    Json(serde_json::json!({ "device_name": s.device_name, "pages": 48213, "tray": s.tray }))
}

async fn ws(up: WebSocketUpgrade) -> Response {
    up.on_upgrade(handle_ws)
}

async fn handle_ws(mut socket: WebSocket) {
    let mut tick = tokio::time::interval(Duration::from_millis(700));
    let mut toner = 82u32;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                toner = if toner <= 20 { 82 } else { toner - 1 };
                if socket.send(Message::Text(format!("toner:{toner}").into())).await.is_err() { return; }
            }
            m = socket.recv() => match m {
                Some(Ok(Message::Text(t))) => {
                    if socket.send(Message::Text(format!("echo:{t}").into())).await.is_err() { return; }
                }
                Some(Ok(Message::Binary(b))) => {
                    if socket.send(Message::Binary(b)).await.is_err() { return; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            }
        }
    }
}

#[derive(Deserialize)]
struct BigQuery {
    bytes: Option<usize>,
}

/// Deterministic bytes (`i % 251`) so a test can verify every byte.
async fn big(Query(q): Query<BigQuery>) -> impl IntoResponse {
    let n = q.bytes.unwrap_or(8 << 20).min(256 << 20);
    let body: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    ([(header::CONTENT_TYPE, "application/octet-stream")], body)
}

async fn to_https(headers: HeaderMap) -> Redirect {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let host = host.split(':').next().unwrap_or(host);
    Redirect::temporary(&format!("https://{host}/"))
}

/// Serve plain HTTP on `listener` until the task is dropped.
pub async fn serve_http(listener: TcpListener) -> std::io::Result<()> {
    axum::serve(listener, router()).await
}

/// A TLS acceptor with a fresh self-signed certificate for `names`.
pub fn https_acceptor(names: Vec<String>) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let cert = rcgen::generate_simple_self_signed(names)?;
    let der = cert.cert.der().to_vec();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!(e))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![der.into()], key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

pub struct TlsListener {
    inner: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    pub fn new(inner: TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        TlsListener { inner, acceptor }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((tcp, addr)) = self.inner.accept().await else {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            };
            if let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(10), self.acceptor.accept(tcp)).await
            {
                return (tls, addr);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

pub async fn serve_https(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> std::io::Result<()> {
    axum::serve(TlsListener::new(listener, acceptor), router()).await
}
