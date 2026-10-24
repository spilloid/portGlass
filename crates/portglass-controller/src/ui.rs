//! The controller's window: a small local web app shown in a Chrome app window.
//!
//! Bound to 127.0.0.1 only. Every request must carry the per-launch random token, and the Host
//! header must be exactly this listener's address (which defeats DNS-rebinding pages); state
//! changes additionally require a JSON body and a same-origin `Origin` when one is sent.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use tokio_stream::wrappers::WatchStream;

use crate::session::{ConnectRequest, Controller};

const INDEX: &str = include_str!("ui/index.html");

#[derive(Clone)]
struct App {
    ctrl: Arc<Controller>,
    token: String,
    host: String,
}

pub struct UiServer {
    pub addr: SocketAddr,
    pub url: String,
}

pub async fn serve(ctrl: Arc<Controller>) -> anyhow::Result<UiServer> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let token = hex::encode(portglass_core::random_bytes::<24>());
    let app = App {
        ctrl,
        token: token.clone(),
        host: addr.to_string(),
    };
    let router = Router::new()
        .route("/", get(index))
        .route("/api/state", get(state))
        .route("/api/events", get(events))
        .route("/api/connect", post(connect))
        .route("/api/disconnect", post(disconnect))
        .route("/api/dismiss", post(dismiss))
        .route("/api/browser", post(open_browser))
        .route("/api/probes/check", post(check_probes))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("UI server stopped: {e}");
        }
    });
    Ok(UiServer {
        addr,
        url: format!("http://{addr}/?t={token}"),
    })
}

fn query_token(req: &Request) -> Option<String> {
    req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("t=").map(str::to_owned))
    })
}

async fn guard(State(app): State<App>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let host_ok = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h == app.host);
    if !host_ok {
        return (StatusCode::MISDIRECTED_REQUEST, "wrong host").into_response();
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()) {
        if origin != format!("http://{}", app.host) {
            return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
        }
    }
    let presented = headers
        .get("x-portglass-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| query_token(&req));
    let token_ok = presented
        .map(|t| portglass_core::ct_eq(t.as_bytes(), app.token.as_bytes()))
        .unwrap_or(false);
    if !token_ok {
        return (StatusCode::UNAUTHORIZED, "missing or wrong token").into_response();
    }
    if req.method() == axum::http::Method::POST {
        let json = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        if !json {
            return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON required").into_response();
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("x-frame-options", "DENY".parse().unwrap());
    h.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
         img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    resp
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn state(State(app): State<App>) -> impl IntoResponse {
    Json(app.ctrl.snapshot())
}

async fn events(
    State(app): State<App>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let stream = WatchStream::new(app.ctrl.subscribe()).map(|snap| {
        Ok(Event::default()
            .json_data(&snap)
            .unwrap_or_else(|_| Event::default()))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn connect(State(app): State<App>, Json(req): Json<ConnectRequest>) -> Response {
    match app.ctrl.connect(req).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(f) => (StatusCode::BAD_REQUEST, Json(f)).into_response(),
    }
}

async fn disconnect(State(app): State<App>) -> StatusCode {
    let ctrl = app.ctrl.clone();
    tokio::spawn(async move { ctrl.disconnect().await });
    StatusCode::ACCEPTED
}

async fn dismiss(State(app): State<App>) -> StatusCode {
    app.ctrl.dismiss();
    StatusCode::NO_CONTENT
}

async fn open_browser(State(app): State<App>) -> StatusCode {
    app.ctrl.open_browser().await;
    StatusCode::ACCEPTED
}

async fn check_probes(State(app): State<App>, _headers: HeaderMap, _body: Body) -> StatusCode {
    let ctrl = app.ctrl.clone();
    tokio::spawn(async move { ctrl.check_probes().await });
    StatusCode::ACCEPTED
}
