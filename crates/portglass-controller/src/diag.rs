//! Pre-flight diagnostics through the tunnel, before the browser opens.
//!
//! Embedded devices often redirect to another port, insist on HTTPS, or present self-signed
//! certificates. PortGlass forwards one TCP port and never rewrites traffic, so instead of
//! papering over those cases it looks for them up front and says what will happen.
//!
//! The diagnostic TLS client below accepts any certificate *for inspection only*: it reads the
//! certificate's fingerprint, sends one header-only `GET /`, and closes. It never carries browser
//! traffic. The browser validates the device's certificate itself, with its normal rules.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use portglass_core::identity::Fingerprint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SchemePref {
    #[default]
    Auto,
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Info,
    Warn,
}

#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub label: String,
    pub host: String,
    pub port: u16,
    pub scheme: Scheme,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub level: Level,
    pub title: String,
    pub text: String,
    pub suggestion: Option<Suggestion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub scheme: Scheme,
    pub http_status: Option<u16>,
    pub server: Option<String>,
    pub tls_fingerprint: Option<String>,
    pub tls_version: Option<String>,
    /// An absolute redirect back to the device's own address (only safe when the browser maps
    /// that address onto the tunnel).
    pub self_redirect: Option<String>,
    pub items: Vec<Diagnostic>,
}

fn item(level: Level, title: impl Into<String>, text: impl Into<String>) -> Diagnostic {
    Diagnostic {
        level,
        title: title.into(),
        text: text.into(),
        suggestion: None,
    }
}

/// Run diagnostics. `open` yields a fresh tunnelled stream to the target each time it is called.
pub async fn inspect<F, Fut, S>(open: F, host: &str, port: u16, pref: SchemePref) -> Report
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<S, String>>,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host_header = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut items = Vec::new();
    let try_tls = match pref {
        SchemePref::Https => true,
        SchemePref::Http => false,
        SchemePref::Auto => true,
    };

    let mut tls_fingerprint = None;
    let mut tls_version = None;
    let mut head: Option<Result<Head, String>> = None;
    let mut scheme = Scheme::Http;

    if try_tls {
        match open().await {
            Ok(stream) => match tls_probe(stream, host).await {
                Ok((mut tls, fp, version)) => {
                    scheme = Scheme::Https;
                    tls_fingerprint = Some(fp.to_string());
                    tls_version = Some(version.clone());
                    items.push(item(
                        Level::Info,
                        "The device uses HTTPS",
                        format!(
                            "{version}; certificate {}. If the browser warns about the certificate, \
                             compare this fingerprint with the one the browser shows before you \
                             continue. PortGlass does not bypass certificate checks.",
                            fp.short()
                        ),
                    ));
                    head = Some(http_head(&mut tls, &host_header).await);
                }
                Err(e) if pref == SchemePref::Https => {
                    items.push(item(
                        Level::Warn,
                        "HTTPS handshake failed",
                        format!(
                            "{e}. The port may serve plain HTTP, or the device may only support \
                             legacy TLS versions that current browsers refuse."
                        ),
                    ));
                    scheme = Scheme::Https;
                }
                Err(_) => {}
            },
            Err(e) => items.push(item(Level::Warn, "Couldn't open a test connection", e)),
        }
    }

    if head.is_none() && scheme == Scheme::Http {
        match open().await {
            Ok(mut stream) => head = Some(http_head(&mut stream, &host_header).await),
            Err(e) => items.push(item(Level::Warn, "Couldn't open a test connection", e)),
        }
    }

    let mut http_status = None;
    let mut server = None;
    let mut self_redirect = None;
    match head {
        Some(Ok(h)) => {
            http_status = Some(h.status);
            server = h.server.clone();
            items.push(item(
                Level::Ok,
                format!("The web interface answered ({})", h.status),
                match &h.server {
                    Some(s) => format!("Server: {s}"),
                    None => "Response headers received through the tunnel.".into(),
                },
            ));
            if let Some(loc) = &h.location {
                items.extend(analyze_redirect(loc, host, port, scheme));
                let host_l = host.trim_matches(['[', ']']).to_ascii_lowercase();
                if split_url(loc).is_some_and(|(_, h, p)| h == host_l && p == port) {
                    self_redirect = Some(loc.clone());
                }
            }
            if h.status == 401 {
                items.push(item(
                    Level::Info,
                    "The device asks for a login",
                    "The browser will prompt for the device's credentials. PortGlass never sees \
                     or stores them — they travel inside the browser's own connection.",
                ));
            }
        }
        Some(Err(e)) => {
            if e.contains("TLS record") {
                items.push(Diagnostic {
                    suggestion: Some(Suggestion {
                        label: "Use HTTPS".into(),
                        host: host.into(),
                        port,
                        scheme: Scheme::Https,
                    }),
                    ..item(Level::Warn, "This port expects HTTPS", e)
                });
            } else {
                items.push(item(
                    Level::Warn,
                    "The port is open but didn't answer like a web server",
                    format!("{e}. If this is not a web interface, the browser won't be able to show it."),
                ));
            }
        }
        None => {}
    }

    Report {
        scheme,
        http_status,
        server,
        tls_fingerprint,
        tls_version,
        self_redirect,
        items,
    }
}

#[derive(Debug)]
struct Head {
    status: u16,
    location: Option<String>,
    server: Option<String>,
}

async fn http_head<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host_header: &str,
) -> Result<Head, String> {
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: PortGlass-Diagnostics/{}\r\n\
         Accept: text/html\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let work = async {
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        s.flush().await.map_err(|e| e.to_string())?;
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 2048];
        loop {
            let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_HEADER_BYTES {
                break;
            }
        }
        Ok::<_, String>(buf)
    };
    let buf = tokio::time::timeout(STEP_TIMEOUT, work)
        .await
        .map_err(|_| "no response within 5 seconds".to_string())??;
    parse_head(&buf)
}

fn parse_head(buf: &[u8]) -> Result<Head, String> {
    if buf.first() == Some(&0x15) || buf.first() == Some(&0x16) {
        return Err("the port answered with a TLS record instead of HTTP".into());
    }
    let end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..end]);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err("the response was not HTTP".into());
    }
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("the HTTP status line was malformed")?;
    let mut location = None;
    let mut server = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim().chars().take(200).collect::<String>();
            match k.trim().to_ascii_lowercase().as_str() {
                "location" => location = Some(v),
                "server" => server = Some(v),
                _ => {}
            }
        }
    }
    Ok(Head {
        status,
        location,
        server,
    })
}

/// Split an absolute URL into (scheme, host, port). Relative URLs return None.
fn split_url(url: &str) -> Option<(Scheme, String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        (h.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse().ok())
    } else {
        (authority.to_string(), None)
    };
    Some((
        scheme,
        host.to_ascii_lowercase(),
        port.unwrap_or(scheme.default_port()),
    ))
}

fn analyze_redirect(location: &str, host: &str, port: u16, scheme: Scheme) -> Vec<Diagnostic> {
    let Some((to_scheme, to_host, to_port)) = split_url(location) else {
        return vec![item(
            Level::Ok,
            "The device redirects within this address",
            format!("Redirect to {location} stays on the forwarded port."),
        )];
    };
    let host_l = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if to_host == host_l && to_port == port {
        if to_scheme == scheme {
            return vec![item(
                Level::Ok,
                "The device redirects within this address",
                format!("Redirect to {location} stays on the forwarded port."),
            )];
        }
        return vec![item(
            Level::Warn,
            format!("The device redirects to {} on the same port", to_scheme.as_str()),
            format!("It sends the browser to {location}. That usually fails; pick the scheme the device expects."),
        )];
    }
    if to_host == host_l {
        return vec![Diagnostic {
            suggestion: Some(Suggestion {
                label: format!("Connect to port {to_port} instead"),
                host: host.to_string(),
                port: to_port,
                scheme: to_scheme,
            }),
            ..item(
                Level::Warn,
                format!("The device redirects to port {to_port}"),
                format!(
                    "It sends the browser to {location}, but this session forwards only port {port}. \
                     The browser won't be able to follow. Connect to port {to_port} instead."
                ),
            )
        }];
    }
    vec![item(
        Level::Warn,
        format!("The device redirects to another host ({to_host})"),
        format!(
            "It sends the browser to {location}. This session forwards only {host}:{port}, so that \
             page won't load. Try connecting to {to_host}:{to_port} through the probe instead."
        ),
    )]
}

async fn tls_probe<S>(
    stream: S,
    host: &str,
) -> Result<(tokio_rustls::client::TlsStream<S>, Fingerprint, String), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let provider = portglass_core::tls::provider();
    let verifier = Arc::new(InspectOnly {
        seen: Mutex::new(None),
        algorithms: provider.signature_verification_algorithms,
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.trim_matches(['[', ']']).to_string())
        .unwrap_or_else(|_| ServerName::try_from("device.invalid").unwrap());
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = tokio::time::timeout(STEP_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|e| format!("TLS handshake failed: {e}"))?;
    let version = tls
        .get_ref()
        .1
        .protocol_version()
        .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."))
        .unwrap_or_else(|| "TLS".into());
    let fp = verifier
        .seen
        .lock()
        .unwrap()
        .ok_or("the device sent no certificate")?;
    Ok((tls, fp, version))
}

/// Records the certificate and accepts it. Inspection only — see the module docs.
#[derive(Debug)]
struct InspectOnly {
    seen: Mutex<Option<Fingerprint>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for InspectOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(Fingerprint::of(end_entity));
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_location_and_server() {
        let h = parse_head(
            b"HTTP/1.1 302 Found\r\nLocation: https://192.168.1.50/\r\nServer: Printer\r\n\r\nbody",
        )
        .unwrap();
        assert_eq!(h.status, 302);
        assert_eq!(h.location.as_deref(), Some("https://192.168.1.50/"));
        assert_eq!(h.server.as_deref(), Some("Printer"));
        assert!(parse_head(&[0x15, 0x03, 0x01])
            .unwrap_err()
            .contains("TLS record"));
    }

    #[test]
    fn redirect_analysis() {
        let same = analyze_redirect("/login", "192.168.1.50", 80, Scheme::Http);
        assert_eq!(same[0].level, Level::Ok);

        let other_port =
            analyze_redirect("https://192.168.1.50/", "192.168.1.50", 80, Scheme::Http);
        assert_eq!(other_port[0].level, Level::Warn);
        let s = other_port[0].suggestion.as_ref().unwrap();
        assert_eq!((s.port, s.scheme), (443, Scheme::Https));

        let explicit =
            analyze_redirect("http://192.168.1.50:80/x", "192.168.1.50", 80, Scheme::Http);
        assert_eq!(explicit[0].level, Level::Ok);

        let other_host = analyze_redirect("http://printer.corp/", "192.168.1.50", 80, Scheme::Http);
        assert!(other_host[0].title.contains("another host"));
    }
}
