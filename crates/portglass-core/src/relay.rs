//! Dialing a PortGlass relay, shared by the probe and the controller.
//!
//! A relay connection is TLS 1.3 pinned to the relay's fingerprint (the same verifier a
//! controller uses for a probe), with the dialer's own certificate as client certificate so the
//! relay knows who is asking. What runs inside after the relay pairs two connections is the
//! ordinary PortGlass TLS between controller and probe, so the outer layer only has to protect
//! the meeting itself.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::identity::{Fingerprint, Identity};
use crate::tls;

/// A byte stream of any origin: a direct TCP connection or a connection spliced by a relay.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}
pub type BoxedIo = Box<dyn Io>;

impl fmt::Debug for dyn Io {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Io")
    }
}

#[derive(Debug)]
pub enum DialError {
    /// No TCP connection (refused, unreachable, or timed out).
    Unreachable(String),
    /// The server is not the relay that was pinned.
    WrongIdentity,
    /// Anything else in the TLS handshake.
    Tls(String),
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialError::Unreachable(m) => write!(f, "can't reach the relay: {m}"),
            DialError::WrongIdentity => f.write_str("the relay presented the wrong identity"),
            DialError::Tls(m) => write!(f, "TLS handshake with the relay failed: {m}"),
        }
    }
}

impl std::error::Error for DialError {}

/// Open a TLS connection to the relay at `address`, pinned to `relay`, speaking `alpn`.
pub async fn dial(
    address: &str,
    relay: Fingerprint,
    identity: &Identity,
    alpn: &[u8],
    timeout: Duration,
) -> Result<TlsStream<TcpStream>, DialError> {
    let config =
        tls::client_config(identity, relay, alpn).map_err(|e| DialError::Tls(e.to_string()))?;
    let tcp = match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(DialError::Unreachable(format!("{address}: {e}"))),
        Err(_) => {
            return Err(DialError::Unreachable(format!(
                "no answer from {address} within {}s",
                timeout.as_secs()
            )))
        }
    };
    let _ = tcp.set_nodelay(true);
    let connector = TlsConnector::from(Arc::new(config));
    match tokio::time::timeout(timeout, connector.connect(tls::server_name(), tcp)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            let wrong = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .is_some_and(|r| matches!(r, rustls::Error::InvalidCertificate(_)));
            Err(if wrong {
                DialError::WrongIdentity
            } else {
                DialError::Tls(e.to_string())
            })
        }
        Err(_) => Err(DialError::Tls("timed out".into())),
    }
}
