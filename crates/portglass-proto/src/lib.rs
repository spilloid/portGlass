//! PortGlass wire protocol.
//!
//! Everything a probe will ever do for a controller is enumerated in [`ControlRequest`]. There is
//! no "run", "exec", "upload", "scan" or free-form forwarding message, and the probe rejects any
//! message it cannot parse into this enum. A data stream never names a destination: it presents a
//! session id and token, and the probe connects it to the single target that session was opened
//! for (after the probe's own policy approved it).
//!
//! Transport: every connection is TLS 1.3 with mutual certificate authentication (see
//! `portglass-core::tls`). ALPN selects the connection kind:
//!
//! * [`ALPN_CONTROL`] — one long-lived connection carrying length-prefixed JSON frames.
//! * [`ALPN_DATA`] — one connection per forwarded TCP connection: a single [`StreamOpen`] frame,
//!   a single [`StreamReply`] frame, then raw bytes in both directions until either side closes.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const ALPN_CONTROL: &[u8] = b"portglass-control/1";
pub const ALPN_DATA: &[u8] = b"portglass-data/1";
pub const DEFAULT_PROBE_PORT: u16 = 47100;
pub const DEFAULT_RELAY_PORT: u16 = 47200;

pub mod pairing;
pub mod relay;

/// Upper bound on any single frame. Control messages are tiny; anything larger is a protocol
/// violation, not a reason to allocate.
pub const MAX_FRAME_LEN: usize = 16 * 1024;

/// A destination as the operator typed it. The probe decides whether it is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSpec {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for TargetSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Controller -> probe, on the control connection. This is the probe's entire command surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlRequest {
    Hello {
        protocol: u32,
        client_version: String,
        /// Display-only (e.g. the Windows user name). The probe audits the identity it
        /// authorized by certificate fingerprint, not this string.
        operator_hint: String,
    },
    OpenSession {
        request_id: u64,
        target: TargetSpec,
        ttl_secs: u32,
    },
    /// Ask the probe to test-connect to the session's target (and nothing else).
    CheckTarget {
        session_id: String,
    },
    CloseSession {
        session_id: String,
    },
    Ping {
        nonce: u64,
    },
}

/// Probe -> controller, on the control connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlEvent {
    HelloOk {
        protocol: u32,
        probe_name: String,
        probe_version: String,
        /// The operator name the probe's own allowlist assigns to this controller's certificate.
        authorized_as: String,
        policy: PolicySummary,
    },
    SessionOpened {
        request_id: u64,
        session_id: String,
        /// Hex. Required on every data stream for this session.
        stream_token: String,
        /// The address the probe resolved and pinned for this session.
        resolved_addr: String,
        expires_in_secs: u32,
        connect_ms: u32,
    },
    SessionRejected {
        request_id: u64,
        code: ErrorCode,
        message: String,
    },
    TargetStatus {
        session_id: String,
        reachable: bool,
        rtt_ms: Option<u32>,
        code: Option<ErrorCode>,
        message: Option<String>,
    },
    SessionEnded {
        session_id: String,
        reason: EndReason,
    },
    Pong {
        nonce: u64,
    },
    /// Sent before the probe closes the control connection because of a bad request.
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// What the probe is willing to forward to, shown to the operator. Informational: enforcement
/// happens in the probe regardless of what the controller displays.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySummary {
    pub allow: Vec<AllowRuleSummary>,
    pub max_session_ttl_secs: u32,
    pub max_streams_per_session: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowRuleSummary {
    pub network: String,
    pub ports: String,
    pub label: Option<String>,
}

/// First frame on a data connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOpen {
    pub session_id: String,
    pub stream_token: String,
}

/// Probe's answer on a data connection. After `Accepted`, the connection carries raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamReply {
    Accepted,
    Rejected { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    VersionMismatch,
    Unsupported,
    ProtocolViolation,
    InvalidRequest,
    UnauthorizedTarget,
    DnsFailed,
    TargetUnreachable,
    ConnectionRefused,
    TargetTimeout,
    SessionNotFound,
    SessionExpired,
    TooManySessions,
    TooManyStreams,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::VersionMismatch => "version_mismatch",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::ProtocolViolation => "protocol_violation",
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::UnauthorizedTarget => "unauthorized_target",
            ErrorCode::DnsFailed => "dns_failed",
            ErrorCode::TargetUnreachable => "target_unreachable",
            ErrorCode::ConnectionRefused => "connection_refused",
            ErrorCode::TargetTimeout => "target_timeout",
            ErrorCode::SessionNotFound => "session_not_found",
            ErrorCode::SessionExpired => "session_expired",
            ErrorCode::TooManySessions => "too_many_sessions",
            ErrorCode::TooManyStreams => "too_many_streams",
            ErrorCode::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    ClosedByController,
    Expired,
    /// An administrator changed the probe's configuration so the session is no longer allowed.
    Revoked,
    /// The control connection closed or went silent; sessions never outlive it.
    ControllerDisconnected,
    ProbeShutdown,
}

impl EndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            EndReason::ClosedByController => "closed_by_controller",
            EndReason::Expired => "expired",
            EndReason::Revoked => "revoked",
            EndReason::ControllerDisconnected => "controller_disconnected",
            EndReason::ProbeShutdown => "probe_shutdown",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("connection closed")]
    Closed,
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN}-byte limit")]
    TooLarge(usize),
    #[error("malformed frame: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error(transparent)]
    Io(std::io::Error),
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Closed
        } else {
            FrameError::Io(e)
        }
    }
}

/// Write one frame: a 4-byte big-endian length, then that many bytes of JSON.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Read one frame. The frame is read exactly — no bytes past it are consumed — so a data stream
/// can switch to raw bytes immediately afterwards.
pub async fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trip_does_not_over_read() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let open = StreamOpen {
            session_id: "abc".into(),
            stream_token: "00ff".into(),
        };
        write_frame(&mut a, &open).await.unwrap();
        a.write_all(b"RAW").await.unwrap();
        let got: StreamOpen = read_frame(&mut b).await.unwrap();
        assert_eq!(got.session_id, "abc");
        let mut raw = [0u8; 3];
        b.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"RAW");
    }

    #[test]
    fn unknown_commands_do_not_parse() {
        for bad in [
            r#"{"type":"exec","command":"cmd.exe"}"#,
            r#"{"type":"open_session","request_id":1,"target":{"host":"a","port":1},"ttl_secs":1,"extra":true}"#,
            r#"{"type":"upload_file","path":"C:\\x"}"#,
        ] {
            assert!(
                serde_json::from_str::<ControlRequest>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn oversized_frames_are_refused_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(u32::MAX).to_be_bytes()).await.unwrap();
        let err = read_frame::<_, StreamOpen>(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn target_display_brackets_ipv6() {
        let t = TargetSpec {
            host: "fe80::1".into(),
            port: 80,
        };
        assert_eq!(t.to_string(), "[fe80::1]:80");
    }
}
