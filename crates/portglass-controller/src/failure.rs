//! Errors as the technician sees them: what happened, and what to do about it.

use portglass_proto::{EndReason, ErrorCode};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    AuthFailed,
    ProbeUnreachable,
    TargetUnreachable,
    ConnectionRefused,
    TlsError,
    NetworkInterrupted,
    SessionExpired,
    SessionRevoked,
    UnauthorizedTarget,
    ProbeTerminated,
    InvalidTarget,
    Busy,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub title: String,
    pub detail: String,
    pub hint: String,
}

impl Failure {
    pub fn new(
        kind: FailureKind,
        title: impl Into<String>,
        detail: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Failure {
            kind,
            title: title.into(),
            detail: detail.into(),
            hint: hint.into(),
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Failure::new(
            FailureKind::Internal,
            "Something went wrong",
            detail,
            "Try again. If it keeps happening, run `portglass diag` and include its output.",
        )
    }

    /// A probe's refusal of a session request.
    pub fn from_probe(code: ErrorCode, message: &str, target: &str) -> Self {
        use FailureKind as K;
        match code {
            ErrorCode::UnauthorizedTarget => Failure::new(
                K::UnauthorizedTarget,
                "This probe isn't allowed to reach that address",
                message,
                {
                    let (host, port) = target
                        .rsplit_once(':')
                        .map(|(h, p)| (h.trim_matches(['[', ']']).to_string(), p.to_string()))
                        .unwrap_or_else(|| (target.to_string(), "<port>".into()));
                    format!(
                        "The probe only forwards to destinations its administrator listed. If \
                         this one should be allowed, ask them to run: portglass-probe allow \
                         --network {host} --ports {port}"
                    )
                },
            ),
            ErrorCode::ConnectionRefused => Failure::new(
                K::ConnectionRefused,
                "The device refused the connection",
                message,
                "The device is on, but nothing is listening on that port. Check the port \
                 (web interfaces are usually 80 or 443) and that the device's web server is enabled.",
            ),
            ErrorCode::TargetTimeout | ErrorCode::TargetUnreachable => Failure::new(
                K::TargetUnreachable,
                "The probe can't reach the device",
                message,
                "Check that the device is powered on and that the address is right from the \
                 probe's network. On the probe: portglass-probe diag --target <address:port>",
            ),
            ErrorCode::DnsFailed => Failure::new(
                K::TargetUnreachable,
                "The probe couldn't resolve that name",
                message,
                "Use the device's IP address, or check DNS on the probe's network.",
            ),
            ErrorCode::SessionExpired => Failure::new(
                K::SessionExpired,
                "The session expired",
                message,
                "Connect again to start a new session.",
            ),
            ErrorCode::TooManySessions | ErrorCode::TooManyStreams => Failure::new(
                K::Busy,
                "The probe is at its limit",
                message,
                "Close other sessions on this probe, or ask its administrator to raise [limits].",
            ),
            ErrorCode::VersionMismatch => Failure::new(
                K::Internal,
                "PortGlass versions don't match",
                message,
                "Update the controller and the probe to the same release.",
            ),
            ErrorCode::InvalidRequest => Failure::new(
                K::InvalidTarget,
                "That target isn't valid",
                message,
                "Enter an IP address or host name and a port, like 192.168.1.50:80.",
            ),
            _ => Failure::new(K::Internal, "The probe reported an error", message, "Try again."),
        }
    }

    pub fn from_end(reason: EndReason) -> Option<Self> {
        use FailureKind as K;
        match reason {
            EndReason::ClosedByController => None,
            EndReason::Expired => Some(Failure::new(
                K::SessionExpired,
                "The session expired",
                "The probe ended the session when its time limit ran out.",
                "Connect again to start a new session.",
            )),
            EndReason::Revoked => Some(Failure::new(
                K::SessionRevoked,
                "The probe's administrator revoked this session",
                "The probe's configuration changed and no longer allows this session.",
                "Contact the probe's administrator.",
            )),
            EndReason::ControllerDisconnected => Some(Failure::new(
                K::NetworkInterrupted,
                "The connection to the probe was interrupted",
                "The probe stopped hearing from this controller and ended the session.",
                "Check the network between you and the probe, then connect again.",
            )),
            EndReason::ProbeShutdown => Some(Failure::new(
                K::ProbeTerminated,
                "The probe stopped",
                "Someone stopped PortGlass Probe on the remote computer.",
                "Ask someone at that site to start the probe again.",
            )),
        }
    }
}
