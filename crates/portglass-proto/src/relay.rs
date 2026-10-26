//! The relay's protocol: how a probe and a controller that cannot reach each other directly meet
//! at a relay both of them can reach.
//!
//! Every relay connection is TLS 1.3 to the relay, pinned to the relay's fingerprint, with the
//! dialing side's PortGlass certificate as its client certificate. ALPN selects the kind:
//!
//! * [`ALPN_REGISTER`] — one long-lived connection per probe. The probe publishes which
//!   controller fingerprints its own allowlist accepts; the relay announces each controller that
//!   wants it with a [`ProbeEvent::Incoming`] ticket.
//! * [`ALPN_ACCEPT`] — the probe answers a ticket on a new connection with one [`Accept`] frame.
//! * [`ALPN_CONNECT`] — a controller asks for a probe with one [`Connect`] frame and gets one
//!   [`ConnectReply`].
//!
//! After `Accept` / `ConnectReply::Connected` the relay copies bytes between the two connections
//! and the ordinary PortGlass connection — mutual TLS between controller and probe, pinned at
//! both ends — runs inside. The relay holds neither end's key, so it carries ciphertext it can
//! neither read nor forge.

use serde::{Deserialize, Serialize};

pub const RELAY_PROTOCOL_VERSION: u32 = 1;
pub const ALPN_REGISTER: &[u8] = b"portglass-relay-register/1";
pub const ALPN_ACCEPT: &[u8] = b"portglass-relay-accept/1";
pub const ALPN_CONNECT: &[u8] = b"portglass-relay-connect/1";

/// The most controller fingerprints a probe may publish. Keeps `Register` well inside
/// [`crate::MAX_FRAME_LEN`].
pub const MAX_PUBLISHED_CONTROLLERS: usize = 128;

/// Probe -> relay, on the registration connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeRequest {
    /// First frame. Sent again whenever the probe's controller allowlist changes.
    Register {
        protocol: u32,
        /// `sha256:...` fingerprints the probe itself would accept.
        controllers: Vec<String>,
    },
    Ping {
        nonce: u64,
    },
}

/// Relay -> probe, on the registration connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeEvent {
    Registered {
        relay_name: String,
    },
    /// A listed controller asked for this probe. Answer on a new [`ALPN_ACCEPT`] connection.
    Incoming {
        ticket: String,
    },
    Pong {
        nonce: u64,
    },
    /// Sent before the relay closes the registration.
    Refused {
        message: String,
    },
}

/// Probe -> relay, the only frame on an accept connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    pub ticket: String,
}

/// Controller -> relay, the only frame a controller sends before the splice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    pub protocol: u32,
    /// The probe's `sha256:...` fingerprint, which the controller has pinned.
    pub probe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectReply {
    /// From the next byte on, this connection is the probe's.
    Connected,
    /// The relay will not pair this controller with that probe. Deliberately one answer for
    /// "not registered here", "not listed by the probe" and "busy", so a controller learns
    /// nothing about probes it is not authorized for.
    Unavailable { message: String },
}
