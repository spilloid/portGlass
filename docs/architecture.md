# Architecture

PortGlass makes **one** TCP service on a remote LAN usable from a technician's PC, in a
dedicated browser, for a limited time. This document describes how; the
[security model](security-model.md) describes why it is safe to allow.

## Components

| Crate | Binary | Role |
|---|---|---|
| `portglass-proto` | — | Wire messages and framing. The probe's entire command surface is the `ControlRequest` enum. |
| `portglass-core` | — | Identities and fingerprints, pinned mutual TLS (rustls), the byte bridge, the audit log. |
| `portglass-probe` | `portglass-probe.exe` | Runs at the remote site. Policy, sessions, forwarding. |
| `portglass-controller` | `portglass.exe` | Runs on the technician's PC. State machine, local tunnel, browser, status window. |
| `portglass-mock-target` | `portglass-mock-target.exe` | Test device: HTML, JS, forms, cookies, WebSocket, binary, HTTPS. Never deployed. |

Deliberately not used: a custom cipher or handshake (rustls does TLS 1.3), a VPN or virtual
adapter, routing or DNS changes, a SOCKS/HTTP proxy, Tauri or a bundled Chromium. The controller
window is a small local web page shown in a Chrome app window, which kept v0.1.0 to one
toolchain (Rust) and one browser dependency the technician already has.

## Connections

All connections go from the controller to the probe's one port (default 47100) and are TLS 1.3
with **mutual** certificate authentication. Each side has a self-signed ECDSA P-256 certificate;
trust is the SHA-256 fingerprint of the other side's certificate, exchanged out of band — the
SSH `known_hosts`/`authorized_keys` model, carried by rustls. Possession of the private key is
proven by the TLS 1.3 CertificateVerify signature, checked by rustls' own verifier.

ALPN selects the connection kind:

| ALPN | Lifetime | Content |
|---|---|---|
| `portglass-control/1` | One per controller, as long as the controller is connected | Length-prefixed JSON frames (≤ 16 KiB) |
| `portglass-data/1` | One per forwarded TCP connection | One `StreamOpen` frame, one `StreamReply` frame, then raw bytes both ways |

### Control protocol

```
controller → probe                     probe → controller
Hello{protocol, version, hint}    →    HelloOk{probe name, version, authorized_as, policy summary}
OpenSession{id, target, ttl}      →    SessionOpened{session_id, stream_token, resolved, ttl}
                                       | SessionRejected{code, message}
CheckTarget{session_id}           →    TargetStatus{reachable, rtt}
CloseSession{session_id}          →    SessionEnded{reason}
Ping{nonce}                       →    Pong{nonce}
(anything else)                   →    Error{unsupported} and the connection is closed
```

`SessionEnded` is also sent unprompted when a session expires, is revoked by a configuration
change, or the probe shuts down.

### Data streams

A data stream names a session, not a destination. The probe checks that the session exists, that
the stream comes from the same controller certificate that opened it, the 256-bit token (constant
time), that it hasn't ended or expired, and the per-session stream limit. Only then does it
connect to the session's **pinned** address and start forwarding. Unknown session, wrong owner
and wrong token produce the same answer.

## Session lifecycle (controller)

```
DISCONNECTED → AUTHENTICATING → CONNECTING → VERIFYING → READY → CLOSING → DISCONNECTED
                     └──────────────┴────────────┴─────────┴──→ FAILED
```

| Phase | What happens | Indicator |
|---|---|---|
| AUTHENTICATING | TCP + mutual TLS to the pinned probe; `Hello`/`HelloOk` | amber |
| CONNECTING | `OpenSession`; the probe applies its policy, resolves and pins the address, test-connects | amber |
| VERIFYING | Bind `127.0.0.1:0`; open one data stream end to end; diagnostics (TLS? redirects?) | amber |
| READY | Accept local connections, one data stream each; launch the session browser; heartbeat every 3 s, probe test-connects the device every 10 s | green (red if the device stops answering) |
| CLOSING | Cancel all forwarded connections, `CloseSession`, close the browser, delete its profile, close the control connection | gray |
| FAILED | Any of: authentication failure, probe unreachable, target unreachable, connection refused, TLS error, network interruption, session expired or revoked, unauthorized target, probe stopped | red, with what to do |

One task owns a session from AUTHENTICATING to teardown, so cleanup happens in one place
whichever way the session ends (`crates/portglass-controller/src/session.rs`). The transition
table is `session::allowed()` and is unit-tested.

## Forwarding

`portglass-core::bridge` copies bytes between two streams in both directions at once:

- **Binary-safe, no inspection.** Bytes are copied, counted, and never logged.
- **Backpressure.** Each direction awaits its write before reading more (32 KiB buffer), so a
  slow reader throttles the sender through TCP flow control.
- **Half-close.** EOF in one direction shuts down the write side of the other stream (a TLS
  `close_notify` plus TCP FIN across the tunnel); the opposite direction keeps flowing.
- **Ends** when both directions finish, either side errors, the idle timeout passes (default
  300 s, configurable on both ends), or the session's cancellation token fires.

Each browser connection is its own data stream, so Chrome's parallel connections, keep-alive and
WebSocket upgrades work without PortGlass understanding HTTP.

## The session browser

The controller launches the installed Chrome (`App Paths` registration, then standard locations,
or `[browser] path`) with:

- `--user-data-dir=%LOCALAPPDATA%\PortGlass\browser-sessions\<session id>` — a new, empty profile
  seeded only to turn off password saving, autofill, sign-in and translation;
- `--app=<url>` — a single-purpose window;
- `--host-resolver-rules="MAP <device>:<port> 127.0.0.1:<tunnel>, MAP * ~NOTFOUND"` — inside this
  process only, the device's own address resolves to the tunnel and (in strict isolation) every
  other name fails to resolve;
- `--no-proxy-server`, so device traffic never goes to a system proxy;
- quiet-profile flags (`--no-first-run`, `--disable-sync`, `--disable-extensions`,
  `--disable-background-networking`, …). No security, certificate or sandbox flags.

Chrome is created suspended, assigned to a Windows Job Object with *kill on close*, then
resumed, so every process it starts is in the job. Closing the session — or the controller
exiting for any reason — ends them all. The profile directory (named by the controller, never
by the probe) is then deleted; any left behind by a crash are swept at the next start.

The tunnel endpoint uses the same job as an access list: for each local connection the
controller looks up the owning process of the client socket in the TCP table and admits it only
if `IsProcessInJob` says it belongs to the session browser.

## The controller window

`portglass` serves a single static page on `127.0.0.1:<random>` and opens it as a Chrome app
window with its own throwaway profile. The page receives state over Server-Sent Events and sends
four commands (connect, disconnect, dismiss, open browser) plus "check probes". Every request
needs the per-launch random token, an exact `Host` header (blocks DNS rebinding), a same-origin
`Origin` if present, and JSON bodies for POSTs. Closing the window ends every session and exits.

## Relay mode (designed, not built)

Both ends already treat "how do I get a byte stream to the probe" as a single seam:
`ProbeLink::connect` and `ProbeLink::open_stream` in the controller, `accept_loop` in the probe.
A relay would be a rendezvous service that both sides dial *outbound*; it would splice a
controller's TCP stream to a probe's, and the mutual TLS described above would run end to end
*through* it — the relay would see ciphertext and connection metadata only, and could not
impersonate either side because it holds neither certificate. Building it needs: probe-side
outbound registration, relay authentication of both parties, and abuse limits. Not in v0.1.0.

## Configuration files

| File | Default location | Example |
|---|---|---|
| Probe | `%LOCALAPPDATA%\PortGlass\probe\probe.toml` (installer: `%ProgramData%\PortGlass\probe.toml`) | [examples/probe.toml](../examples/probe.toml) |
| Controller | `%APPDATA%\PortGlass\controller\controller.toml` | [examples/controller.toml](../examples/controller.toml) |

Identities (`probe.crt`/`probe.key`, `controller.crt`/`controller.key`) live in an `identity`
folder next to each file; the private key's ACL is narrowed to the owner, SYSTEM and
Administrators at creation.
