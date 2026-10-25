# Changelog

All notable changes to PortGlass. Versions follow [semver](https://semver.org/); the version in
`Cargo.toml` (`[workspace.package]`) is authoritative.

## 0.1.0 — unreleased

First release: a working direct-mode vertical slice.

### Added
- **PortGlass Probe** (`portglass-probe`): mutually authenticated TLS 1.3 listener pinned to
  controller certificate fingerprints; deny-by-default destination allowlist (networks + ports)
  enforced at the probe, with loopback and link-local reachable only through rules written for
  them; host names resolved once and pinned per session; sessions bound to their control
  connection, with TTL expiry, per-session stream limits, idle timeouts, live configuration
  reload that revokes what the new file no longer allows, and fail-closed handling of an invalid
  file; JSON-lines audit log; `init`, `run`, `authorize`, `allow`, `check-config`, `diag`,
  `fingerprint`.
- **PortGlass Controller** (`portglass`): session state machine (DISCONNECTED → AUTHENTICATING →
  CONNECTING → VERIFYING → READY → CLOSING) with actionable error states; 127.0.0.1-only tunnel
  listener; dedicated Chrome session window with a per-session profile deleted on close and the
  device's own address mapped onto the tunnel; pre-flight diagnostics (HTTPS detection,
  certificate fingerprint, cross-port and cross-host redirects); live status window with red /
  amber / green / gray indicator, throughput and connection metrics; terminal `connect`; `diag`.
- **Double-click first run:** `portglass.exe` creates its identity on first launch, opens without a console window, shows *Add a probe* with your fingerprint and a form to pair a probe (saved to `controller.toml`), and reports startup problems such as a missing Chrome in a dialog. `portglass-probe.exe` sets itself up on first launch, asks in its console who may connect and which devices to allow, prints what to enter on the technician's PC, and waits for Enter before closing.
- **Mock device** (`portglass-mock-target`): HTML, script, forms, cookie login, WebSocket echo and
  push, large binary download, HTTPS with a throwaway certificate.
- Tests: forwarding (HTTP, WebSocket, byte-exact concurrent downloads, half-close), authorization
  and authentication failures, token misuse, teardown, expiry, revocation, control-connection
  loss, UI server request guard, real-browser end-to-end, and STD-008 UI capture validation.
- Hardening from adversarial review: the 127.0.0.1 tunnel endpoint admits only the session
  browser's processes (TCP owner + Job Object membership); Chrome starts suspended and is resumed
  only once contained; probe-supplied identifiers are validated and never used as paths; no TLS
  session resumption on the probe; per-address handshake limits; in-flight request caps and send
  timeouts on control connections; additional cloud-metadata ranges and NAT64/IPv4-compatible
  forms treated as special; `--no-proxy-server` for the session browser.
- Docs: architecture, security model and threat analysis, deployment/firewall/EDR guidance,
  troubleshooting; PowerShell build, demo, install, firewall and diagnostics scripts; CI, Pages and
  signed-release workflows.
