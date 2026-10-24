# PortGlass

**Operate one web interface on a remote LAN as if it were on your desk — without a VPN, remote
desktop, or routing a whole network.**

PortGlass v0.1.0 · Windows · MIT · [Docs site](https://spilloid.github.io/portGlass/)

A technician picks a probe, types `192.168.1.50:80`, and a dedicated, isolated browser window
opens on the printer's real web interface. Closing the session closes the tunnel and deletes
everything the browser stored.

![The PortGlass window while connected](docs/img/controller-connected-dark.png)

> **Guiding principle: expose one explicitly authorized TCP service, not an entire network.**

## How it works

```
 Technician PC                                         Remote site
┌──────────────────────────────┐   TLS 1.3, mutual   ┌──────────────────────┐   plain TCP   ┌─────────┐
│ PortGlass Controller         │   certificate auth  │ PortGlass Probe      │──────────────▶│ printer │
│  • status window             │═════════════════════│  • its own allowlist │  one address, │ :80     │
│  • 127.0.0.1:<random> ◀──┐   │   one port (47100)  │  • sessions expire   │  one port     └─────────┘
│  • session browser ──────┘   │                     │  • audit log         │
└──────────────────────────────┘                     └──────────────────────┘
```

- **PortGlass Probe** runs on an authorized Windows computer at the remote site. It forwards TCP
  only to destinations its administrator listed, only for controllers its administrator
  authorized, for a limited time. It does not run commands, transfer files, scan the network, or
  start automatically.
- **PortGlass Controller** runs on the technician's PC. It authenticates to the probe, asks for a
  session to one destination, exposes it on `127.0.0.1` only, and opens your installed Google
  Chrome with a brand-new profile pointed at the device's own address.

Details: [architecture](docs/architecture.md) · [security model and threat analysis](docs/security-model.md)
· [deployment, firewall and EDR guidance](docs/deployment.md) · [troubleshooting](docs/troubleshooting.md).

## Requirements

- Windows 10 or 11 (x64) on both ends.
- Google Chrome installed on the technician's PC. PortGlass does not bundle a browser.
- The technician's PC must reach the probe's TCP port (default 47100): same LAN, or an existing
  authorized VPN. Relay mode for NAT-to-NAT is designed for but not built in v0.1.0.
- To build from source: Rust (stable, MSVC target) and Visual Studio Build Tools.

## Quick start

### 1. On the technician's PC

```powershell
portglass init                       # creates your identity; prints your fingerprint
```

Send the printed fingerprint to the probe's administrator.

### 2. On the remote computer (the probe)

```powershell
portglass-probe init --name front-office          # prints the probe's fingerprint
portglass-probe authorize --name alice --fingerprint sha256:6A01:...   # the technician's
portglass-probe allow --network 192.168.1.50 --ports 80,443 --label "Front office printer"
portglass-probe run                                # visible console; Ctrl+C stops it
```

Allow the probe's port in Windows Firewall from technician addresses only — see
[deployment](docs/deployment.md#windows-firewall), or `scripts/probe-firewall.ps1`.

### 3. Back on the technician's PC

```powershell
portglass probe add --name front-office --address 10.0.5.20:47100 --fingerprint sha256:6F59:...
portglass                            # opens the PortGlass window
```

Pick the probe, type `192.168.1.50:80`, and press **Connect**. The light goes red → amber →
green, and the printer's own page opens in a separate window. **End session** (or closing that
window) closes the tunnel and deletes the browser's data.

Prefer the terminal? `portglass connect --probe front-office --target 192.168.1.50:80`.

## Try it on one PC

```powershell
./scripts/build.ps1
./scripts/launch-demo.ps1     # mock printer + probe + controller, all on loopback
```

The demo creates throwaway identities under `%TEMP%`, starts a mock printer interface on
`127.0.0.2:18080`, a probe limited to that address, and the controller window.

## What you get

| | |
|---|---|
| **Secure single-port bridge** | Raw TCP, binary-safe, both directions at once, with backpressure and half-close. HTTP, HTTPS and WebSockets work unmodified. Many concurrent connections to the one authorized target. |
| **Dedicated browser** | Your installed Chrome, a fresh profile per session in `%LOCALAPPDATA%\PortGlass\browser-sessions`, deleted when the session ends. Never your personal profile, no system proxy, no global settings. |
| **The device's own address** | The session window shows `http://192.168.1.50/`, mapped onto the tunnel inside that window only, so Host checks, cookies and same-port redirects behave as on the device's LAN. In strict isolation nothing else resolves. |
| **Genuine status** | Red · amber · green · gray, driven by the session state machine, heartbeats, and the probe test-connecting to the device every 10 seconds. |
| **Diagnostics before you're surprised** | Detects HTTPS, shows the device certificate's fingerprint, and warns when the device redirects to a port this session doesn't forward — with a one-click switch. |
| **Least capability** | The probe's whole command surface is open, check, close, and ping. Anything else is rejected and audited. |
| **Audit** | Both ends log operator, probe, destination, port, session start/end and outcome as JSON lines. Never payloads or credentials. |

## Commands

| Controller (`portglass`) | |
|---|---|
| `portglass` | Open the PortGlass window |
| `portglass init [--operator NAME]` | Create this controller's identity and config |
| `portglass fingerprint` | Print this controller's fingerprint |
| `portglass probe add/list/remove` | Manage pinned probes |
| `portglass connect --probe P --target H:PORT [--no-browser]` | Session from the terminal |
| `portglass diag` | Check config, identity, Chrome, and every probe |

| Probe (`portglass-probe`) | |
|---|---|
| `portglass-probe init [--name NAME]` | Create config and identity |
| `portglass-probe run` | Run in this console (default) |
| `portglass-probe authorize --name N --fingerprint F` | Authorize a technician |
| `portglass-probe allow --network NET --ports 80,443` | Allow a destination |
| `portglass-probe check-config` | Show the effective policy |
| `portglass-probe diag --target H:PORT` | Check policy and reachability from the probe |
| `portglass-probe fingerprint` | Print the probe's fingerprint |

Examples of both configuration files: [`examples/`](examples/).

## Known limitations (v0.1.0)

- **Direct mode only.** The technician must be able to reach the probe's port. No relay yet.
- **One target port per session.** A device that serves assets or redirects across ports
  (80 ↔ 443, a separate WebSocket port) needs a session per port; PortGlass tells you when it
  sees the redirect.
- **HTTPS certificates are the browser's call.** Self-signed device certificates produce Chrome's
  normal warning; PortGlass shows the fingerprint so you can compare. It never disables checks.
- **Chrome shows a notice about `--host-resolver-rules`.** That is the per-window address mapping;
  PortGlass never hides it. Set `preserve_address = false` to avoid the flag (see
  [security model](docs/security-model.md#browser-address-mapping)).
- **No Windows service yet.** The probe runs in a visible console by design for v0.1.0.
- **Unsigned development builds.** Release builds are signed in CI once signing is configured
  for this repository; see [deployment](docs/deployment.md#code-signing).

Full list: [docs/security-model.md#known-limitations](docs/security-model.md#known-limitations).

## Development

```powershell
cargo test --workspace                                         # unit + integration
cargo test -p portglass-controller -- --ignored                # real Chrome: e2e + UI capture
./scripts/build.ps1 -Release                                   # dist\ with both binaries
```

How work is routed and reviewed: [CLAUDE.md](CLAUDE.md), [docs/dev-process.md](docs/dev-process.md).
Company standards adoption: [docs/standards.md](docs/standards.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## License

MIT © 2026 Joseph Spillers. See [LICENSE](LICENSE).
