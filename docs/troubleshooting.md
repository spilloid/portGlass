# Troubleshooting

Start with the built-in checks:

```powershell
portglass diag                                   # technician: config, identity, Chrome, every probe
portglass-probe check-config                     # probe: effective policy
portglass-probe diag --target 192.168.1.50:80    # probe: policy decision + test connection
./scripts/diagnostics.ps1                        # both, plus versions, ports and firewall rules
```

The PortGlass window's **Activity** list shows each step of the last session with timestamps.

## The light stays red

| Message | Meaning | What to do |
|---|---|---|
| **Can't reach the relay for probe …** | No TCP connection to the relay | Relay address right? Is `portglass-relay` running, and TCP 47200 open at the VPS provider and on the host? |
| **The relay presented the wrong identity** | Something answered at the relay address with a different certificate | Compare with `portglass-relay fingerprint` on the relay. Don't proceed if you didn't expect a change. |
| **Probe … isn't available through the relay** | The probe isn't registered there, or doesn't authorize this controller | The probe console should say `Registered with relay`. If it says the relay refused it, the relay administrator runs `portglass-relay authorize`. Check that `portglass-probe check-config` lists your fingerprint. See [relay.md](relay.md#troubleshooting). |
| **Can't reach probe …** | No TCP connection to the probe's address and port | Is `portglass-probe run` running? Right address/port? Firewall rule on the probe (`scripts/probe-firewall.ps1`)? On a VPN if required? |
| **Probe … presented the wrong identity** | Something answered at that address with a different certificate | Check the address. If the probe was re-initialized, get its new fingerprint (`portglass-probe fingerprint`), `portglass probe remove` + `add`. If you didn't expect a change, stop and investigate. |
| **Probe … doesn't recognize this controller** | Your certificate isn't in the probe's `[[controller]]` list | Send `portglass fingerprint` to the probe's administrator; they run `portglass-probe authorize`. |
| **This probe isn't allowed to reach that address** | The destination isn't in the probe's `[[allow]]` list | The message includes the exact `portglass-probe allow` command for the administrator. |
| **The device refused the connection** | The device is up but nothing listens on that port | Web interfaces are usually 80 or 443; check the device's settings. |
| **The probe can't reach the device** | Timeout or no route from the probe | Is the device on? Is the address right *from the probe's network*? `portglass-probe diag --target …` |
| **The session expired** | TTL reached | Connect again; pick a longer session length if appropriate (capped by the probe). |
| **The probe's administrator revoked this session** | `probe.toml` changed and no longer allows it | Talk to the administrator. |
| **The connection to the probe was interrupted / stopped responding** | Heartbeats failed; the probe also ends the session on its side | Network between you and the probe. |
| **Device not responding** (while connected) | The tunnel is up but the probe's 10-second test connection to the device failed | The device went offline or is overloaded. |

## The browser opens but the page doesn't work

- **Yellow bar: "You are using an unsupported command-line flag: --host-resolver-rules"** —
  expected; that is PortGlass mapping the device's address onto the tunnel in that window only.
  See [security model](security-model.md#browser-address-mapping).
- **"This site can't be reached … ERR_NAME_NOT_RESOLVED"** after clicking something — the page
  tried to go somewhere other than the forwarded address and port (strict isolation). The
  PortGlass window's **Checks** list usually names it (e.g. "The device redirects to port 443").
  Use the suggested button, or start a session to that port.
- **Certificate warning** — the device uses a self-signed or mismatched certificate. Compare the
  fingerprint in the PortGlass window with Chrome's (click *Not secure* → certificate details)
  before proceeding. PortGlass never bypasses certificate checks.
- **The device logs you out / cookies don't stick** — keep `preserve_address = true` (the
  default) so the browser uses the device's own host name and port.
- **Assets on another port, or a separate WebSocket port** — one session forwards one port. Open a
  second session for the other port, or use the device's single-port mode if it has one.
- **Very old devices (SSL 3 / TLS 1.0 only)** — current Chrome refuses them; PortGlass's check
  reports the handshake failure. Nothing PortGlass can safely do.

## Files and logs

| | Location |
|---|---|
| Controller config / identity / audit | `%APPDATA%\PortGlass\controller\` |
| Session browser profiles (deleted after each session) | `%LOCALAPPDATA%\PortGlass\browser-sessions\` |
| Probe (per-user) | `%LOCALAPPDATA%\PortGlass\probe\` |
| Probe (installed) | `%ProgramData%\PortGlass\` |

More detailed console logging: set `RUST_LOG=debug` before running either program. Debug logs
contain connection metadata, never payload.
