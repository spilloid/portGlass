# Security model and threat analysis

For administrators and security teams deciding whether to allow PortGlass. Short version:
PortGlass is a **single-destination, time-limited, mutually authenticated TCP forwarder** with a
visible user interface on both ends. It has no command execution, file transfer, scanning,
persistence or general forwarding to abuse, and it is designed to be easy to see and audit
rather than hard to detect.

## What each component can do — and cannot

| | Probe | Controller | Relay (optional) |
|---|---|---|---|
| Accepts network connections | Yes: one TCP port, mutual TLS only | Only on `127.0.0.1`: the UI (token-guarded) and the tunnel endpoint (session browser processes only) | Yes: one TCP port, TLS; pairs only listed probes with the controllers they publish |
| Makes network connections | To destinations in its own allowlist, for authorized sessions only; to its configured relay, if any; GitHub once at startup to look for an update (off with `PORTGLASS_NO_UPDATE_CHECK`) | To pinned probes, directly or through a pinned relay; GitHub, as the probe | GitHub, as the probe |
| Runs other programs | No (`icacls` once, at `init`, to restrict its private key) | Chrome (session and UI windows, started suspended, placed in a Job Object, then resumed); `reg`/`taskkill` for Chrome discovery and cleanup | No (`icacls` once, at `init`, on Windows) |
| Reads/writes files | Its config, identity, audit log; its own program file, only when a person runs `update` | Its config, identity, audit log, session browser profiles; its own program file, only when a person chooses *Update* | Its config, identity, audit log; its own program file, only on `update` |
| Elevation | None required | None required | None required |
| Persistence | None. Runs in a visible console until stopped | None | Whatever its administrator sets up (a systemd unit is provided) |
| Changes system settings | No | No (no proxy, routes, DNS, certificates, default browser) | No |

The probe's entire remote command surface is: open a session, check a session's target, close a
session, ping. That is a closed Rust enum with `deny_unknown_fields`; an unknown command is
answered with `unsupported`, audited, and the connection is closed.

## Trust model

- **Identities** are self-signed ECDSA P-256 certificates generated on each machine. Private keys
  never leave the machine that made them.
- **The probe trusts controllers** whose SHA-256 certificate fingerprint is in its
  `[[controller]]` list, and audits them by the *name the probe's administrator gave them*, not
  by anything the controller claims.
- **The controller trusts one probe identity per entry**: the fingerprint the technician pinned.
  A different certificate at the same address fails with "presented the wrong identity".
- Both checks happen inside the TLS 1.3 handshake (custom rustls verifiers that compare
  fingerprints in constant time and delegate signature verification to rustls), so an
  unauthorized party never reaches the protocol. TLS 1.2 is not offered on these connections.
- **Fingerprint exchange is out of band** and is the security-critical step of enrollment. Verify
  fingerprints over a channel you already trust (ticket system, phone, in person).
- **No TLS session resumption** on the probe (no session cache, no tickets): every connection
  runs the allowlist check, so a revoked controller cannot resume an earlier session. The probe
  also re-checks the allowlist after each handshake and again after `Hello`.
- **The controller treats the probe as untrusted input.** The probe runs on a customer machine,
  a weaker trust domain than the technician's PC. Session ids and tokens must be fixed-length
  lowercase hex or the session is refused, and nothing a probe sends is used as a path:
  browser profile directories are named by the controller.

## Authorization at the probe

The probe decides every destination itself; the controller's UI only displays the probe's
policy.

1. **Deny by default.** Only `[[allow]]` entries (an address or CIDR network plus ports) are
   reachable.
2. **Never reachable:** unspecified (`0.0.0.0`, `::`, `0.0.0.0/8`), broadcast, multicast.
3. **Reachable only through a rule written for them:** loopback (`127.0.0.0/8`, `::1`),
   link-local (`169.254.0.0/16` — which includes cloud metadata at `169.254.169.254` — and
   `fe80::/10`), and other metadata/host-agent endpoints (Azure `168.63.129.16`, Alibaba
   `100.100.100.200`, AWS IPv6 `fd00:ec2::254`). A broad rule such as `0.0.0.0/0` does not open them.
4. **IPv6 forms of IPv4 addresses** inherit the IPv4 address's restrictions: IPv4-mapped
   (`::ffff:127.0.0.1`), IPv4-compatible (`::127.0.0.1`) and NAT64 (`64:ff9b::7f00:1`).
5. **Host names** are resolved on the probe once, at session open. Every resolved address must be
   allowed (a name that resolves into both an allowed and a disallowed network is denied), and
   the session is pinned to one address for its whole life — later DNS answers cannot move it.
6. **Data streams cannot choose a destination.** They present a session id and 256-bit token,
   must come from the same controller certificate that opened the session, and are connected to
   that session's pinned address.
7. **Limits:** concurrent sessions per probe, streams per session, maximum session TTL, per-stream
   idle timeout, control-connection silence timeout, 64 pending TLS handshakes (8 per source
   address, 5-second handshake timeout), 4 in-flight session/check requests per control
   connection, rate-limited and length-bounded denial audits, 16 KiB frames. A controller that
   stops reading for 5 seconds is disconnected (and its sessions end).
8. **The probe's own LAN addresses are not special.** A subnet rule that includes the probe's
   own address exposes the probe computer's listening services on the allowed ports. Write rules
   for the devices, not whole subnets, where you can.

## Session expiry and revocation

A session ends — and every forwarded connection of it is cut immediately — when:

| Trigger | Who |
|---|---|
| The technician ends it, or closes the session browser | Controller |
| Its TTL passes (requested, capped by `max_session_ttl_secs`) | Probe |
| The control connection closes or is silent for `control_timeout_secs` | Probe |
| The administrator edits `probe.toml` so the controller or destination is no longer allowed (applied within ~2 s) | Probe |
| `probe.toml` becomes invalid — the probe **fails closed**: it revokes everything until fixed | Probe |
| The probe is stopped (Ctrl+C) | Probe |

## Audit

Both ends append JSON lines (`audit.jsonl`). The probe records: start/stop; controller
connect/disconnect (operator, fingerprint, peer address, client version); rejected certificates
(fingerprint, rate-limited); session opened/denied/ended (operator, requested target, resolved
address, rule label, TTL, reason, duration, stream counts, byte counts); failed streams; rejected
commands; configuration changes. The controller records requested/ready/ended/failed sessions.

**Never recorded:** forwarded bytes, HTTP content, credentials, cookies, session tokens. The
bridge has no access to a logger; the audit API accepts typed metadata only. A test submits a
password through the tunnel and asserts it appears in neither audit log.

## Browser address mapping

By default the session browser is started with `--host-resolver-rules`, which maps the device's
own address onto the local tunnel **inside that one Chrome process**, and — in strict isolation —
makes every other host name unresolvable there. Consequences you should know:

- **It is visible.** Chrome shows "You are using an unsupported command-line flag". PortGlass
  never suppresses that notice (for example with `--test-type`), because hiding it is exactly
  what malicious launchers do; PortGlass's own window explains it instead.
- **EDR may notice it.** Some products flag Chrome launched with resolver rules. Allow
  `portglass.exe` launching `chrome.exe` with `--user-data-dir` under
  `%LOCALAPPDATA%\PortGlass\browser-sessions\` — see [deployment](deployment.md#edr-and-allowlisting).
- **Opting out:** `[browser] preserve_address = false` and `isolation = "open"` launch Chrome with
  no unusual flags at `http://127.0.0.1:<port>/`. Devices that redirect to their own address then
  leave the tunnel; PortGlass warns when it sees that.

## The local tunnel endpoint

The controller listens on `127.0.0.1:<random>` for the session browser. Every process on the
technician's PC can reach that address — other users on a shared host, local malware, a web page
in the everyday browser using DNS rebinding — so the controller admits a connection **only if
the process that owns its client socket is part of the session browser's Job Object** (owning
process from the Windows TCP table, membership via `IsProcessInJob`). Everything else is closed
before any byte reaches the probe, and counted in the window. Chrome is started suspended,
assigned to the job, then resumed, so every process it ever starts is inside the job; if
containment fails, the browser is not launched. **On macOS** there are no job objects: the session browser leads its own process group (ended as a
whole when the session closes), and a connection is admitted only if `lsof` names a process that
descends from that browser (`proc_pidinfo` ancestry). Unlike Windows, Chrome is not contained if
the controller itself crashes.
`portglass connect --no-browser` deliberately
opens the endpoint to any local process and says so in the window.

The session browser is started with `--no-proxy-server`, so device traffic never goes to a
system proxy or PAC file. **Enterprise Chrome policy still applies** to the session profile (for
example a forced proxy mode or force-installed extensions); PortGlass cannot and does not
override policy.

## The local UI

The controller window is a page served on `127.0.0.1:<random>`. Defenses: random 192-bit token
on every request; `Host` must be exactly the listener address (blocks DNS rebinding); `Origin`,
when sent, must be the same origin; POSTs require `application/json` (forces a CORS preflight
from any other origin); `Content-Security-Policy` with `frame-ancestors 'none'`, `nosniff`,
`no-store`. Another program running as the same Windows user can still read the token from the
process command line — same-user processes are inside the trust boundary on Windows.

## Threat analysis

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Someone on the network connects to the probe | Mutual TLS: no allowlisted certificate, no protocol. Handshake timeout and pending-handshake cap. | The port is discoverable and identifies itself as PortGlass in its certificate. Restrict it with Windows Firewall. |
| T2 | Impersonated probe (DNS/ARP spoofing) | Controller pins the probe's fingerprint. | Enrollment trusts whatever fingerprint the technician pins. |
| T3 | Stolen controller identity | Probe admin removes the fingerprint; live reload disconnects it within ~2 s. | Key is a file under the user's profile protected by NTFS ACLs, not DPAPI or a TPM (future work). |
| T4 | Authorized technician reaches more than intended | Allowlist at the probe, special ranges, DNS pinning, data streams bound to sessions, audit. | Whatever the administrator allows is reachable; write narrow rules. |
| T5 | Probe used as a pivot / port scanner | Destinations are allowlisted; each session test-connects one address; requests are audited. | An authorized controller can probe *allowlisted* ports for liveness. |
| T6 | Session outlives its purpose | TTL, close, browser-close, control-loss revocation; cancellation reaches every stream. | The device-side TCP connection closes when the probe drops it; device-side sessions (logins) persist per the device's own rules. |
| T7 | Payload or credential disclosure | End-to-end TLS between the two PortGlass ends; device TLS (HTTPS) runs end to end inside it; nothing logs payload. | Plain-HTTP devices are plaintext on the remote LAN segment between probe and device, exactly as they are today. |
| T8 | Malicious page in the session browser | Isolated, throwaway profile; strict isolation; Chrome's own sandbox and certificate checks unchanged. | A compromised device can attack the browser like any web page. |
| T9 | Local web page attacks the controller UI | Token, Host and Origin checks, JSON-only POSTs, CSP. | Same-user processes can read the token. |
| T10 | Resource exhaustion | Frame size caps, stream/session limits, handshake cap, idle and silence timeouts, rate-limited auth-failure audit. | A flood of TCP connections still costs accept() work; use the firewall. |
| T11 | Tampered binaries | Version resources and Authenticode signing in the release pipeline; an Ed25519-signed manifest of every released binary. | Development builds are unsigned. |
| T12 | Compromised probe attacks the technician's PC | Probe strings validated (fixed-format ids/tokens, never used as paths); the probe can only answer within the protocol; the device page runs in an isolated, throwaway browser profile. | A compromised probe controls what the technician sees from the device. |
| T13 | Other local software uses an open tunnel | Tunnel endpoint admits only session-browser processes. | Same-user code that injects into Chrome is inside the browser's trust boundary. |
| T14 | Malicious or compromised relay | The relay never terminates the PortGlass TLS: controller and probe authenticate each other end to end through it, pinned at both ends, and the probe applies its own allowlist and policy to every relayed connection exactly as to a direct one. The relay holds neither key. | It sees metadata (which fingerprints meet, when, from which IPs, byte counts) and can refuse, drop, delay or throttle connections. |
| T15 | Stranger uses the relay | Only probes listed in `relay.toml` can register. A controller is paired only with a registered probe whose published allowlist contains its fingerprint, and gets one indistinguishable answer otherwise. Tickets are random 128-bit values bound to the probe they were issued to. Handshake, waiting and per-probe pair caps apply. | Anyone can complete a TLS handshake with the relay and learn that it is a PortGlass relay. Bound by the handshake caps, as T1. |
| T16 | Hostile relay floods the probe | Relayed answers share the probe's pending-handshake cap and then face its normal mutual TLS. A relay can make the probe dial back, but not get past authentication. | Bounded CPU and connection churn on the probe while the relay misbehaves; remove `[relay]` to stop it. |
| T17 | Malicious update | Installed only on a person's action. The manifest must verify against a release key compiled into the running build (never fetched), name a strictly newer `x.y.z` version and plain file names, and the download must match its SHA-256 and size before anything is renamed. The signing key exists only as a secret of the repository's `release` environment and offline; CI verifies each signed manifest against the compiled-in key before publishing it. | Theft of the signing key, or a malicious commit that the pipeline builds and signs. A withheld or delayed update (an attacker can block GitHub). Rotating a key needs a release that trusts the successor. Two copies updating at the same moment are not serialized (a version floor beside the program stops later rollbacks). On Windows the running program is renamed aside and the new one renamed in; a crash between the two renames leaves only `<program>.old`, which must be renamed back by hand. |

## Known limitations

- The relay is a server someone has to run. It sees connection metadata, though never content.
  There is no hosted relay service.
- A probe registers with at most one relay.
- One device per session. Its web partner port (80/443, 8080/8443) and same-device redirect
  targets ride along as extra probe sessions when the probe's policy allows them (at most two);
  any other port needs its own session. Extra ports are opened against the IP the probe
  pinned for the main session, so they always reach the same machine. A device can choose which
  of its own allowed ports come along by redirecting to them; write allow rules for the ports you
  mean, not wide ranges.
- Private keys are ACL-protected files, not DPAPI/TPM-backed.
- No Windows service mode; the probe runs in a visible console.
- The probe's listener exposes TLS on one port to whatever the firewall allows.
- No central enrollment or allowlist management; configuration is per probe file.
- Audit logs are local files without tamper evidence; forward them to your SIEM if needed.
- IPv6 targets work at the TCP level but the session browser falls back to `127.0.0.1` URLs for them.
- Lowering `max_session_ttl_secs` does not shorten sessions already open (lowering
  `max_streams_per_session` applies to new connections immediately; removing a rule revokes).
- Strict isolation requires `preserve_address = true`; with address mapping off there are no
  resolver rules at all.
