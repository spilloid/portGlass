# Deployment

## Installing the probe

The probe needs no elevation to run. Installing it under Program Files, writing its configuration
under ProgramData, and adding a firewall rule do need an administrator — once.

```powershell
# As Administrator, from an extracted release folder:
./scripts/install-probe.ps1 -Name front-office
# Optional, scoped to your technicians' addresses:
./scripts/probe-firewall.ps1 -RemoteAddress 10.0.5.0/24
```

`install-probe.ps1`:

- copies `portglass-probe.exe` to `%ProgramFiles%\PortGlass\`;
- creates `%ProgramData%\PortGlass\` readable only by Administrators, SYSTEM, and the user you
  name with `-RunAsUser` (default: you), and runs `portglass-probe init` there;
- creates a Start menu shortcut **PortGlass Probe** that opens the visible console;
- registers nothing to start automatically: no service, no scheduled task, no Run key.

Remove everything with `./scripts/uninstall-probe.ps1` (add `-KeepConfig` to keep identity,
configuration and audit log).

Then authorize technicians and destinations:

```powershell
portglass-probe --config "$env:ProgramData\PortGlass\probe.toml" authorize --name alice --fingerprint sha256:...
portglass-probe --config "$env:ProgramData\PortGlass\probe.toml" allow --network 192.168.1.50 --ports 80,443 --label "Front office printer"
portglass-probe --config "$env:ProgramData\PortGlass\probe.toml" check-config
```

Write narrow rules. `network = "192.168.1.50"` with `ports = [80, 443]` is the intended shape; a
whole subnet with a port range is possible but grants more.

### Starting automatically

v0.1.0 intentionally has no service mode. If your organization decides the probe should start
with Windows, create that yourself (for example a scheduled task at logon running
`portglass-probe run` in a visible window) and document it — PortGlass will not do it silently.

## Windows Firewall

The probe listens on TCP 47100 by default (`[probe] listen`). Windows will ask the first time
the probe listens on a non-loopback address; prefer an explicit, narrow rule:

```powershell
New-NetFirewallRule -DisplayName "PortGlass Probe" -Direction Inbound -Action Allow `
  -Program "$env:ProgramFiles\PortGlass\portglass-probe.exe" -Protocol TCP -LocalPort 47100 `
  -RemoteAddress 10.0.5.0/24 -Profile Domain,Private
```

`scripts/probe-firewall.ps1 -RemoteAddress <technician addresses>` creates exactly that rule
(and `-Remove` deletes it). The probe makes ordinary outbound TCP connections to allowlisted
destinations; no outbound rule is normally needed.

On the technician's PC nothing listens on the network: the tunnel endpoint and the UI are bound
to `127.0.0.1`.

**Connectivity:** in direct mode the technician's PC must reach the probe's address and port:
same LAN, routed internal network, or an existing authorized VPN. If both sides are behind NAT
with no VPN, use a [PortGlass Relay](relay.md). The probe then also makes one long-lived
**outbound** TCP connection to the relay (default port 47200), plus one outbound connection per
forwarded browser connection. Its `listen` port doesn't need to be reachable from anywhere, so
you can leave the Windows Firewall rule out or scope it to the LAN.

## EDR and allowlisting

PortGlass is designed to look like what it is. Expect, and allow, these behaviors:

| Binary | Behavior | Why |
|---|---|---|
| `portglass-probe.exe` | Listens on TCP 47100 (configurable) | Accepts mutually authenticated controller connections |
| `portglass-probe.exe` | Outbound TCP to allowlisted LAN addresses | The forwarding itself |
| `portglass-probe.exe` | Runs `icacls.exe` once during `init` | Restricts its private key's ACL |
| `portglass.exe` | Starts `chrome.exe` with `--user-data-dir=%LOCALAPPDATA%\PortGlass\browser-sessions\<id>`, `--app=`, `--host-resolver-rules=`, `--no-proxy-server` | The dedicated session browser |
| `portglass.exe` | Creates Chrome **suspended** (`CREATE_SUSPENDED`), assigns it to a Job Object, then resumes its threads | Contains every Chrome process from the first instruction, for cleanup and for the tunnel's access check. Some EDR products associate suspended-start-then-resume with process hollowing; PortGlass writes nothing into the process. |
| `portglass.exe` | Reads the TCP connection table and opens local processes with query-only rights (`IsProcessInJob`) | Admits only session-browser connections to the tunnel endpoint |
| `portglass.exe` | Terminates the job's processes, runs `taskkill.exe /T` as a fallback | Ends the session browser with the session |
| `portglass.exe` | Runs `reg.exe query ...\App Paths\chrome.exe` | Finds Chrome |
| `portglass.exe` | Listens on `127.0.0.1` ephemeral ports | Tunnel endpoint and window |

It does **not** inject into processes, hide windows or processes, modify security products,
obfuscate traffic (it is standard TLS 1.3 with ALPN `portglass-control/1` / `portglass-data/1`),
change proxies, DNS, routes or certificates, or persist.

Recommendations:

1. Allowlist by **publisher signature** (release builds are Authenticode-signed), not by path or
   hash alone.
2. If your EDR alerts on `chrome.exe --host-resolver-rules` or on `portglass.exe` starting
   Chrome suspended, scope an exception to parent
   `portglass.exe` and `--user-data-dir` under `%LOCALAPPDATA%\PortGlass\browser-sessions\`, or
   set `preserve_address = false` (no unusual flags; see the security model for the trade-off).
3. Forward both `audit.jsonl` files to your SIEM.
4. Do not assume security software will trust PortGlass automatically; pilot it on one probe and
   one technician first and review what your tools report.

## Code signing

Release binaries are signed in GitHub Actions with Azure Artifact Signing through
`.github/actions/sign-release` (the same mechanism as SpoolSmith), RFC 3161 timestamped, and
verified before anything is attached to a release. The release workflow **refuses to publish
unsigned binaries**. Until this repository's `release` environment is configured
(`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` secrets; `SIGNING_ENDPOINT`,
`SIGNING_ACCOUNT`, `SIGNING_PROFILE`, `SIGNING_EXPECTED_SUBJECT` variables, and a federated
credential trusting `…:environment:release` for this repository), releases fail closed. Run the
**Signing check** workflow after configuring it. Builds from source and CI artifacts are
unsigned development builds.

Executables carry version resources (Explorer → Properties → Details: *PortGlass Probe* /
*PortGlass Controller*, product *PortGlass*, version, copyright).

## Updating and removing

Stop the probe (Ctrl+C), replace the binary, start it again. Sessions do not survive a restart by
design. Controllers: replace `portglass.exe`. Both keep their identities and configuration.
