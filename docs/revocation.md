# Revocation runbook

What to do when a technician's PC is lost or stolen, or a controller's private key may have been
copied. Speed matters more than thoroughness in the first step.

## What a stolen controller can do

A controller's private key is its identity. Whoever holds it can do what that technician could:
open sessions to the destinations each probe allows, for up to each probe's
`max_session_ttl_secs`, from anywhere the probe (or its relay) is reachable.

- **It never expires.** Controller keys have no lifetime and there is no central revocation list.
  The key keeps working on every probe that lists its fingerprint **until each probe's
  administrator removes it**.
- The PC also holds `controller.toml`: the pinned probes' names, addresses, fingerprints and
  relays. It holds no probe private keys.
- Revocation is per probe. A probe you don't edit still trusts the key.

## 1. Revoke at every probe (minutes)

On each probe that lists the controller, remove its `[[controller]]` entry from `probe.toml`
(match by `fingerprint`, not only `name`) and save.

- The probe applies the change within about 2 seconds and ends that controller's sessions,
  cutting every forwarded connection ([session ends](security-model.md)).
- New connections fail inside the TLS handshake. The probe keeps no TLS session cache or
  tickets, so the old key cannot resume anything.
- If you can't edit a probe right away, **stop it** (Ctrl+C, or close its window). A stopped probe
  accepts no one.
- Nothing is needed at the relay. It pairs only controllers that each probe's own allowlist
  accepts, and the probe authenticates the controller end to end in any case.

Keep a list of which probes each technician was added to, so this step doesn't depend on memory.

## 2. Check what happened

Each probe's `audit.jsonl` records controller connects with the operator name and fingerprint,
peer address, and every session's destination, port, start, end and outcome. Look for
connections by the revoked fingerprint after the time the PC went missing.

## 3. Give the technician a new identity

On the replacement (or cleaned) PC:

1. If a controller config already exists, move it aside. `portglass init` refuses to overwrite
   one. It lives in `%APPDATA%\PortGlass\controller` on Windows and
   `~/Library/Application Support/PortGlass/controller` on macOS.
2. Run `portglass init` and send the new fingerprint to each probe's administrator **over a channel
   you already trust** (ticket system, phone, in person), as at first enrollment.
3. The administrator adds a new `[[controller]]` entry with the new fingerprint.
4. Re-add each probe from its pairing code (`portglass-probe pairing-code` on the probe).

Never reuse the old identity files, even if the PC turns up.

## If a probe's key is compromised

Re-initialize that probe (`portglass-probe init` in a fresh directory), then on every controller
`portglass probe remove` the old entry and add the new pairing code. A controller pinned to the
old fingerprint refuses the new probe ("presented the wrong identity") until it's re-pinned. If
the probe uses a relay, replace its `[[probe]]` fingerprint in `relay.toml`.
