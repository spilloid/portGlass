# PortGlass Relay

Use a relay when the technician's PC can't reach the probe's port: the probe is behind a NAT
router, there's no VPN, and you don't want to forward a port to it. Both sides dial **out** to the
relay; the relay pairs them and copies bytes. The ordinary PortGlass connection, mutual TLS pinned
at both ends, runs inside that pipe, so the relay carries ciphertext it can't read or alter.

```
technician PC ──outbound──▶  relay (public, TCP 47200)  ◀──outbound── probe (behind NAT)
     └──────────── end-to-end mutual TLS (unchanged) ────────────────────┘
```

You need one machine both sides can reach. A small Linux VPS is plenty: the relay is one
process using a few megabytes of memory, plus about 100–150 KB per live browser connection.
Choose a plan by **bandwidth allowance and location**, not RAM. Every byte of a session passes
through the relay, and its distance from you and the site adds latency.

## Set up the relay (Linux VPS)

1. Download `portglass-relay-<tag>-linux-x64.tar.gz` from the release and check it:

   ```sh
   sha256sum -c portglass-relay-<tag>-linux-x64.tar.gz.sha256
   tar xzf portglass-relay-<tag>-linux-x64.tar.gz
   sudo install -m 0755 portglass-relay/portglass-relay /usr/local/bin/
   ```

2. Create a user and the configuration. `init` writes `relay.toml` and the relay's identity, and
   prints the **relay fingerprint**. Probes and technicians pin that fingerprint.

   ```sh
   sudo useradd --system --home /var/lib/portglass-relay --create-home portglass-relay
   sudo -u portglass-relay portglass-relay --config /var/lib/portglass-relay/relay.toml init --name my-relay
   ```

3. Open TCP **47200** in the VPS provider's firewall and in `ufw`/`firewalld` if you use one.
   That is the only port the relay needs.

4. Run it as a service. Copy `portglass-relay.service` from the package to
   `/etc/systemd/system/`, then:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now portglass-relay
   journalctl -u portglass-relay -f
   ```

   You can also run `portglass-relay --config ... run` in a terminal (Ctrl+C stops it).

## Pair a probe through the relay

On the **probe** PC, either answer the relay question in the first-run setup or run:

```powershell
portglass-probe use-relay --address relay.example.com:47200 --fingerprint <relay fingerprint>
```

Restart the probe. It will report `Relay registration refused` until the relay authorizes it.
Get the probe's fingerprint (`portglass-probe fingerprint`), then on the **relay**:

```sh
sudo -u portglass-relay portglass-relay --config /var/lib/portglass-relay/relay.toml \
  authorize --name front-office --fingerprint <probe fingerprint>
```

The relay applies changes to `relay.toml` within a few seconds. The probe retries every
30 seconds after a refusal, and its console says `Registered with relay ...` once it's in.

On the **technician's PC**, in *Add probe*, fill in the name and probe fingerprint as usual, open
**Not on the same network? Connect through a relay**, and enter the relay address and relay
fingerprint. The probe address can stay empty. From the terminal, the same thing is:

```powershell
portglass probe add --name front-office --fingerprint <probe fingerprint> `
  --relay relay.example.com:47200 --relay-fingerprint <relay fingerprint>
```

Technicians are **not** listed on the relay. Each probe tells the relay which controller
fingerprints its own `probe.toml` accepts, and the relay pairs only those. Authorizing or
removing a technician stays a probe-side decision, as it is without a relay.

## What the relay can and cannot do

| | |
|---|---|
| Sees | Which probe and which controller fingerprints connect, when, from which IP addresses, and how many bytes. All of this goes into its audit log. |
| Cannot see | The device, the address, the pages, credentials or anything else inside a session. That is end-to-end TLS between controller and probe. |
| Cannot do | Impersonate a probe or a controller (it has neither key), reach any network the probe can, or open a session the probe's own policy wouldn't allow. |
| Can do | Refuse or drop connections (denial of service), and observe the metadata above. Run it on a machine you control. |

## Limits (`[limits]` in relay.toml)

| Setting | Default | Meaning |
|---|---|---|
| `max_pairs_per_probe` | 256 | Live spliced connections per probe. Each browser connection is one. |
| `max_waiting_per_probe` | 32 | Controller requests waiting for that probe to answer. |
| `answer_timeout_secs` | 10 | How long a controller waits for the probe to answer. |
| `idle_timeout_secs` | 300 | A splice with no traffic in either direction for this long closes. |
| `registration_timeout_secs` | 45 | A silent probe registration is dropped. Probes ping every 15 s. |

There are also fixed caps on unauthenticated handshakes: 128 in total and 16 per source address.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Probe: `relay ... refused this probe: this relay does not list probe ...` | Not authorized on the relay | Run `portglass-relay authorize` with the fingerprint the message shows. |
| Probe: `can't reach the relay` | Address, DNS, or the VPS firewall | Check that TCP 47200 is open at the provider *and* on the host. |
| Window: *The relay presented the wrong identity* | Relay fingerprint mistyped, or a different server at that address | Compare with `portglass-relay fingerprint` on the relay. |
| Window: *Probe X isn't available through the relay* | Probe offline or not registered, or it doesn't authorize this controller | The probe console should say `Registered with relay`. Check `portglass-probe check-config` lists your fingerprint. |
