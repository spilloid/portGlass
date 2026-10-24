## What changed

<!-- What problem does this solve, and for whom? Link the issue or motion if there is one. -->

## How it was checked

- [ ] `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Touches the browser or the window: `cargo test -p portglass-controller -- --ignored` (real Chrome e2e + STD-008 UI capture), and the screenshots looked at
- [ ] Touches the probe's policy, TLS, sessions or protocol: reviewed adversarially per `CLAUDE.md` routing, and logged in `docs/dev-process.md`
- [ ] The probe still cannot do anything beyond open / check / close / ping a session to an allowlisted destination
- [ ] Nothing logs payloads, credentials, or session tokens
- [ ] Docs and `CHANGELOG.md` updated in this change if behavior changed
- [ ] Only synthetic, authorized test data: mock devices, loopback addresses, throwaway identities — no real customer networks, devices, fingerprints or credentials

## Evidence

<!-- Logs, screenshots, or a short reproduction. -->
