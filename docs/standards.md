# Company standards in PortGlass

Adoption of corporate-strategy `standards/STD-*.md` in this repository, as of 2026-10-24.

| Standard | Status | Where / why |
|---|---|---|
| STD-001 Orchestrated, adversarially-reviewed development | adopted | `CLAUDE.md` routing; `docs/dev-process.md` log. First review round used a same-family substitute (Codex usage-limited) — see the log. |
| STD-002 PR template | adopted | `.github/PULL_REQUEST_TEMPLATE.md`, checked in CI (`standards` job). |
| STD-003 Documentation freshness | adopted | README states the Cargo version and CHANGELOG's latest entry matches it, both checked in CI; dated quarantine list in `CLAUDE.md`. |
| STD-004 Identity architecture | deviates (by design) | PortGlass has no user accounts. Its identity model is device certificates pinned by fingerprint (SSH-style), which suits two-party machine trust better than local auth + OIDC + bearer tokens. Revisit if a central enrollment/fleet service is built. |
| STD-005 Agent-facing surface (MCP) | not applicable | No agent-facing API in v0.1.0. An agent-operable probe would need its own motion. |
| STD-006 Secret handling | adopted (a, b) | (a) no deployment secrets committed; signing uses OIDC — stated in `SECURITY.md`. (b) session tokens and device credentials are never logged or persisted; tested for the audit logs. |
| STD-007 Repo metadata | adopted (license, changelog) | MIT LICENSE (`Joseph Spillers`), `CHANGELOG.md`. AI attribution: none, per the operator's standing preference. |
| STD-008 UI capture & overflow validation | adopted, **mechanism deviates** | `crates/portglass-controller/tests/ui_capture.rs` drives headless Chrome over DevTools: every window state × light/dark × 500/1280/390 px; fails on horizontal overflow, clipped elements, browser errors, or a status light that disagrees with the state. Rust instead of a `docs/scripts/capture-*.mjs` Playwright script because this repo has no Node toolchain; `standards/check.sh` won't detect it until its STD-008 check learns this shape. Wired into CI (`ui_capture` step). |
