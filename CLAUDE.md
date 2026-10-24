# PortGlass — guidance for AI agents

PortGlass opens one authorized remote web interface in a dedicated, isolated browser over a
mutually authenticated single-port TCP bridge. Rust workspace, Windows first. It is a Spillers
Technology product line; company memory lives in `../corporate-strategy`
(`state/products/PortGlass.md`, motion `board/meetings/2026-10-24-portglass-new-product/`).

Read [`docs/architecture.md`](docs/architecture.md) and
[`docs/security-model.md`](docs/security-model.md) before any unit of work.

## Product rules that override convenience

- **Expose one explicitly authorized TCP service, not a network.** No SOCKS/HTTP proxy, no
  routing, DNS, virtual adapters or packet capture.
- **The probe's capability stays minimal and obvious.** Its command surface is
  `ControlRequest` (open / check / close / ping). Never add execution, file transfer, scanning,
  process launching, persistence, or a way for a data stream to choose its destination.
- **Enforce at the probe.** Anything the controller's UI restricts must also be enforced by the
  probe's policy.
- **Never weaken the browser.** No certificate, sandbox or security flags; no `--test-type` or
  anything else that hides Chrome's own notices; no global proxy or default-browser changes; never
  the technician's own profile. Don't bundle Chromium (D-0049 direction).
- **Never log payload, credentials or tokens.** Audit records are typed metadata only.
- **No stealth.** Visible windows and consoles, version resources, conventional install, no
  silent persistence. Minimize suspicious behavior by minimizing capability, not by hiding.
- **Status reflects real connectivity.** The indicator is derived from the state machine and live
  checks, never set directly.
- **Visual polish is part of the product.** Run the UI capture and look at the screenshots.

## Roles

Claude (the orchestrator session) owns architecture, contracts/tests, the final diff, and all
validation. Implementers and reviewers are consultants. Never accept a change because a bigger
model wrote it — only because it was run and held up. Method: corporate-strategy
`standards/STD-001-adversarial-review.md`.

## Routing — two model families, matched to the work

| Work | Implementer | Reviewer |
|---|---|---|
| Mechanical: docs, scripts, config, boilerplate mirroring an existing pattern | `codex-luna` or Claude **Haiku** | Terra / Sonnet |
| Default feature work: controller UI, CLI, diagnostics | Claude **Sonnet** / `codex-terra` | the *other* family |
| Window design and motion | Claude **Opus** | Sonnet + screenshot inspection (UI capture) |
| TLS/identity, probe policy, sessions/revocation, bridge concurrency, protocol, browser process lifetime | `codex-sol` (**gpt-6.1-sol**, high) or Claude **Opus** | the other family at the top tier — regardless of diff size |
| Release-gate / whole-system adversarial review | — | `codex-astra` (**gpt-6-astra**, ultra) — scarce, review only |

- Cross-family review by default. If one family is unavailable, substitute the other family's
  matching tier, and log it as a same-family substitute — not as cross-family review.
- Codex tiers go through `.claude/agents/codex-*.md` dispatchers; Claude tiers through the Agent
  tool's `model` override.
- Sol/ultra **as implementer** needs the operator's explicit in-session approval.

## Standing review rules (STD-001)

- A finding can be right about the problem and wrong about the fix — adjudicate, choose the fix.
- Re-read diffs after a fix round.
- When a reviewer indicts the spec, believe it.
- Review reads diffs; session lifetime, process cleanup and shutdown ordering need live runs
  (`cargo test -- --ignored`, the demo script).
- Verify before trusting, both directions. A green suite is evidence about the tests — have
  reviewers grade the tests, and prove a new check can fail.
- A dispatcher's report is a claim, not proof. Check exit codes and output files yourself.
- Log every round in [`docs/dev-process.md`](docs/dev-process.md).

## Conventions

- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
  before every commit; `-- --ignored` (real Chrome) for browser/UI changes.
- Console output is ASCII (Windows consoles mangle UTF-8); the window may use typography.
- Behavior changes update docs and `CHANGELOG.md` in the same commit (STD-003).
- Commits: no AI attribution lines. Conventional-ish prefixes (`feat:`, `fix:`, `docs:`).
  Author `Joseph Spillers <jdspille@gmail.com>`.
- Never push, merge, tag or publish a release without the operator's explicit go-ahead.

## Things to re-verify before trusting them

Dated claims that no automated check covers yet (STD-003 rule 4):

- **2026-10-24** — Chrome honors `--host-resolver-rules` `MAP host:port` for IP literals and
  `MAP * ~NOTFOUND` blocks other hosts (verified by `tests/browser.rs` on Chrome stable of that
  date). Chrome could change or remove this flag; re-run the browser test on Chrome updates.
- **2026-10-24** — The profile `Preferences` seed (`credentials_enable_service`, `autofill`,
  `browser.theme.user_color2`) is honored. Password-saving suppression is asserted nowhere;
  the theme color was not observed to apply.
- **2026-10-24** — A Chrome process once survived session close in an early real-browser run.
  Plausibly the job-assignment race fixed by suspended spawn (dev-process row 6), not proven.
  The non-DISCONNECTED end state from the same period is explained and fixed (row 6).
- **2026-10-24** — The tunnel gate relies on Chrome's network service living in the browser's
  Job Object (nested-job semantics of `IsProcessInJob`). Verified by `tests/browser.rs` on that
  date's Chrome stable; a Chrome change that moves networking out of the job would break
  sessions loudly (refused connections), not open the tunnel.
- **2026-10-24** — The security/concurrency code has had a same-family (Opus) adversarial review
  only. Cross-family Codex Sol review is pending (dev-process row 7).
- **2026-10-24** — EDR behavior is unobserved. No security product has been run against PortGlass.
- **2026-10-24** — Signing is wired but unconfigured for this repository; no signed build exists.
