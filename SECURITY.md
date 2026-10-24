# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's **Report a vulnerability**
(Security → Advisories) on this repository, or by email to jdspille@gmail.com. Include the
version, what you did, and what happened. Please don't open a public issue for a security
problem. Expect an acknowledgement within a week.

In scope: anything that lets someone reach a destination a probe's policy does not allow,
connect without an authorized certificate, keep a session alive after it should end, read
forwarded traffic, make the probe do anything other than forward an authorized session, attack
the controller's local window, or weaken the session browser.

## Supported versions

Only the latest release receives fixes. PortGlass is pre-1.0.

## Design

How PortGlass is meant to be safe, what it deliberately cannot do, and its known limitations:
[docs/security-model.md](docs/security-model.md).

## Secrets

This repository contains **no deployment secrets and no real identities**. Certificates and
private keys are generated on each machine by `init` and never committed (`*.key` is ignored).
The files in [`examples/`](examples/) are templates with fictional fingerprints. Release signing
uses an Azure federated credential (OIDC); no signing key or secret is stored in the repository.
Session tokens and device credentials are never written to logs or disk by PortGlass.
