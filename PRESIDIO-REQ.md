# PRESIDIO-REQ — presidio-hardened-ai

Requirements baseline for `presidio-hardened-ai`: a hardened security layer for
AI / LLM client integrations in the PRESIDIO toolkit.

## Overview

Build a production-ready Python package named `presidio-hardened-ai` that acts as a
hardened security layer / drop-in wrapper for AI/LLM client usage. Users adopt it
with minimal code changes while automatically receiving strong Presidio security
defaults. Do **not** copy upstream source — wrap/extend via re-exports, subclassing,
or middleware.

## Open scoping decisions (v0.1.0)

These must be resolved before implementation and recorded here:

- **Target surface** — which AI/LLM SDK or interface is wrapped (e.g. a provider
  SDK client, a generic HTTP LLM client, or an agent framework). Decide and record.
- **Hardening primitives** — confirm the v0.1.0 subset of the security extensions below.
- **Public vs. private** — currently private; promote to public + MIT badge + branch
  protection per the GitHub repo-config runbook when ready to publish.

## Mandatory Presidio Security Extensions

- Secret/credential redaction at the logging sink (no PII, tokens, or keys in logs)
- Prompt-injection detection and unsafe-output guards
- Strict TLS + certificate validation and timeouts on all outbound calls
- Per-client rate limiting with exponential backoff
- On-startup / on-build CVE / dependency quick-check (`pip-audit`)
- Security event logging ("Presidio hardening applied to ...")
- Full GitHub security files: `SECURITY.md`, `.github/dependabot.yml`,
  `.github/workflows/codeql.yml`, and a test/build workflow

## Technical Requirements

- Python 3.10+
- `src/` layout (`src/presidio_ai/`), `pyproject.toml`, `uv` for env/deps
- `ruff` lint + format enforced; `pytest` with high coverage
- `README.md` with side-by-side examples showing the security improvements
- `LICENSE` = MIT; version starts at 0.1.0

## Roadmap

| Version | Scope | Status |
|---|---|---|
| v0.1.0 | Initial scaffold; target scoping; hardened client skeleton | In progress |

## Version Deliberation Rule

Every deliberation about future versions and roadmap — brainstormed features, scoping
decisions, and rationale — is persisted here. `README.md` carries the top-level
roadmap table linking back to this file.

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
