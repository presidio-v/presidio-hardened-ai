# presidio-hardened-ai

A hardened security layer for AI / LLM client integrations, part of the PRESIDIO
hardened toolkit (`presidio-v`). Adopt it with minimal code changes and get strong
Presidio security defaults — secret redaction, prompt-injection guards, output
filtering, rate limiting, and structured security event logging — automatically.

> **Version 0.1.0** — MIT License. Initial scaffold; the security target and
> wrapped surface are being scoped (see [PRESIDIO-REQ.md](PRESIDIO-REQ.md)).

## Status

This repository was seeded from the `presidio-templates` scaffold. The concrete
target (which AI/LLM SDK or surface is wrapped) and the v0.1.0 feature set are
under active scoping — full detail and rationale live in
[PRESIDIO-REQ.md](PRESIDIO-REQ.md).

## Mandatory Presidio Security Extensions (planned)

- Secret/credential redaction at the logging sink
- Prompt-injection and unsafe-output guards
- Strict TLS and certificate validation for all outbound calls
- Per-client rate limiting with backoff
- On-startup CVE / dependency quick-check (`pip-audit`)
- Structured security event logging ("Presidio hardening applied to ...")

## Roadmap

| Version | Scope | Status |
|---|---|---|
| v0.1.0 | Initial scaffold; target scoping; hardened client skeleton | In progress |

Full roadmap detail and version deliberation: [PRESIDIO-REQ.md](PRESIDIO-REQ.md).

## Install

```bash
pip install presidio-hardened-ai   # not yet published
```

## Development

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m pytest tests/ -x -q
```

## Security

Vulnerability reporting and the security feature matrix: [SECURITY.md](SECURITY.md).

## SDLC

This repository is developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.

## License

MIT — see [LICENSE](LICENSE).
