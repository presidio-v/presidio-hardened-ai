# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

## Security Features

| Feature | Description |
|---|---|
| **Secret redaction** | Tokens, keys, and PII redacted at the logging sink |
| **Prompt-injection guards** | Detection and mitigation for unsafe prompts/outputs (planned) |
| **Transport hardening** | Strict TLS, certificate validation, and timeouts on outbound calls |
| **Rate limiting** | Per-client request limiting with exponential backoff |
| **Dependency audit** | `pip-audit` on startup (non-blocking) and in CI |
| **Security event logging** | Structured events for hardening, requests, and guard triggers |

> Some features are planned for v0.1.0; see [PRESIDIO-REQ.md](PRESIDIO-REQ.md) for
> the current scoping status.

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
