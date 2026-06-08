# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

### Supported Python runtimes

| Python | Supported |
|--------|-----------|
| 3.10 – 3.12 | Yes |

This package starts at `requires-python >=3.10`, aligned with the family baseline
from `presidio-hardened-ikigov-assess` v0.9.0 (Python 3.9 is upstream end-of-life and
leaves the dev/audit dependency tree pinned to a vulnerable `urllib3`).

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include: a description, steps to reproduce, potential impact, and a suggested fix if
any. You will receive an acknowledgement within 5 business days; we aim to release a
patch within 30 days of a confirmed vulnerability.

## Security Design

`presidio-hardened-ai` implements the following controls in P1 (v0.1.0):

- **Tamper-evident ledger** — every entry is HMAC-SHA256-chained to its predecessor.
  Any insertion, deletion, reorder, or in-place edit breaks the chain and is detected
  by `pai verify` (timing-safe MAC comparison). A keyed MAC is mandatory; there is no
  unkeyed mode.
- **Commitments only, never content** — the ledger, the exported evidence file, and
  the security log carry hashes, counts, and structural metadata exclusively. Raw PII
  and organisational data never enter any persisted artifact. The ingest path enforces
  this by construction (only `sha256` commitments and per-entity counts are recorded).
- **PII scrub on ingest** — Presidio (NLP extra) or curated regex detection, with
  `redact` / `block` / `warn` actions. Detection favours precision; differential
  privacy is the planned mathematical backstop (P2) for residual recall.
- **Input validation & output escaping** — identifiers and paths are length-bounded
  and rejected on control/NUL bytes; free-text is HTML-escaped before any rendering.
- **Structural-only security log** — `~/.presidio-ai/security.log` records event name,
  counts, and mode flags only; never content or `ledger_ref` values. Logging is
  best-effort and never breaks the operation.
- **Per-session abuse guard** — a configurable maximum number of operations per session
  (`PRESIDIO_AI_MAX_OPS`, default 1000).
- **Restricted file permissions** — the ledger file and `~/.presidio-ai/` are created
  `0600` / `0700`.

### Evidence signatures

Exported `EvidenceRef` objects carry a detached HMAC-SHA256 signature over the
content hash, bound to a signer id (the v0.9.0 family baseline). Verification is
fail-closed. A public-key scheme (sigstore/minisign) can be layered later without
changing the `EvidenceRef` shape, which matches the
`presidio-hardened-ikigov-assess` v0.13.0 contract verbatim.

## Software Development Lifecycle

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
