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


### Differential-privacy budget (v0.2.0)

- **Privacy parameters are evidence, not PII.** ε, δ, noise multiplier, sampling rate, and
  step count are recorded to the ledger by design — they are accounting facts required to
  make the guarantee auditable, and contain no organisational data.
- **Tamper-evident budget.** The org ε budget is re-derived from the MAC-verified ledger
  chain; a tampered ledger fails closed (no spend figure is returned). An over-budget
  charge is rejected and recorded nowhere.
- **Sound accounting.** Integer-order subsampled-Gaussian RDP (Mironov–Talwar–Zhang 2019)
  composed over steps, converted via Mironov (2017) — a sound upper bound on ε.

### Evidence signatures

Exported `EvidenceRef` objects carry a detached HMAC-SHA256 signature over the
content hash, bound to a signer id (the v0.9.0 family baseline). Verification is
fail-closed. A public-key scheme (sigstore/minisign) can be layered later without
changing the `EvidenceRef` shape, which matches the
`presidio-hardened-ikigov-assess` v0.13.0 contract verbatim.


### High-ε authorization (v0.3.0)

- **n-of-m approval** gates budget charges at/above a configured ε threshold, reusing the
  x402 multi-party-authorization design (HMAC-SHA256 countersignatures).
- **Replay-bound** — an approval signs the canonical authorization request (job id + the
  job's privacy parameters), so it cannot be replayed onto a different job or (ε, δ).
- **Local trust** — approver keys are a local verifier trust store; no network resolution.
  The recorded `mpa-authorized` ledger entry holds approver ids and the request hash only.
- **Fail-closed** — insufficient or invalid approval rejects the charge and records nothing
  (CLI exit 3); over-budget is exit 2.


### Federated learning (v0.5.0)

- **Data stays in the silo.** Only DP-noised model updates are shared with the coordinator;
  raw silo data never leaves it.
- **Per-client differential privacy** bounds each silo's contribution and composes over
  rounds × local steps (accounted per client).
- **Secure aggregation** (`--secure-agg`) hides individual silo updates from the
  coordinator via zero-sum additive masking; it recovers only the combined update. The
  reference uses a seedable PRNG — a production deployment uses pairwise-exchanged mask
  seeds and a CSPRNG.


### DP randomness & Opacus backend (v0.6.0)

- **CSPRNG noise option.** The reference trainer's `secure_rng=True` draws DP noise from an
  `os.urandom`-backed CSPRNG (`random.SystemRandom`), closing the earlier seedable-PRNG
  caveat; the default remains a seeded PRNG for reproducible testing only.
- **Opacus backend** uses `PrivacyEngine(secure_mode=...)` and is verified in a dedicated
  torch CI lane that cross-validates Opacus' privacy accountant against this suite's
  `dpsgd_epsilon` — so the accounting cannot silently diverge between backends.


### Public-key evidence signing (v0.7.0–v0.8.0)

- **Ed25519 (RFC 8032)** detached signatures are available alongside HMAC for evidence,
  over the same canonical `{content_hash, signer}` message (drop-in at the wire level).
- **Asymmetric trust:** the producer holds the private key; a verifier holds only the
  public key. The signing algorithm is a property of the verifier's trust entry, so the
  `EvidenceRef` contract is unchanged.
- **Ed25519 is the default (v0.8.0)**, coordinated with ikigov v0.14.0 public-key
  verification; HMAC remains available via `--algorithm hmac-sha256`. Deploy the v0.14.0
  verifier before/with this flip so the live loop never sees evidence it cannot check.
- `cryptography` is an optional `[crypto]` extra; Ed25519 calls raise a clear ImportError
  without it. A fixed-key golden vector locks the wire format across repos.

## Software Development Lifecycle

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
