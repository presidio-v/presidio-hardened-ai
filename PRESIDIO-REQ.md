# Presidio-Hardened Toolkit: presidio-hardened-ai

## Overview

`presidio-hardened-ai` provides **training-time privacy controls** for AI systems. It
is the training-job member of the `presidio-hardened-*` family: where
`presidio-hardened-x402` governs agentic *payments* and `presidio-hardened-ikigov-assess`
governs *assessment*, this package governs what happens when sensitive data is prepared
for and used in model training.

**Thesis — architecture is the defense.** Privacy guarantees that rest on policy or
trust are not guarantees. The product is the minimal composition that closes a named
threat model and produces *evidence* a regulator (or the IKI-Gov governance spine) can
verify, rather than take on trust.

**Wedge (locked):** training-time privacy · regulated EU **financial services** ·
**sovereign / on-prem** · **LLM fine-tuning** · positioning = **compliance evidence**.
Because a single org training on its own data has no counterparty, SMPC is out of scope
and federated learning is deferred (P3); v1 is an open-weights, in-VPC play by
construction (DP-SGD needs gradient access a hosted frontier API will not give).

**Design invariant — the ledger holds commitments, never content.** Only hashes,
counts, and structural metadata are persisted; raw PII and organisational data never
enter the ledger, the evidence file, or the security log. This mirrors the family's
structural-only logging rule (cf. ikigov `security.log`).

CLI command: `pai`

## Mandatory Presidio Security Extensions

- Input sanitisation for all CLI parameters (identifiers, paths, enums): bounds, type,
  allow-list; rejection of control/NUL bytes.
- Secure logging: structural metadata only — no source content, no PII, no `ledger_ref`
  values, no secrets. `~/.presidio-ai/security.log`.
- Tamper-evident persistence: HMAC-SHA256-chained ledger; timing-safe verification;
  keyed MAC mandatory (no unkeyed mode).
- Output sanitisation: free-text HTML-escaped before any rendering.
- Per-session abuse guard (`PRESIDIO_AI_MAX_OPS`, default 1000).
- Restricted file permissions: ledger `0600`, `~/.presidio-ai/` `0700`.
- Dependency CVE check via `pip-audit` (`audit`/`dev` extra).
- Full GitHub security files: `SECURITY.md`, `.github/dependabot.yml`,
  `.github/workflows/codeql.yml`, `.github/workflows/pytest.yml`.

## Technical Requirements

- Python 3.10+ (family baseline from ikigov v0.9.0; 3.9 is EOL and pins a vulnerable
  `urllib3` in the dev/audit tree).
- `pyproject.toml` + hatchling + Typer CLI; `src/presidio_ai/` layout.
- 80%+ test coverage with pytest; ruff lint + format clean.
- LICENSE = MIT. Version = 0.1.0.

---

# Version Registry & Deliberation Log

## Roadmap Summary

| Version | Phase | Theme | Status |
|---|---|---|---|
| v0.1.0 | P1 | Evidence layer: tamper-evident ledger + PII-scrub on ingest + signed `EvidenceRef` export | **Current** |
| v0.2.0 | P2 | DP-SGD fine-tune harness + ε-budget accountant (public-base / private-delta) | Planned |
| v0.3.0 | P2 | n-of-m authorization for high-ε jobs; ikigov MCP bridge (`iga assess --evidence`) | Planned |
| v0.4.0 | P3 | Federated learning for cross-border / cross-silo data | Planned |
| — | P4 | Multi-party consortium (SMPC) — pull-only | Deferred |

---

## v0.1.0 — P1: Evidence Layer

**Deliberated:** 2026-06-08

### Scope decision
Ship the lowest-research-risk, highest-trust-leverage slice first: the **evidence
layer**. No differential privacy yet (P2) and no model training — P1 wraps a
fine-tuning project the customer is *already* running and produces the verifiable
record it cannot currently generate. This lands the first logo on compliance value
alone and makes the ikigov v0.13.0 contract real and demoable.

### Core components
1. **Ledger** (`ledger.py`) — append-only JSON-L; each entry HMAC-SHA256-chained over
   `(seq, timestamp, event, payload, prev_hash)`. `verify_chain` detects any edit,
   insert, delete, reorder, or wrong key. Payload is commitments-only.
2. **PII scrub** (`pii.py`) — regex (default) or Presidio NLP (`[nlp]` extra, lazy,
   regex fallback); actions `redact` / `block` / `warn`; returns redacted text plus
   per-entity counts (counts are ledger-safe, text is not stored).
3. **Ingest** (`ingest.py`) — scrubs records, writes a `data-ingested` lineage entry
   (source commitment, scrubbed-content hash, record counts, redaction counts), returns
   scrubbed records. Cornerstone evidence for D1/D4; the ledger itself is O5.
4. **Evidence** (`evidence.py`) — `EvidenceRef` (schema matches ikigov v0.13.0
   verbatim) with detached HMAC signature; `build_ingest_evidence` emits **D1, D4, O5**
   (the high-confidence items only); `export_evidence` writes the JSON `iga assess
   --evidence` consumes.
5. **CLI** (`cli.py`) — `pai ingest`, `pai verify`, `pai version`.

### EvidenceRef contract (cross-repo)
Fields: `item_id, source, source_version, ledger_ref, content_hash, signer, signature,
claimed_at`. This is the integration contract with
`presidio-hardened-ikigov-assess` v0.13.0 — change only in lockstep with that repo.
Partial-credit items (T4/T5/D2/I4) are intentionally **not** emitted in P1 so the
export never overstates what the ledger proves.

### Decision notes
- **Open-weights / in-VPC is structural, not a limitation** — it is the prerequisite
  for the DP-SGD gradient access P2 needs and for the sovereignty pitch.
- **Scrub + DP compose, but DP is P2** — P1 ships scrub as the first line; DP is the
  mathematical backstop for residual recall and is deliberately deferred.
- **HMAC baseline, not public-key** — reuses the v0.9.0 family signature primitive;
  sigstore/minisign can be layered later without changing `EvidenceRef`.

---

## Cross-cutting decisions

| Decision | Rationale |
|---|---|
| Commitments-only ledger | The audit log must never become a new breach surface; hashes/counts prove facts about data without holding it |
| Keyed MAC mandatory | An unkeyed hash chain is forgeable; tamper-evidence requires a secret |
| `EvidenceRef` owned here, consumed by ikigov | The governance spine stays framework-pure; each control owns and versions its own item→evidence map |
| Evidence is provenance, not score | Maturity (how complete) and evidence coverage (how verifiable) are orthogonal |

## SDLC

Developed under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
