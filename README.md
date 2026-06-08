# presidio-hardened-ai

> v0.1.0 — **Evidence layer (P1):** tamper-evident privacy ledger, PII-scrub on
> ingest, and signed `EvidenceRef` export for the IKI-Gov governance spine.

Training-time privacy controls for AI. Where the rest of the toolkit governs
*payments* (`presidio-hardened-x402`) and *assessment* (`presidio-hardened-ikigov-assess`),
this package governs the **training job**: it scrubs PII on the way in, records an
immutable, auditor-verifiable lineage, and emits cryptographically signed evidence
that a governance assessment can verify rather than take on trust.

Part of the [`presidio-hardened-*`](https://github.com/presidio-v) toolkit family.

**Design invariant — the ledger holds commitments, never content.** Only hashes,
counts, and structural metadata are recorded; raw PII and organisational data never
enter the ledger, the evidence file, or the security log.

---

## Why

A governance maturity tool scores from human self-attestation — someone ticks a box.
`presidio-hardened-ai` converts the *technical-control* subset of those boxes into
**signed evidence**: an assessor (or an agent) can verify the claim against this
producer's ledger. That is the suite's differentiator — a machine-verifiable
conformity trail instead of a questionnaire.

P1 signs evidence for the items it can substantiate with high confidence:

| IKI-Gov item | What it attests | Basis |
|---|---|---|
| **D1** | Data inventory & end-to-end lineage | ingest source + content commitments |
| **D4** | DPIA inputs | PII-scrub record (per-entity redaction counts) |
| **O5** | Immutable, auditor-verifiable audit log | HMAC-chained ledger head |

These map to EU AI Act **Art. 10** (data governance) and **Art. 12** (record-keeping).
The `EvidenceRef` schema matches `presidio-hardened-ikigov-assess` v0.13.0 verbatim —
it is the cross-repo contract.

---

## Installation

```bash
pip install presidio-hardened-ai

# Full NLP-based PII detection (PERSON, LOCATION, ...):
pip install "presidio-hardened-ai[nlp]"
python -m spacy download en_core_web_sm
```

---

## Quick start

```bash
export PRESIDIO_AI_LEDGER_KEY="$(openssl rand -hex 32)"

# Scrub a source, record lineage, and export signed D1/D4/O5 evidence.
pai ingest --source crm-export --input data.jsonl \
    --ledger audit/ledger.jsonl --out scrubbed.jsonl \
    --evidence-out audit/evidence.json --use-case fraud-scoring

# Verify the ledger chain (any tamper breaks it).
pai verify --ledger audit/ledger.jsonl
```

The exported `evidence.json` is consumed directly by the governance spine:

```bash
iga assess --use-case fraud-scoring --risk-class high \
    --affirm S1,S2,S3 --evidence audit/evidence.json   # ikigov v0.13.0
```

---

## Differential-privacy accounting & budget

```bash
# Account the (epsilon, delta) cost of a planned DP-SGD run.
pai dp-account --noise-multiplier 1.1 --sample-rate 0.0043 --steps 5000 --delta 1e-5
#   epsilon = 1.83  (optimal RDP order 12)

# Charge a job against a tamper-evident org epsilon budget, emit D4 evidence.
pai dp-charge --ledger audit/ledger.jsonl --total-epsilon 10 --job-id fraud-ft \
    --noise-multiplier 1.1 --sample-rate 0.0043 --steps 5000 \
    --evidence-out audit/dp-evidence.json

pai dp-budget --ledger audit/ledger.jsonl --total-epsilon 10   # spent / remaining
```

Accounting uses the integer-order subsampled-Gaussian RDP bound (Mironov–Talwar–Zhang
2019) with Mironov (2017) RDP→DP conversion. The ε budget is re-derived from the
verified ledger chain, so spend cannot be understated without breaking the chain. The
DP-SGD gradient work plugs in behind the optional `[torch]` extra.


### High-ε authorization (n-of-m)

Require sign-off before a high-privacy-risk run spends budget:

```bash
# Each approver countersigns the job (out of band):
pai dp-authorize --job-id fraud-ft --noise-multiplier 1.0 --sample-rate 0.05 \
    --steps 2000 --approver alice --approver-key "$ALICE_KEY" --quiet
#   -> {"approval": "alice:<hexsig>", ...}

# The charge requires 2-of-3 approvals at/above epsilon 0:
pai dp-charge --ledger audit/ledger.jsonl --total-epsilon 10 --job-id fraud-ft \
    --noise-multiplier 1.0 --sample-rate 0.05 --steps 2000 \
    --mpa-threshold 2 --mpa-min-epsilon 0 --approver-keys approvers.json \
    --approval alice:<hexsig> --approval bob:<hexsig>
```

Approvals are HMAC countersignatures bound to the job's privacy parameters (no
replay across jobs); the authorization is recorded to the ledger before the charge.
Exit codes: `2` budget exceeded, `3` authorization denied.

## Library

```python
from presidio_ai import Ledger, PIIScrubber, ingest_records, build_ingest_evidence, export_evidence

ledger = Ledger("audit/ledger.jsonl", key="…")
result = ingest_records(records, source_id="crm-export", ledger=ledger,
                        scrubber=PIIScrubber(action="redact"))

refs = build_ingest_evidence(result, ledger=ledger, signing_key="…", signer="prod")
export_evidence(refs, "audit/evidence.json", use_case="fraud-scoring")
```

---

## Security

See [SECURITY.md](SECURITY.md). Controls in P1: keyed (HMAC-SHA256) tamper-evident
ledger; commitments-only persistence; strict input validation + output escaping;
structural-only security log at `~/.presidio-ai/security.log`; per-session abuse
guard; `0600`/`0700` file permissions.

---

## Roadmap

| Phase | Version | Theme |
|---|---|---|
| P1 | v0.1.0 | Evidence layer: ledger + PII-scrub + signed EvidenceRef |
| P2 | v0.2.0 | ε-budget accountant + DP governance + DP evidence |
| **P2** | **v0.3.0** | **n-of-m authorization (MPA) for high-ε jobs — current** |
| P2 | v0.3.0 | n-of-m authorization for high-ε jobs; ikigov MCP bridge |
| P3 | v0.4.0 | Federated learning for cross-border / cross-silo data |
| P4 | — | Multi-party consortium (SMPC) — pull-only |

See [PRESIDIO-REQ.md](PRESIDIO-REQ.md) for the full deliberation log.

---

## License

MIT — see [LICENSE](LICENSE).

## SDLC

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
