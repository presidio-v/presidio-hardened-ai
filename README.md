# presidio-hardened-ai

> v0.30.0 — **Training-time privacy controls (P1–P4):** tamper-evident DP ε-budgets,
> n-of-m (MPA) authorized training, malicious-secure guaranteed-output-delivery consortium
> rounds with zero-knowledge bounded-norm (L∞/L2) input validation, and Ed25519-signed
> evidence the IKI-Gov governance spine verifies from the public key alone.

Training-time privacy controls for AI. Where the rest of the toolkit governs
*payments* (`presidio-hardened-x402`) and *assessment* (`presidio-hardened-ikigov-assess`),
this package governs the **training job**: it scrubs PII on the way in, records an
immutable, auditor-verifiable lineage, and emits cryptographically signed evidence
that a governance assessment can verify rather than take on trust.

Part of the [`presidio-hardened-*`](https://github.com/presidio-v) toolkit family.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the suite interlocks — the cross-repo claim→evidence loop and an end-to-end `pai` → `iga` demo.

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
2019) with Canonne-Kamath-Steinke (2020) RDP→DP conversion. The ε budget is re-derived from the
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


### Train with DP-SGD

```bash
# Train a DP-SGD logistic model, charge the org budget, export D4 evidence.
pai dp-train --input data.jsonl --ledger audit/ledger.jsonl --total-epsilon 10 \
    --job-id fraud-ft --noise-multiplier 1.1 --sample-rate 0.01 --steps 1000 \
    --clip-norm 1.0 --lr 0.1 --evidence-out audit/dp-evidence.json
#   Trained 'fraud-ft': accuracy=0.94  epsilon=1.83
```

`data.jsonl` is one `{"x": [floats], "y": 0|1}` per line. The default trainer is a
dependency-free reference DP-SGD (correct per-example clipping + Gaussian noise), so the
charged `(ε, δ)` is the guarantee of a real private run. The production Opacus backend
plugs into the same `DPTrainer` interface behind the optional `[torch]` extra.


### Federated learning across silos

```bash
# Train across silos whose data never leaves them; report per-silo DP cost.
pai fl-train --silo eu.jsonl --silo us.jsonl --rounds 10 --local-steps 50 \
    --charge --total-epsilon 10 --ledger-dir audit/fl/ \
    --evidence-dir audit/fl-evidence/ --signing-key "$PRIV_HEX" \
    --noise-multiplier 1.1 --sample-rate 0.01 --secure-agg
#   pooled accuracy: 0.93
#   eu: epsilon=1.83 over 500 steps   us: epsilon=1.83 over 500 steps
```

Each `--silo` is a `{"x":[...],"y":0|1}` JSONL file. Silos train locally (DP-SGD) from the
broadcast global model and only their updates are aggregated (FedAvg). With `--secure-agg`
the coordinator recovers only the combined update, not any individual silo's. Each silo's
`(ε, δ)` composes over `rounds × local-steps`.


### Production DP-SGD (Opacus)

```bash
pip install "presidio-hardened-ai[torch]"
```

```python
from presidio_ai.dp import make_trainer, DPSGDConfig
model = make_trainer("opacus").train(features, labels, DPSGDConfig(
    noise_multiplier=1.1, sample_rate=0.01, steps=1000, delta=1e-5, clip_norm=1.0,
))
```

The Opacus backend trains real models on GPU/CPU and implements the same `DPTrainer`
interface as the reference trainer; its `TrainedModel.result` uses this suite's
accountant so evidence is consistent. A dedicated CI lane (`ci-torch.yml`) installs the
extra and cross-validates Opacus' privacy accountant against ours. For production DP
noise in the reference trainer, pass `secure_rng=True` (CSPRNG, non-deterministic).


### Public-key evidence signing (Ed25519)

```bash
pip install "presidio-hardened-ai[crypto]"
pai keygen                       # -> private_key / public_key (hex); keep the private one secret

pai ingest --source crm --input data.jsonl --ledger audit/ledger.jsonl \
    --evidence-out audit/evidence.json --algorithm ed25519 --signing-key "$PRIVATE_HEX"
```

The verifier holds only the **public** key (in its trust store); the algorithm is a
property of that trust entry, so the `EvidenceRef` contract is unchanged. **Ed25519 is
the default** (v0.8.0; HMAC remains available via `--algorithm hmac-sha256`), so evidence
export requires a signing key. Signatures are deterministic
(RFC 8032) and verify with `verify_ed25519(content_hash, signer, signature, public_key)`.

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

## Working with us

`presidio-hardened-ai` is past proof-of-concept. The full P1–P4 stack is built and verified
end to end: per-client differential-privacy accounting with tamper-evident ε-budgets, n-of-m
authorized (MPA-gated) training, malicious-secure consortium rounds with guaranteed output
delivery, zero-knowledge bounded-norm input validation (L∞ and L2, enforcing the exact DP clip
sensitivity), Ed25519-signed evidence, and cross-suite verification by
`presidio-hardened-ikigov-assess` from the public key alone. We are now selecting a small number
of **initial design partners** to take it from verified to deployed. This is active outreach —
we are choosing where to prove the system first, not asking for help.

We are looking for four partner profiles, each matched to a seam that already exists in the
code. **Federated-learning consortia** — several mutually-distrusting institutions that want a
shared model without exposing raw data or individual updates — map directly onto the consortium
round (`run_god_consortium_round`): honest-majority robust aggregation, no trusted coordinator,
one signed `D4` per round. **Regulated data custodians** who need high-privacy-cost work gated by
human or system sign-off use the n-of-m MPA control and per-silo ε-budgets. **Auditors and
compliance teams** consume the other end — the tamper-evident ledger and the signed `D4`
EvidenceRef, verifiable offline against a held public key, with `ikigov` turning it into a
framework-mapped assessment. **Cloud and on-prem ML infrastructure operators** are the partners
who would exercise the heavier `[torch]`, `[mpc]`, and `[zk]` lanes on real hardware.

Three concrete validations would close the loop with a partner: a first live consortium round
aggregating *real model weights* across entities; an auditor *signing off from a signed `D4`
alone*, with no access to the underlying data or training run; and *cross-entity DP-budget
accountability*, with each participant's ε spend reconciled against the shared, tamper-evident
ledger.

To be precise about status: the cryptographic core, the governance flow, and the cross-suite
evidence loop are tested and reproducible today on the pure-Python path. The native acceleration
lanes — `[mpc]` (authenticated X25519 key agreement + transport) and `[zk]` (Ristretto255 +
Bulletproofs) — are committed as audited-dependency source and validated by decision-equivalence
tests, but their first production build and benchmarking is the immediate next step, and one we
would take *with a partner's infrastructure*. Nothing here is claimed to be running in production
yet — that is precisely what a design partnership is for.

If one of these profiles is yours, reach out through the repository (open a discussion, or use
the contact in [SECURITY.md](SECURITY.md)).

## Roadmap

| Phase | Versions | Theme |
|---|---|---|
| P1 | v0.1.0 | Evidence layer: tamper-evident ledger + PII-scrub + signed `EvidenceRef` |
| P2 | v0.2.0–v0.4.0, v0.10.0, v0.15.0 | ε-budget accountant (CKS-2020 + fractional-order RDP), n-of-m MPA, DP-SGD (reference + Opacus) |
| P3 | v0.5.0, v0.9.0 | Federated learning across silos + per-silo ε-budget + signed D4 |
| P4 | v0.11.0–v0.18.0 | Consortium secure aggregation: exact field masking, dropout recovery, `[mpc]` authenticated key agreement, malicious-secure (Feldman VSS + signed survivor-set + homomorphic check) |
| P4 | v0.19.0–v0.24.0 | Zero-knowledge bounded-norm input validation (L∞/L2); pluggable MODP / Ristretto255+Bulletproofs backend |
| P4 | v0.25.0–v0.29.0 | Guaranteed output delivery (honest-majority robust aggregation) + whole-consortium proof aggregation |
| **P4** | **v0.30.0** | **Byzantine-ML robustness gate: aggregate validation + rollback — current** |

Seven accepted ADRs (`docs/adr/`, see the [index](docs/adr/README.md)) cover the P4 arc.
See [PRESIDIO-REQ.md](PRESIDIO-REQ.md) for the full deliberation log and
[CHANGELOG.md](CHANGELOG.md) for the release summary.

---

## License

MIT — see [LICENSE](LICENSE).

## SDLC

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
