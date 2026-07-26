# presidio-hardened-* — Suite Architecture

> Cross-repo overview of how the `presidio-hardened-*` family interlocks. Lives in
> `presidio-hardened-ai/docs/` and may be mirrored into `presidio-hardened-docs`.

## Thesis

**Architecture is the defense.** Privacy and governance guarantees that rest on policy or
trust are not guarantees. Each tool in the family produces, or consumes, *evidence* that a
regulator (or the governance spine) can verify cryptographically — not claims to be taken
on faith.

## The family

| Repo | Role | Governs |
|---|---|---|
| `presidio-hardened-ikigov-assess` | Governance **spine** — IKI-Gov assessment, ISO 42001 / EU AI Act / NIST AI RMF coverage, signed evidence packs, multi-tenant MCP | *assessment* |
| `presidio-hardened-ai` | Training-time privacy **control** — PII scrub + tamper-evident lineage ledger, DP-SGD + ε-budget, federated learning | *training* |
| `presidio-hardened-x402` | Agentic-payment **control** — PII redaction + spending policy + replay/MPA on x402 payments | *payments* |
| `presidio-hardened-arch-translucency` | Runtime architecture (SLO broker) | *runtime* (referenced) |

The spine **consumes** evidence; the controls **produce** it.

## The unifying primitive

> Every privacy-sensitive action emits a **signed, Presidio-screened, policy-checked,
> optionally multi-party-authorized ledger entry** — and the governance spine ingests
> those entries as verifiable evidence.

x402 applies it to payments; `presidio-hardened-ai` to training jobs; ikigov consumes the
result. Shared building blocks, reused (not reinvented) across repos:

- **Presidio PII screening** — regex / NLP detection + redaction; the same family
  `screen.presidio-group.eu` posture.
- **Commitments-only logging** — ledgers, evidence files and security logs carry hashes,
  counts and structural metadata, *never* PII or raw org data.
- **Tamper-evident audit ledger** — append-only, HMAC-SHA256-chained JSON-L; any
  edit/insert/reorder breaks the chain.
- **`EvidenceRef@1`** — the cross-repo wire contract (8 fields: `item_id, source,
  source_version, ledger_ref, content_hash, signer, signature, claimed_at`). The producer
  signs; the spine verifies. The schema is pinned in both repos' `PRESIDIO-REQ.md`.
- **Signing** — HMAC-SHA256 baseline, **Ed25519 (RFC 8032) by default**. The *algorithm is
  a property of the verifier's trust store* (`{alg, public_key}`), so the contract never
  changed when public-key signing landed. Trust entries accept a **list** of keys for
  rotation.
- **Policy-as-code, n-of-m authorization, content packs, RDP accounting** — each a small,
  reusable, independently-tested primitive.

## The claim → evidence loop

A maturity/GRC tool scores governance from human self-attestation — someone ticks a box.
The suite's differentiator is turning the *technical-control* subset of those boxes into
**cryptographically verified** evidence:

```
  presidio-hardened-ai (producer)                 ikigov (governance spine, consumer)
  ───────────────────────────────                 ───────────────────────────────────
  scrub PII on ingest                              iga assess --evidence … --trust …
  → HMAC-chained lineage ledger        EvidenceRef   → verify_ref (Ed25519, fail-closed)
  → DP-SGD + ε-budget charge        ───@1, signed──▶ → affirm D1/D4/O5 as
  → sign D1 / D4 / O5 (Ed25519)        (no PII)        "evidence-verified"
                                                     → evidence_coverage %  (orthogonal
                                                        to maturity: "how verifiable")
```

The verifier holds only **public** keys; the producer keeps the private key. No shared
secret. An affirmation is now *proven*, not *ticked*.

## End-to-end demo (verified)

```bash
# 1. Producer mints an Ed25519 keypair (keep the private key secret).
export PRESIDIO_AI_LEDGER_KEY="$(openssl rand -hex 32)"
pai keygen          # prints private_key / public_key (hex); export PRIV=… PUB=…

# 2. Scrub + record lineage + emit signed D1/D4/O5 evidence.
pai ingest --source crm --input data.jsonl --ledger audit/ledger.jsonl \
    --evidence-out evidence.json --use-case fraud-scoring \
    --algorithm ed25519 --signing-key "$PRIV"

# 3. Verifier's trust store holds ONLY the public key.
echo "{\"presidio-hardened-ai\": {\"alg\": \"ed25519\", \"public_key\": \"$PUB\"}}" > trust.json

# 4. Governance spine verifies the evidence and folds it into the assessment.
iga assess --use-case fraud-scoring --risk-class high --affirm S1,S2 \
    --evidence evidence.json --trust trust.json --quiet
```

Result (verified against `presidio-hardened-ai` v0.20.0 + ikigov v0.19.0):

```
affirmed:        ["D1", "D4", "O5", "S1", "S2"]
D1 provenance:   evidence-verified
evidence_coverage: 3/5 affirmed items backed (3 verified) = 60%
```

`D1` (data lineage), `D4` (DPIA inputs) and `O5` (immutable audit log) are affirmed by
cryptographically verified evidence; `S1`/`S2` remain self-attested. The full bundle can
then be sealed with `iga export` / `iga verify-bundle`.

### Consortium round (P4, malicious-secure) — verified

The same claim→evidence loop closes for a **multi-party** round. Several mutually-distrusting
banks jointly train; the coordinator (and any colluding minority) learns only the aggregate;
the round is hardened against a *deviating* coordinator or party and proves each contribution
is within the DP clip norm — then emits one signed `D4` an auditor verifies exactly like the
single-node case.

```python
# presidio-hardened-ai: one governed, malicious-secure consortium round
from presidio_ai.fl.consortium import run_secure_consortium_round, sign_survivor_set

res = run_secure_consortium_round(
    round_id="round-1",
    updates=updates,
    dp_results=dp,
    session=session,  # verifiable-mode (Feldman VSS)
    ledger=ledger,
    survivor_signatures=sigs,
    survivor_keys=skeys,
    survivor_threshold=2,
    group=group,
    budgets=budgets,
    clip_bound=2.0,  # ZK bounded-norm gate
    signing_key=PRIV,
    signer="presidio-hardened-ai",
    algorithm="ed25519",
    evidence_path="consortium.evidence.json",
)

# presidio-hardened-ikigov-assess: verify the round's evidence with only the public key
from presidio_ikigov_assess.evidence import load_evidence, load_trust_store, verify_ref

refs = load_evidence(open("consortium.evidence.json").read())
trust = load_trust_store('{"presidio-hardened-ai": {"alg": "ed25519", "public_key": "<PUB>"}}')
assert verify_ref(refs[0], trust)  # D4 verifies; a tampered key fails closed
```

Result (verified live against `presidio-hardened-ai` v0.20.0 + ikigov v0.19.0):

```
PRODUCER  survivors=[bankA,bankB,bankC]  signers=[bankA,bankB,bankC]
          max per-silo epsilon=1.0795    charged silos=[bankA,bankB,bankC]
          ledger: sensitivity_proven=True  clip_bound=2.0
          signed D4 evidence -> consortium.evidence.json
CONSUMER  D4: verify_ref=True  (signer=presidio-hardened-ai, ledger_ref=pai-ledger:seq/1)
          tampered-key verify (must be False): False
```

What that one run exercises, all composing: authenticated key agreement → Feldman-VSS seed
sharing → Pedersen-committed signed inputs → **ZK bounded-norm proofs** (so the per-client
`(ε, δ)` is *proven*, not assumed) → exact field secure aggregation with dropout recovery →
signed survivor-set + homomorphic aggregate check (security-with-abort) → n-of-m MPA →
per-silo ε charged to tamper-evident budgets → one signed `D4` the governance spine verifies.

### Guaranteed-output-delivery round (P4, honest majority) — verified

The same loop runs in **GOD** mode (ADR-0006), where a misbehaving minority cannot halt the
round and there is no coordinator: parties VSS-share their updates, the sum is robustly
reconstructed by an honest quorum, the L2 bounded-norm gate (bound to the shared inputs by a
commitment-equality proof) screens each contribution, and one signed `D4` is emitted.

```python
from presidio_ai.fl.consortium import run_god_consortium_round

res = run_god_consortium_round(
    round_id="god-1",
    updates=updates,
    dp_results=dp,
    threshold=3,  # honest-majority quorum t+1
    ledger=ledger,
    group=group,
    budgets=budgets,
    l2_bound=2.0,  # exact DP clip norm, proven
    signing_key=PRIV,
    signer="presidio-hardened-ai",
    algorithm="ed25519",
    evidence_path="god.evidence.json",
)
# ikigov verifies the round's D4 with only the public key (verify_ref(refs[0], trust) == True)
```

Result (verified live against `presidio-hardened-ai` v0.29.0 + ikigov v0.19.0, with a
poisoning party whose update exceeds the L2 bound):

```
PRODUCER  included=[bank0,bank1,bank2,bank4]  excluded=[bank3]      # poisoner gated out
          aggregate == honest-only sum: True
          ledger: mode=god  proven_norm=l2  honest_majority_threshold=3
CONSUMER  D4: verify_ref=True   (signer=presidio-hardened-ai)
```

The malicious party is excluded by the bounded-norm gate, the honest quorum still **delivers**
the correct aggregate (no abort, no coordinator), and the signed evidence verifies cross-suite
exactly as the single-node and security-with-abort cases do.

## Coordination invariants

- **Signing default ↔ verifier capability.** `presidio-hardened-ai` ≥ v0.8.0 defaults to
  Ed25519; a verifier must be ikigov ≥ v0.14.0 (public-key verification). Deploy/commit the
  verifier **before or with** the producer flip, so the loop never sees evidence it cannot
  check. HMAC remains available (`--algorithm hmac-sha256`) for older verifiers.
- **`EvidenceRef@1` is a shared contract** — change it only in lockstep across producer and
  consumer; a fixed-key Ed25519 golden vector pins the wire format in both test suites.
- **Federated parity** — `pai fl-train --charge` produces the same per-silo ledger + signed
  evidence as single-node `dp-train`, so a consortium feeds each silo's evidence into an
  independent assessment.
- **Consortium round invariants (P4)** — the producer and all parties must share the *same*
  `SecureAggregationSession` group for verifiable mode (Feldman VSS) and the same commitment
  group for the ZK proofs; `clip_bound` is the DP clip sensitivity, so a verifying bounded-norm
  proof makes the charged `(ε, δ)` sound against a malicious client. Guarantee is
  **security-with-abort**: any deviation (equivocation, false aggregate, inconsistent share,
  out-of-norm input) yields a clean, ledger-recorded abort rather than a bad result.

## Status (at time of writing)

- **presidio-hardened-ai** v0.30.0 — P1 evidence layer · P2 ε-accountant (CKS-2020 +
  fractional-order RDP) · MPA · DP-SGD (reference + Opacus `[torch]`) · federated learning +
  per-silo governance · **P4 consortium**: exact secure aggregation + dropout recovery,
  `[mpc]` authenticated key agreement, malicious-secure rounds (commitments + Feldman VSS +
  signed survivor-set), ZK bounded-norm input validation — L∞ and **L2** — (pluggable MODP / Ristretto255+Bulletproofs backends) · **guaranteed output delivery** (honest-majority robust secret-sharing; bounded-norm-gated; whole-consortium proof aggregation; exclude-and-retry interim) · **Byzantine-ML robustness gate** (aggregate validation + rollback) · Ed25519 signing (default).
- **presidio-hardened-ikigov-assess** v0.19.0 — assessment/scoring/gates · ISO 42001 / EU
  AI Act / NIST AI RMF via content packs · signed evidence-pack export · external
  evidence-backed affirmation (Ed25519 + rotation) · multi-tenant remote MCP.
- **presidio-hardened-x402** — published payment-security middleware (PII redaction, spend
  policy, replay, MPA, screening).

## Decisions

- [ADR-0001](adr/0001-multiparty-secure-aggregation.md) — multi-party consortium training via secure aggregation (P4, **Accepted & built**: v0.11.0 core, v0.12.0 exact field arithmetic, v0.13.0 governed rounds, v0.14.0 `[mpc]` key agreement + transport).
- [ADR-0002](adr/0002-malicious-security-hardening.md) — malicious-security hardening: commitments + verifiable secret sharing + signed survivor-set consistency (P4, **Accepted & built** v0.16.0–v0.18.0; security-with-abort).
- [ADR-0003](adr/0003-bounded-norm-input-validation.md) — bounded-norm input validation via zero-knowledge (transparent Pedersen range proofs over the prime-order group; enforces the DP clip sensitivity) (P4, **Accepted & built** v0.19.0–v0.20.0; Ristretto255+Bulletproofs perf backend deferred).
- [ADR-0004](adr/0004-ristretto-bulletproofs-backend.md) — Ristretto255 + Bulletproofs performance backend: a pluggable `ProofBackend` (audited dalek crates behind `[zk]`, built in `ci-zk`) with the pure-Python MODP proof as a dependency-free fallback; same guarantee (P4, **Accepted & built** v0.21.0–v0.22.0).
- [ADR-0005](adr/0005-l2-bounded-norm.md) — L2 bounded-norm proofs: commit squares + a square-correctness Σ-proof + range-prove the homomorphic squared-norm, enforcing the *exact* DP clip norm on both backends (P4, **Accepted & built** v0.23.0–v0.24.0).
- [ADR-0006](adr/0006-guaranteed-output-delivery.md) — guaranteed output delivery: honest-majority robust secret-sharing aggregation (VSS-shared inputs + robust reconstruction) so a misbehaving minority cannot halt the round; interim exclude-and-retry (P4, **Accepted & built** v0.25.0–v0.27.0).
- [ADR-0007](adr/0007-byzantine-ml-robustness.md) — Byzantine-ML robustness against in-norm backdoors: a privacy-preserving layered posture (norm + DP influence-bound + accountability + aggregate validation/rollback), with cosine-band ZK and robust-aggregation-under-MPC as scoped escalations (P4, **Accepted & built** v0.30.0).

## SDLC

Developed under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
