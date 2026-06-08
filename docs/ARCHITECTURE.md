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

Result (verified against `presidio-hardened-ai` v0.10.0 + ikigov v0.18.0):

```
affirmed:        ["D1", "D4", "O5", "S1", "S2"]
D1 provenance:   evidence-verified
evidence_coverage: 3/5 affirmed items backed (3 verified) = 60%
```

`D1` (data lineage), `D4` (DPIA inputs) and `O5` (immutable audit log) are affirmed by
cryptographically verified evidence; `S1`/`S2` remain self-attested. The full bundle can
then be sealed with `iga export` / `iga verify-bundle`.

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

## Status (at time of writing)

- **presidio-hardened-ai** v0.10.0 — P1 evidence layer · P2 ε-accountant (+CKS-2020
  conversion) · MPA · DP-SGD (reference + Opacus `[torch]`) · federated learning + per-silo
  governance · Ed25519 signing (default).
- **presidio-hardened-ikigov-assess** v0.18.0 — assessment/scoring/gates · ISO 42001 / EU
  AI Act / NIST AI RMF via content packs · signed evidence-pack export · external
  evidence-backed affirmation (Ed25519 + rotation) · multi-tenant remote MCP.
- **presidio-hardened-x402** — published payment-security middleware (PII redaction, spend
  policy, replay, MPA, screening).

## Decisions

- [ADR-0001](adr/0001-multiparty-secure-aggregation.md) — multi-party consortium training via secure aggregation (P4, Proposed).

## SDLC

Developed under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
