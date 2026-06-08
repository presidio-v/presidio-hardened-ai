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

Strategy and threat model: see [`docs/PLAN.md`](docs/PLAN.md).

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
| v0.1.0 | P1 | Evidence layer: tamper-evident ledger + PII-scrub on ingest + signed `EvidenceRef` export | Shipped |
| v0.2.0 | P2 | DP-SGD fine-tune harness + ε-budget accountant (public-base / private-delta) | Shipped |
| v0.3.0 | P2 | n-of-m authorization (MPA) for high-ε jobs (ikigov bridge deferred to ikigov v0.13.0) | Shipped |
| v0.4.0 | P2 | DP-SGD trainer: verifiable stdlib reference + Opacus adapter seam (`pai dp-train`) | Shipped |
| v0.5.0 | P3 | Federated learning: FedAvg across silos + secure aggregation + per-client DP (`pai fl-train`) | **Current** |
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

## v0.2.0 — P2: ε-Budget Accountant & DP Governance

**Deliberated:** 2026-06-08

### Scope decision
Ship the *verifiable governance core* of differential privacy — privacy accounting,
the org ε-budget, and DP evidence — with the actual DP-SGD gradient work behind an
optional `[torch]` extra (mirrors P1's `[nlp]` split). The core carries **no heavy
dependency** (pure stdlib `math`) so the privacy guarantee is fully testable in CI.

### Components
`dp/accountant.py` (RDP of the subsampled Gaussian + composition + RDP→DP conversion),
`dp/budget.py` (ledger-derived ε spend + over-budget guard), `dp/trainer.py`
(public-base/private-delta planning surface), DP `EvidenceRef` (`evidence.build_dp_evidence`),
and CLI (`pai dp-account`, `pai dp-charge`, `pai dp-budget`).

### DP semantics (pinned — do not change silently)
`(epsilon, delta)`-DP for the **whole training run** (all `steps` composed) under
**Poisson subsampling** at rate `sample_rate`, per-step **L2 clipping to sensitivity 1**,
and **Gaussian noise** of std `noise_multiplier`. `delta` is the guarantee's failure
probability. Accounting method (authoritative references):
- Subsampled-Gaussian RDP, **integer-order** bound — Mironov, Talwar & Zhang (2019).
- RDP→`(ε,δ)` conversion — Mironov (2017): `ε(δ) = min_α [ rdp(α) + ln(1/δ)/(α-1) ]`.
- Step composition: additive in RDP. Cross-job composition: **basic** (ε add, δ add) —
  always sound, matches the "finite budget spent down" framing.
Integer orders only → a sound **upper bound** (slightly looser than a fractional-order
accountant). Orders scanned: 2…256.

### Acceptance criteria (each maps to a test)
1. `q=0 ⇒ RDP=0`; `q=1 ⇒ RDP = α/(2σ²)` exactly (closed-form oracles). *(test_accountant)*
2. Stable log-sum-exp == independent direct summation to rel 1e-9. *(test_accountant)*
3. ε strictly increases with `steps` and `sample_rate`, decreases with `noise_multiplier`. *(test_accountant)*
4. `steps=0 ⇒ ε=0`; invalid params raise `AccountantError`. *(test_accountant)*
5. Budget `spent()` is re-derived from the **verified** ledger chain and **fails closed**
   if the ledger is tampered. *(test_budget)*
6. A charge that would exceed the budget raises `BudgetExceeded`, records **no** entry,
   and the CLI exits **2**. *(test_budget, test_dp_cli)*
7. Charge payloads contain **privacy parameters only** (no PII). *(test_budget)*
8. DP evidence emits **D4** only, verifies under signature, and its content hash commits
   to the privacy parameters. *(test_dp_evidence)*

### Validation beyond unit tests
The accountant's outputs match published DP-SGD magnitudes — e.g. σ=1.1,
q≈256/60000, 5000 steps, δ=1e-5 ⇒ ε≈1.83 — providing an external sanity anchor on top
of the closed-form oracles.

### Evidence mapping
**D4** only (DPIA input: quantified `(ε,δ)` re-identification/membership bound). T4
(robustness) and EU AI Act Art. 15 framing are deferred so the export never overstates
what the accounting proves.

### Security
Privacy parameters (ε, δ, σ, q, steps) are **evidence, not PII** and are recorded to the
ledger by design. The budget is tamper-evident (spend derived from the MAC-verified
chain). Over-budget is fail-closed.

### Known limitations / future
Fractional-order (tighter) RDP and the Canonne–Kamath–Steinke (2020) conversion; RDP-level
cross-job composition (tighter than basic); the Opacus-backed `DPTrainer` and its
cross-validation against this accountant, wired under the `[torch]` extra in CI.

---

## v0.3.0 — P2: n-of-m Authorization for High-ε Jobs

**Deliberated:** 2026-06-08

### Scope decision
Gate any budget charge whose accounted epsilon meets a threshold behind **n-of-m
approval**, reusing the `presidio-hardened-x402` multi-party-authorization design
(HMAC-SHA256 countersignatures). This is the CRO control surface: a high
privacy-risk training run cannot spend budget until enough recognised approvers
have signed off, and the approval is recorded immutably in the ledger.

**Why MPA only (bridge deferred).** The roadmap originally paired this with the
ikigov MCP bridge. The bridge's consumer — ikigov v0.13.0 "external evidence-backed
affirmation" — is not yet implemented, and the *producer* side already emits the
exact `iga assess --evidence` document (the `EvidenceRef` export from P1/P2). The
bridge is therefore "emitted, awaiting consumer"; wiring a live bridge against an
unimplemented spec would be speculative coupling. It moves to a v0.3.x once ikigov
v0.13.0 lands.

### Components
`dp/authorization.py` (`MPAPolicy`, `sign_approval`/`verify_approval`, `authorize`);
`EpsilonBudget.charge` integration (records an `mpa-authorized` ledger entry *before*
the charge, fail-closed); CLI `pai dp-authorize` (approver-side) and `--mpa-threshold`
/ `--mpa-min-epsilon` / `--approver-keys` / `--approval` on `pai dp-charge`.

### Design (pinned)
An approval is an HMAC-SHA256 countersignature over the canonical **authorization
request** (job id + the job's privacy parameters), bound to the approver id — so an
approval cannot be replayed onto a different job or different (ε, δ). Authorization
requires `threshold` distinct, recognised, correctly-signed approvers. Mirrors x402's
crypto-countersignature mode.

### Acceptance criteria (each maps to a test)
1. A signature binds to (request, approver); a wrong key, wrong approver id, wrong
   job, or altered params fails verification. *(test_authorization)*
2. `MPAPolicy` rejects threshold < 1, threshold > approvers, and duplicate approvers. *(test_authorization)*
3. A charge with ≥ threshold valid approvals records `mpa-authorized` **then** the
   charge, in that order. *(test_mpa_integration)*
4. Insufficient/invalid approvals raise `MPADenied` and record **nothing**
   (fail-closed). *(test_mpa_integration)*
5. ε below `min_epsilon` requires no approval even when a policy is set. *(test_mpa_integration)*
6. CLI: `dp-authorize` emits a usable approval; `dp-charge` exits 0 with sufficient
   approvals and **3** when denied. *(test_mpa_integration)*

### Security
Approver keys form a **local verifier trust store** (a JSON file / supplied map) — no
network key resolution. Approvals are replay-bound to the request. The `mpa-authorized`
ledger entry records approver ids and the request hash only — never keys. CLI exit
codes: `2` budget exceeded, `3` authorization denied.

### Future
Webhook approver mode (full x402 parity); public-key (sigstore/minisign) approvals;
the ikigov MCP bridge once ikigov v0.13.0 ships.

---

## v0.4.0 — P2: DP-SGD Trainer (reference + Opacus seam)

**Deliberated:** 2026-06-08

### Scope decision
Make the DP accounting *real*: ship a runnable DP-SGD training loop that completes the
pipeline (train → charge ε → ledger → D4 evidence). Per the verifiability principle, the
default is a **dependency-free reference trainer** (correct Abadi et al. mechanism on
logistic regression) that runs fully in CI; the production Opacus backend is a seam behind
the `[torch]` extra, **not shipped unverified**.

### Components
`dp/trainer.py`: `DPTrainer` Protocol, `ReferenceDPSGDTrainer` (per-example L2 clipping to
`clip_norm` + Gaussian noise of std `noise_multiplier × clip_norm`, Poisson lots, averaged
over the expected lot size — Abadi et al. 2016), `TrainedModel`, and `make_trainer(backend)`
(`opacus` raises a clear NotImplementedError until the adapter is cross-validated against
the accountant). CLI `pai dp-train` reads `{"x":[...],"y":0|1}` JSONL, trains, charges the
budget via `EpsilonBudget.charge`, and optionally exports D4 evidence.

### Pinned semantics
The trainer's `noise_multiplier` is the noise-to-sensitivity ratio σ; `clip_norm` (C) is
the L2 sensitivity. Noise is `N(0, (σC)²)` per coordinate, so the accounted guarantee uses
`noise_multiplier=σ` at sensitivity 1 — identical to the `dpsgd_epsilon` accountant, which
the trainer calls so the charged ε is exactly the run's guarantee (asserted in tests).

### Acceptance criteria (each maps to a test)
1. Clipping bounds a per-example gradient to `clip_norm`; zero/under-cap vectors untouched. *(test_dp_trainer)*
2. Training separable data reaches ≥0.9 accuracy under DP noise. *(test_dp_trainer)*
3. Deterministic for a fixed seed. *(test_dp_trainer)*
4. `TrainedModel.result.epsilon` equals `dpsgd_epsilon(config)`. *(test_dp_trainer)*
5. Invalid data raises; `make_trainer("opacus")` raises NotImplementedError. *(test_dp_trainer)*
6. CLI `dp-train` runs end-to-end (charge + D4 evidence), exit 2 over-budget, 1 on bad input. *(test_dp_trainer)*

### Security note — randomness
DP's guarantee assumes good randomness. The reference trainer uses a **seedable** PRNG
(`random.Random`) for reproducibility/testing, flagged `# noqa: S311` with the explicit
caveat that a production noise source must be a CSPRNG (numpy Generator / `os.urandom`);
the Opacus backend uses torch's generator. Cross-validating a CSPRNG-backed run is part of
the deferred `[torch]` lane.

### Future
Opacus `DPTrainer` behind `[torch]` (real models, GPU) with an accounting cross-check vs
this accountant in a torch CI lane; CSPRNG noise option for the reference trainer.

---

## v0.5.0 — P3: Federated Learning

**Deliberated:** 2026-06-08

### Scope decision
Let a single org (or consortium) train across **silos that never share raw data** — the
P3 prize. Each silo runs local DP-SGD (the v0.4.0 reference trainer) starting from the
broadcast global model; a coordinator combines updates by FedAvg. The coordinator sees
only model updates, and a **secure-aggregation** seam means it can recover only the
*combined* update, not any individual silo's. Fully verifiable (no torch); the Opacus
local backend plugs in later via the v0.4.0 `DPTrainer` seam.

### Components
`fl/aggregation.py`: `Aggregator` protocol, `FedAvgAggregator` (sample-weighted mean),
`SecureSumAggregator` (zero-sum additive masking — same result, individual contributions
hidden). `fl/coordinator.py`: `FederatedClient`, `federated_train(clients, rounds,
local_config, aggregator)`, `FederatedResult`. CLI `pai fl-train --silo … --silo …`.

### Pinned semantics
- **Per-client DP composes over rounds.** A silo runs `local_steps` DP-SGD steps per round
  for `rounds` rounds; since RDP is additive over steps, the silo's guarantee is exactly
  `dpsgd_epsilon(steps = rounds × local_steps)` at its noise/rate — computed per client.
- **FedAvg** = sample-count-weighted mean of silo updates (McMahan et al. 2017).
- **Secure aggregation** = additive masks that cancel across clients; the server recovers
  Σ(weighted updates) without observing any single one. Single-process reference of the
  pairwise-mask protocol.

### Acceptance criteria (each maps to a test)
1. FedAvg is the correct sample-weighted mean. *(test_fl)*
2. SecureSum yields the same result as FedAvg; masked contributions sum (per coordinate)
   to the raw weighted sum yet differ from the individual raw contributions. *(test_fl)*
3. `federated_train` learns a separable boundary across two silos (pooled accuracy ≥0.9). *(test_fl)*
4. Each silo's `per_client_epsilon` equals `dpsgd_epsilon(rounds × local_steps)`. *(test_fl)*
5. Deterministic for a fixed seed; SecureSum end-to-end matches FedAvg. *(test_fl)*
6. Invalid input (no clients, rounds<1, malformed silo) raises / CLI exit 1. *(test_fl)*

### Security
Raw silo data never leaves the silo — only DP-noised model updates are shared. Per-client
DP bounds each silo's contribution; secure aggregation hides individual updates from the
coordinator. The reference masking uses a seedable PRNG (noted as not production crypto;
a deployment uses pairwise-exchanged mask seeds and a CSPRNG).

### Future
Opacus local backend behind `[torch]`; per-silo budget/evidence integration (reuse
`EpsilonBudget` + D4 export per client); cross-silo (sample-level) accounting variants;
dropout-robust secure aggregation.

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
