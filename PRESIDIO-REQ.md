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
  `.github/workflows/codeql.yml`, `.github/workflows/ci.yml` (pytest + ruff; extras lanes
  `ci-torch.yml`, `ci-mpc.yml`, `ci-zk.yml`).

## Technical Requirements

- Python 3.11+ (3.10 reached end of life in October 2026; same floor as presidio-evidence
  and ikigov-assess).
- Runtime dependency on `presidio-evidence` (canonical JSON, evidence signing, envelope).
- `pyproject.toml` + hatchling + Typer CLI; `src/presidio_ai/` layout.
- 80%+ test coverage with pytest; ruff lint + format clean.
- LICENSE = MIT. Version = 0.30.0.

---

# Version Registry & Deliberation Log

## Roadmap Summary

| Version | Phase | Theme | Status |
|---|---|---|---|
| v0.1.0 | P1 | Evidence layer: tamper-evident ledger + PII-scrub on ingest + signed `EvidenceRef` export | Shipped |
| v0.2.0 | P2 | DP-SGD fine-tune harness + ε-budget accountant (public-base / private-delta) | Shipped |
| v0.3.0 | P2 | n-of-m authorization (MPA) for high-ε jobs (ikigov bridge deferred to ikigov v0.13.0) | Shipped |
| v0.4.0 | P2 | DP-SGD trainer: verifiable stdlib reference + Opacus adapter seam (`pai dp-train`) | Shipped |
| v0.5.0 | P3 | Federated learning: FedAvg across silos + secure aggregation + per-client DP (`pai fl-train`) | Shipped |
| v0.6.0 | P2 | Opacus DP-SGD backend + torch CI lane; CSPRNG noise option for the reference trainer | Shipped |
| v0.7.0 | — | Ed25519 public-key evidence signing + `pai keygen` (`[crypto]` extra); HMAC default | Shipped |
| v0.8.0 | — | Ed25519 becomes the **default** signing algorithm (coordinated with ikigov v0.14.0 verification) | Shipped |
| v0.9.0 | P3 | FL governance: per-silo ε-budget charging + signed D4 evidence in `pai fl-train` (`--charge`) | Shipped |
| v0.10.0 | P2 | Tighter RDP→DP conversion (Canonne-Kamath-Steinke 2020); strictly ≤ the prior bound | Shipped |
| v0.11.0 | P4 | Secure-aggregation core: additive masking + Shamir dropout recovery (`fl.secure_agg`) — ADR-0001 | Shipped |
| v0.12.0 | P4 | Exact field-quantised secure aggregation (no float-cancellation error) | Shipped |
| v0.13.0 | P4 | Governed consortium rounds: MPA + per-silo DP + one signed D4 (`pai consortium-round`) | Shipped |
| v0.14.0 | P4 | `[mpc]` lane: authenticated X25519 key agreement + transport wire format | Shipped |
| v0.15.0 | P2 | Fractional-order RDP accountant (TF-Privacy/Opacus series); ≤ integer-only ε | Shipped |
| v0.16.0 | P4 | Pedersen commitments + Feldman VSS primitives (`fl.commit`) — ADR-0002 | Shipped |
| v0.17.0 | P4 | Verifiable (Feldman-VSS) seed sharing in `SecureAggregationSession` | Shipped |
| v0.18.0 | P4 | Malicious-secure consortium round: signed survivor-set + homomorphic aggregate check | Shipped |
| v0.19.0 | P4 | Zero-knowledge bounded-norm proofs (`fl.zk`): Pedersen range + L∞ vector — ADR-0003 | Shipped |
| v0.20.0 | P4 | Bounded-norm ZK gate in the secure round; DP clip sensitivity *proven*, not assumed | Shipped |
| v0.21.0 | P4 | Pluggable `ProofBackend` interface + MODP backend + auto-dispatch — ADR-0004 | Shipped |
| v0.22.0 | P4 | Ristretto255 + Bulletproofs native backend (`rust/`, `[zk]`, `ci-zk`) — accelerator | Shipped |
| v0.23.0 | P4 | **L2** bounded-norm proofs (commit-squares) on the MODP backend — ADR-0005 | Shipped |
| v0.24.0 | P4 | L2 on the Ristretto native backend (square Σ-proof over points + native range) | Shipped |
| v0.25.0 | P4 | GOD interim: exclude-and-retry liveness (`run_consortium_round_with_retry`) — ADR-0006 D | Shipped |
| v0.26.0 | P4 | Robust reconstruction (`robust_reconstruct`) — verify/discard/interpolate | Shipped |
| v0.27.0 | P4 | GOD aggregation + round (`fl.god`, `run_god_consortium_round`) — honest-majority | Shipped |
| v0.28.0 | P4 | Bounded-norm gate on the GOD path via commitment-equality binding (ADR-0006 item 4) | Shipped |
| v0.29.0 | P4 | Whole-consortium bounded-norm proof aggregation (cross-bound batch / native Bulletproof) | Shipped |
| v0.30.0 | P4 | Byzantine-ML robustness gate: aggregate validation + rollback + canary (`fl.robustness`) — ADR-0007 | Shipped |
| v0.31.0 | — | Strict canonical JSON + decimal-string privacy parameters (#68); ADR-0002 provenance `parents` + `--parent` (#67) | **Current** (unreleased) |
| — | — | `ci-zk` manual until first green build on a Rust runner; then benchmarks | Deferred |

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

## v0.6.0 — P2: Opacus DP-SGD Backend + Torch CI Lane

**Deliberated:** 2026-06-08

### Scope decision
Complete the DP-SGD harness with the production **Opacus** backend behind the `[torch]`
extra, and add the **CI lane that verifies it**. The prior versions deliberately shipped
only the dependency-free reference trainer because torch can't run in the default
(dependency-light) test environment; this version adds a separate CI job that installs
`[torch]` and exercises the adapter — so the torch code is verified in CI rather than
shipped unverified.

### Components
`dp/trainer.OpacusDPSGDTrainer` (implements `DPTrainer`; lazy torch/opacus import — a clear
ImportError without the extra). `make_trainer("opacus")` returns it. The returned
`TrainedModel.result` uses **this suite's accountant** so the evidence epsilon is identical
across backends. New `.github/workflows/ci-torch.yml` installs `.[dev,torch]` and runs
`tests/test_opacus.py`. The reference trainer gains a `secure_rng` option (CSPRNG noise via
`random.SystemRandom`) closing the v0.4.0 randomness caveat — at the cost of reproducibility.

### Cross-validation (the point of the lane)
`tests/test_opacus.py` trains a model via Opacus **and** compares Opacus' own privacy
accountant (`PrivacyEngine.get_epsilon`) against `dpsgd_epsilon` for the same parameters.
They must agree to the same order of magnitude (0.2× – 5× tolerance across Opacus
versions); ours is a sound integer-order **upper bound**, so it should not be smaller than
Opacus' tighter (fractional-order) estimate by much.

### Acceptance criteria
1. Without `[torch]`, `make_trainer("opacus")` raises a clear ImportError and the default
   test lane is unaffected (`test_opacus.py` skips via `importorskip`). *(test_dp_trainer / default CI)*
2. `secure_rng=True` produces a valid model and is non-deterministic (CSPRNG). *(test_dp_trainer)*
3. **[torch lane]** Opacus backend trains separable data to ≥0.8 accuracy. *(test_opacus)*
4. **[torch lane]** Opacus' accountant cross-validates against `dpsgd_epsilon`. *(test_opacus)*

### Security
`secure_rng` uses an `os.urandom`-backed CSPRNG for DP noise (production-grade; the default
seedable PRNG remains for reproducible reference/testing). The Opacus path uses
`PrivacyEngine(secure_mode=secure_rng)`, which uses a cryptographically secure RNG when set.

### Future
GPU lane; larger reference models; PRV accountant option to tighten our bound toward
Opacus'.

---

## v0.8.0 — Ed25519 Becomes the Default Signing Algorithm

**Deliberated:** 2026-06-08

### Scope decision
Flip the default evidence signing algorithm from HMAC-SHA256 to **Ed25519**, now that the
consumer (ikigov **v0.14.0**) verifies public-key signatures. HMAC remains available via
`--algorithm hmac-sha256` (and `algorithm="hmac-sha256"` in the library). No new
mechanism — purely the default — so the change is small: `build_ingest_evidence` /
`build_dp_evidence` and the `ingest` / `dp-charge` / `dp-train` `--algorithm` options now
default to `ed25519`.

### Consequence
Evidence export now **requires a signing key** under the default: generate one with
`pai keygen` and pass `--signing-key` (Ed25519 private hex). HMAC continues to reuse the
ledger key when explicitly selected.

### Deploy ordering (important)
Roll out / commit the ikigov **v0.14.0** verifier (public-key trust entries) **before or
together with** this flip, so the live governance loop never receives Ed25519 evidence a
v0.13.0 (HMAC-only) verifier cannot check. End-to-end verified across both repos against
the fixed-key golden vector.

### Tests
The HMAC path stays covered by pinning `algorithm="hmac-sha256"` in the legacy evidence
tests; the Ed25519 default path is covered by `test_ed25519.py`. Gate: 149 passed,
1 skipped (torch).

---

## v0.7.0 — Public-Key (Ed25519) Evidence Signing

**Deliberated:** 2026-06-08

### Scope decision
Add **Ed25519** signing for `EvidenceRef` alongside the HMAC baseline — the public-key
foundation that lets the IKI-Gov consumer retire shared-secret verification. The
**signing algorithm is a property of the verifier's trust store** (the verifier knows
whether a signer uses an HMAC secret or an Ed25519 public key), so the 8-field
`EvidenceRef` contract is **unchanged**: an Ed25519 signature is 64 bytes / 128 hex,
within the existing hex bound. Verifiable in CI — unlike torch, `cryptography` runs in
the default test lane.

### Sequencing (no break to the live loop)
HMAC-SHA256 remains the **default** signing algorithm this version, so the running
ikigov v0.13.0 verifier keeps working unchanged. Ed25519 is opt-in (`--algorithm
ed25519`). The default flips to Ed25519 only after the ikigov consumer learns to verify
public-key signatures (its trust store entries gaining `{alg, public_key}`) — the
immediate follow-up.

### Components
`evidence.py`: `generate_ed25519_keypair`, `sign_ed25519`, `verify_ed25519`, and an
algorithm dispatch in `_sign`/`build_ingest_evidence`/`build_dp_evidence`
(`algorithm="hmac-sha256" | "ed25519"`). Lazy `cryptography` import (clear ImportError
without the `[crypto]` extra). CLI: `pai keygen` (Ed25519 keypair) and `--algorithm` /
`--signing-key` on `ingest` / `dp-charge` / `dp-train`.

### Acceptance criteria (each maps to a test)
1. Keypair shapes; fixed-key signature is the deterministic golden vector (RFC 8032). *(test_ed25519)*
2. Verify is fail-closed: wrong pubkey, tampered content, wrong signer binding, malformed
   signature all return False. *(test_ed25519)*
3. `build_*` with `algorithm="ed25519"` produces refs that verify under the public key and
   do **not** verify under HMAC. *(test_ed25519)*
4. Ed25519 requires a str private-key hex; unknown algorithm raises. *(test_ed25519)*
5. CLI: `keygen`; `ingest`/`dp-train --algorithm ed25519 --signing-key` produce
   pubkey-verifiable evidence; missing key exits 1. *(test_ed25519)*

### Security
Ed25519 (RFC 8032) detached signatures over the canonical `{content_hash, signer}` — the
same message HMAC signs, so the two are drop-in at the wire level. Private keys never
leave the producer; only public keys go in a verifier's trust store. The golden vector
locks the wire format for the cross-repo consumer.

### Future
Flip the default to Ed25519 once ikigov verifies it; key rotation / multiple active keys
per signer; sigstore keyless option.

---

## v0.9.0 — Federated-Learning Governance (per-silo budget + evidence)

**Deliberated:** 2026-06-08

### Scope decision
Close the FL governance loop: a federated run should produce the **same** auditable
artifacts as single-node `dp-train`, but **per silo**. `charge_federated` charges each
silo's composed (ε, δ) to its own tamper-evident ledger budget and optionally exports a
signed **D4** evidence ref per silo — so a consortium can feed each member's evidence into
an independent IKI-Gov assessment. Per-silo budgets are independent; raw data still never
leaves the silo (unchanged from v0.5.0).

### Components
`fl/governance.py` (`charge_federated`, `SiloGovernance`). CLI: `pai fl-train` gains
`--charge` with `--total-epsilon`, `--ledger-dir`, `--key`, and optional `--evidence-dir` /
`--algorithm` / `--signing-key` / `--signer` (Ed25519 default, consistent with v0.8.0).

### Acceptance criteria (each maps to a test)
1. `charge_federated` writes one charge entry to each silo's own (chain-verified) ledger. *(test_fl_governance)*
2. With `--evidence-dir`, each silo's D4 evidence verifies under the Ed25519 public key. *(test_fl_governance)*
3. Per-silo budgets are independent; a silo's ledger holds only its own charge. *(test_fl_governance)*
4. Over-budget raises `BudgetExceeded` (CLI exit 2). *(test_fl_governance)*
5. CLI `--charge` reports per-silo remaining ε + evidence path; missing `--total-epsilon`/
   `--ledger-dir` exits 1. *(test_fl_governance)*

### Completes
The DP → budget → evidence → ikigov loop now holds for federated training, not just
single-node — the full suite governs centralized and cross-silo training identically.

---

## v0.10.0 — Tighter RDP→DP Conversion (Canonne-Kamath-Steinke 2020)

**Deliberated:** 2026-06-08

### Scope decision
Replace the classic Mironov (2017) RDP→(ε,δ) conversion with the tight
**Canonne-Kamath-Steinke (2020)** conversion (the same one Opacus uses) — the deferred
tightening from the v0.2.0 accountant. Per order α>1:
``ε(α) = ρ(α) + log1p(-1/α) - (log δ + log α)/(α-1)``, minimised over orders. The two
extra terms are non-positive for α>1, so the result is **never looser** than the prior
bound — it is a sound upper bound that strictly tightens the reported ε. No change to the
RDP computation or composition; only the final conversion.

### Effect
The canonical example (σ=1.1, q≈256/60000, 5000 steps, δ=1e-5) drops from ε≈1.83 to
ε≈1.51. This also **tightens agreement with the Opacus accountant** (which uses the same
conversion), so the torch-lane cross-check ratio moves closer to 1.

### Acceptance criteria (each maps to a test)
1. CKS ε is positive and **≤ the Mironov bound** for the same RDP curve. *(test_accountant)*
2. Existing monotonicity / smaller-δ-costs-more / closed-form-oracle tests still hold
   under the tighter conversion. *(test_accountant)*
3. The Opacus cross-validation (torch lane) stays within tolerance (now closer to 1).
   *(test_opacus)*

### Future
Fractional Rényi orders for the subsampled-Gaussian bound (a further, smaller tightening)
remain deferred — the integer-order bound + CKS conversion is the verified baseline.

---

## v0.11.0 — Secure-Aggregation Core (P4 v1, ADR-0001)

**Decision (ADR-0001, Accepted 2026-06-08).** The consortium computation is a *sum*
(FedAvg), so P4 uses **secure aggregation by additive masking** (Bonawitz et al., 2017),
not general-purpose MPC. The coordinator recovers only the aggregate; no individual party
update is ever revealed, at symmetric-crypto cost, and the scheme *layers* with per-client
DP for the same defence-in-depth used elsewhere.

**Shipped this version — the pure-Python, fully-tested core** (`presidio_ai.fl.secure_agg`):

- **Antisymmetric pairwise masks.** Each pair shares a seed; party *i* adds `+PRG(s_ij)`
  when `i<j` and `-PRG(s_ij)` when `i>j`, so pairwise masks cancel in the sum.
- **Self-masks.** A private `PRG(b_i)` per party closes the window where a coordinator who
  learned a *dropped* party's pairwise seeds could strip a survivor's input.
- **Dropout recovery via Shamir t-of-n.** Self and pairwise seeds are secret-shared; from
  any `t` survivor shares the coordinator reconstructs survivors' self-seeds (to remove
  self-masks) and dropped parties' pairwise seeds (to remove masks that no longer cancel).
  Fewer than `t` survivors **fails closed**.
- **Verified** to reproduce plaintext FedAvg with and without dropout (ADR action items
  3 & 6); seeds drawn from a CSPRNG by default (`secrets.SystemRandom`).

**Threat model (v1).** Honest-but-curious coordinator + ≤`t` colluding parties. Malicious
security is explicitly out of scope (revisit via commitments / verifiable secret sharing,
or threshold HE — ADR-0001 Option C).

**Deferred to the `[mpc]` lane** (network, not core): authenticated pairwise key agreement
(seeds are modelled in-process today), the HTTP/transport layer in a dedicated CI lane
(mirroring `[torch]`), field-quantised exact arithmetic (removes float-cancellation
tolerance and overflow), and per-round composition — per-client DP on inputs, n-of-m MPA
to authorize a round, and one signed `D4` evidence + ledger entry per consortium round
(aggregate only).

---

## v0.12.0 — Exact Field-Quantised Secure Aggregation (P4)

The v0.11.0 core masked in floating point, so cancellation was exact only to rounding.
v0.12.0 moves all masking and reconstruction into the prime field GF(`PRIME`): real
updates are quantised once at the boundary (fixed-point, `frac_bits`) and the field
aggregate de-quantised once at the end. Cancellation is now **exact** (integer equality,
verified), with no float accumulation and no overflow within `±PRIME/2` fixed-point units.
The hash-based field PRG (SHA-256 counter mode, 128-bit reduction, bias ≤ 2⁻⁶⁷) replaces
the float PRG. `set_pairwise_seed` adds the seam the key-agreement layer plugs into.

---

## v0.13.0 — Governed Consortium Rounds (P4)

`run_consortium_round` makes one round a governed operation end to end: **(1)** n-of-m MPA
authorises the round (gated on the worst-case per-party ε, recorded to the ledger before
any aggregation); **(2)** survivors' updates are combined by exact secure aggregation
(coordinator sees only the aggregate; dropout-recovered or fail-closed); **(3)** each silo's
(ε, δ) is charged to its **own** ledger budget (distributed DP); **(4)** one signed **D4**
EvidenceRef commits to the *aggregate only* + worst-case bound, pointing at a
commitments-only `consortium-round` ledger entry. CLI: `pai consortium-round`.

---

## v0.14.0 — `[mpc]` Lane: Authenticated Key Agreement + Transport (P4)

Replaces the in-process seed assumption with real cryptography. **X25519** Diffie–Hellman
→ **HKDF-SHA256** → field-element seed, with an order-independent `info` (sorted ids +
session id) so both endpoints derive the same seed and rounds are domain-separated. Each
DH public key is **Ed25519-signed** under the party's identity key and verified against a
local trust store; `establish_pairwise_seeds` is **fail-closed** — a coordinator that
substitutes its own DH key for a party it lacks the identity key for is rejected (MITM
defeated). A validated `MaskedSubmission` wire format + a thin Starlette/uvicorn
coordinator sit behind the `[mpc]` extra; verifiable core (key agreement, wire format)
runs in the default lane, with a dedicated `ci-mpc` lane for the full stack.

**Deferred (next P4 step):** malicious-security hardening — the coordinator/parties are
honest-but-curious in v1; a malicious model needs commitments / verifiable secret sharing
(ADR-0001 revisit trigger), and very large consortia may want HE packing (Option C).

---

## v0.15.0 — Fractional-Order RDP Accountant (P2)

Adds non-integer Rényi orders to the subsampled-Gaussian accountant. Integer orders keep
the exact closed-form binomial bound; fractional orders use the canonical TF-Privacy/Opacus
log-A series with a pure-stdlib stable `_log_erfc` (`math.erfc` below x=20, asymptotic
expansion above). `dpsgd_epsilon` minimises over `FRACTIONAL_ORDERS` by default, so the
reported ε is **≤** the integer-only result (`DEFAULT_ORDERS` retained as the oracle). In
high-sampling-rate regimes a sub-2 order strictly wins (e.g. ε 118 vs 246 at q=0.2).

**Verified:** the fractional series converges to the integer closed form as α→integer
(residual scales linearly with the offset — a derivative term, not error); RDP monotone in
α; fractional grid never looser than integer; Opacus cross-validation tightened to rel=0.2.
The series coefficient is updated incrementally (O(n), not O(n²)); non-converging fractional
orders are skipped (integers always succeed), never aborting.

---

## v0.16.0–v0.18.0 — Malicious-Security Hardening (P4, ADR-0002)

ADR-0002 (Accepted, Option A) extends the threat model from honest-but-curious to a
**deviating** coordinator or colluding parties, with **security-with-abort**. Three
mechanisms, each closing one named attack, all anchored in the ledger:

- **v0.16.0 — primitives (`fl.commit`).** A pure-Python prime-order Schnorr group over the
  RFC 3526 MODP-2048 safe prime. **Pedersen commitments** `g^m h^r` (hiding, binding,
  *additively homomorphic*) and **Feldman VSS** (Shamir shares + `g^{a_i}` coefficient
  commitments so a recipient rejects an inconsistent share). No new binary dependency;
  primality of the hardcoded modulus is re-verified in tests.
- **v0.17.0 — verifiable seed sharing.** `SecureAggregationSession(group=…)` shares the
  self/pairwise mask seeds with Feldman VSS; reconstruction verifies every quorum share
  against the published commitments and **fails closed** on a tampered share. *Refinement
  to the ADR's field-migration concern:* only the seed-sharing exponent field moves to
  `Z_q`; the additive masking stays exact in GF(2⁶¹−1) (the seed is just a larger int into
  the PRG), so the honest-but-curious path is unchanged.
- **v0.18.0 — malicious-secure round (`run_secure_consortium_round`).** Abort-before-side-
  effects: **(1)** a `≥t`-signed, ledger-anchored agreement on the survivor set — each
  signature binds the exact alive-set, so a coordinator cannot equivocate to mount the
  Bonawitz unmasking attack; **(2)** Pedersen-committed inputs; **(3)** verifiable-session
  aggregation (VSS-checked); **(4)** a **homomorphic aggregate check** — the product of
  input commitments must equal a commitment to the returned aggregate, so a *false
  aggregate* aborts (holds in the no-wrap operating range); **(5)** only then MPA + per-silo
  DP charge + a commitments-only round entry (survivor signers + input-commitment digest) +
  one signed `D4`.

**Threat model now:** confidentiality + integrity-or-abort against a malicious coordinator
(equivocation, false aggregate) and a malicious minority of parties (inconsistent shares).
A cheater can still force a clean, attributable **abort** (a DoS) — accepted; availability
is not confidentiality/integrity.

**Deferred (separate ADRs):** bounded-norm **ZK input validation** (well-formed-but-
adversarial updates / model poisoning — a different, Byzantine-robustness problem) and
**guaranteed-output-delivery** MPC. The commitment cost at full model dimension and a
production group/transport binding are the remaining engineering items (ADR-0002 item 7).

---

## v0.19.0–v0.20.0 — Bounded-Norm ZK Input Validation (P4, ADR-0003)

ADR-0003 (Accepted, Option A) closes the last deviation gap ADR-0002 named: a **well-formed
but out-of-norm** update used to dominate/poison the aggregate. Because secure aggregation
hides individual updates, the bound is proven in **zero knowledge**.

- **v0.19.0 — `fl.zk`.** A transparent (no trusted setup) Pedersen **bit-decomposition range
  proof** over the prime-order MODP-2048 group: a Chaum–Pedersen OR-proof per bit, bound to
  the commitment via the product check `Π C_i^{2^i} == C`, with a Fiat–Shamir transcript
  binding the group, commitment, bound, and all bit commitments. On top, an **L∞ bounded-norm
  vector proof** (`prove_bounded`/`verify_bounded`) range-proves each shifted commitment
  `C_k·g^B` in `[0, 2^bits)`.
- **v0.20.0 — gate.** `run_secure_consortium_round(clip_bound=…)` admits a contribution only
  if its bounded-norm proof verifies against the **same** input commitments; a poisoning
  update (norm > bound) is rejected before aggregation. Parties now commit to *signed*
  fixed-point values so one commitment is both range-provable and homomorphically checkable.

**The point.** The proven bound is the DP **clip sensitivity**, so the per-client `(ε, δ)`
the accountant reports and the ledger attests becomes **sound against a malicious client** —
sensitivity is *proven*, not assumed. The round records `sensitivity_proven` on the ledger.

**Deviation from ADR-0003 (honest note).** The ADR recommended Bulletproofs over Ristretto255;
neither is available (this libsodium build has no Ristretto255; no vetted Python Bulletproofs
library exists). v1 uses a textbook, fully-tested range proof over the vetted MODP group —
same ZK guarantee, `O(n)` proof vs `O(log n)`. **Deferred:** the Ristretto255 + Bulletproofs
performance backend (reserved `[zk]` extra; likely Rust-FFI), the **L2** bound (matches the
clip norm exactly), and guaranteed-output-delivery MPC. *Semantic* robustness (in-norm
backdoors) is a Byzantine-ML problem, out of scope for cryptographic validation.

---

## v0.21.0–v0.22.0 — Pluggable Proof Backend: Ristretto255 + Bulletproofs (P4, ADR-0004)

ADR-0004 makes the ADR-0003 bounded-norm proofs production-fast without touching the
guarantee, the `EvidenceRef@1` contract, or the threat model.

- **v0.21.0 — the seam.** A `ProofBackend` Protocol (commit / homomorphic sum / serialize /
  prove_bounded / verify_bounded; commitments opaque, blindings plain ints) with `ModpBackend`
  (the ADR-0003 pure-Python proofs) as a **dependency-free fallback**. `get_backend()` tries
  the native wheel and otherwise returns MODP, cached. `run_secure_consortium_round` dispatches
  through `backend=`. Hardening fix: `verify_bounded` binds the proof to the *requested* bound.
- **v0.22.0 — the accelerator.** `rust/` is a PyO3/maturin crate (`presidio_ai_zk`) over the
  **audited** dalek `bulletproofs` + `curve25519-dalek`: Pedersen commitments + an aggregated
  `O(log n)` L∞ range proof, with the same shift-by-`B` semantics as MODP. A `ci-zk` lane
  builds the wheel and cross-validates native vs MODP on **decision equivalence** (the two
  are not byte-compatible). `[zk]` stays installable (no-op) so the fallback always works.

**The architectural move:** the `[zk]` extra is an *accelerator, not a requirement* — a
deployment that can build the Rust wheel gets audited production speed; one that cannot still
gets correct bounded-norm validation, slower. Identical guarantee on both paths.

**Build note.** The native crate is buildable, CI-validated source; it is **not** compiled in
the dev sandbox (no Rust toolchain). It builds and self-validates in `ci-zk`; the default gate
runs the MODP backend. **Deferred:** the **L2** bound (build on this backend's inner-product
argument) and guaranteed-output-delivery MPC.

---

## v0.23.0–v0.24.0 — L2 Bounded-Norm Proofs (P4, ADR-0005)

ADR-0005's commit-squares construction proves the **exact** DP clip norm `‖x‖₂ ≤ C` (not the
`√d`-loose L∞ proxy), from standard primitives on both backends.

- **The new primitive — a square-correctness Σ-proof.** Proving `C_y` commits to the square
  of `C_x`'s value reduces to `C_y = C_x^x · h^{r_y − x·r_x}` — an AND of openings sharing the
  witness `x`. No arithmetic-circuit (r1cs) machinery.
- **L2 = squares + homomorphic sum + one range proof.** Each coordinate's square is committed
  and square-proven; the **homomorphic sum of the square commitments is already a commitment
  to `Σ x_k²`**, so the squared-norm needs no extra aggregation proof — just range-prove it
  `≤ C²` with the backend's existing range proof. So L2 is "L∞'s range proof applied once to a
  homomorphically-assembled squared-norm, plus a square proof."
- **v0.23.0 (MODP)** is the verified default (pure-Python, the `≤ C²` check via two range
  proofs). **v0.24.0 (Ristretto native)** expresses the same Σ-protocol from two generic point
  primitives in the wrapper and delegates the squared-norm check to the native range proof;
  `ci-zk` validates native↔MODP **decision equivalence**.
- `run_secure_consortium_round(l2_bound=…)` gates on `‖x‖₂ ≤ C` and records `proven_norm="l2"`
  on the ledger. A vector within L∞ but over L2 is rejected (the whole point).

**The payoff:** the per-client `(ε, δ)` is now sound against a malicious client at the *exact*
clip norm DP-SGD uses, not a loose proxy. **Deferred:** guaranteed-output-delivery MPC and
whole-consortium proof aggregation. *Semantic* (in-norm backdoor) robustness remains out of
scope for cryptographic validation.

---

## v0.25.0–v0.27.0 — Guaranteed Output Delivery (P4, ADR-0006, Option A)

ADR-0006 upgrades ADR-0002's security-with-abort to **guaranteed output delivery**: the round
delivers the correct aggregate even when a minority misbehaves, so one bad member cannot DoS
the consortium. The precondition is an **honest majority** (`n ≥ 2t+1`) — a trust premise the
consortium accepts.

- **v0.25.0 — interim (Option D).** `run_consortium_round_with_retry` runs the ADR-0002 round
  and, on an attributable `PartyMisbehavior`, drops the culprit (it becomes a tolerated
  dropout) and re-runs among the rest, with honest parties re-signing the smaller survivor set.
  GOD-in-practice for malicious *parties* with zero new crypto.
- **v0.26.0 — robust reconstruction.** `robust_reconstruct` verifies shares against the Feldman
  commitments, discards invalid ones, and interpolates from a valid quorum — robust *detection*
  (so `n ≥ 2t+1` suffices, not `3t+1`).
- **v0.27.0 — robust secret-sharing aggregation (Option A).** Each party VSS-shares its update;
  shares add locally (sum of shares = a sharing of the sum, no multiplication); the sum is
  robustly reconstructed by any honest quorum. A **malicious dealer** is excluded (its
  inconsistent shares fail Feldman verification); a **malicious holder** is discarded (its bad
  summed-share fails the homomorphically-combined commitments); and there is **no coordinator**
  to halt the round. `run_god_consortium_round` composes MPA + per-silo DP + a signed `D4` and
  records `mode="god"` + the excluded set on the ledger.

**Right-sized:** because the target is a *sum*, GOD needs no multiplication gates — Option A is
general GOD-MPC specialised to linear functions, reusing the suite's Feldman VSS. **Remaining
(ADR-0006 item 4):** binding the bounded-norm ZK gate to the *shared* inputs needs a small
cross-commitment equality proof. **Deferred:** whole-consortium proof aggregation; general
GOD-MPC for non-linear aggregates; verifiable threshold HE.

---

## v0.28.0–v0.29.0 — GOD Bounded-Norm Binding + Whole-Consortium Aggregation (P4)

- **v0.28.0 — bounded-norm on the GOD path (ADR-0006 item 4, closed).** The GOD aggregation
  shares a value whose Feldman commitment is `C_0 = g^s` (binding, not hiding), so the
  bounded-norm ZK gate (over a *hiding* Pedersen `g^s h^r`) is bound to it by a
  **commitment-equality Schnorr proof**: `C_ped · C_fel^{-1} = h^r` is a pure power of `h`
  iff the `g`-exponents match. `run_god_consortium_round(clip_bound=/l2_bound=)` now gates each
  party's *shared* input on the proven norm and excludes a party that fails the norm or the
  binding — GOD still delivers over the honest set.
- **v0.29.0 — whole-consortium aggregation.** One round-level bounded-norm proof for every
  party. A transcript `domain` hashing **all** parties' commitments cross-binds the batch
  (tampering any one commitment fails the whole proof). On the MODP path this is a cross-bound
  collection (verified); on the native Ristretto path it is a **single Bulletproof over the
  concatenated consortium vector** (true `O(log)` aggregation via `prove_multiple`).

This closes the last two open P4 sub-items. The only remaining work is operational: the first
`ci-zk` / `ci-mpc` / `ci-torch` runs to compile the native lanes and produce the benchmark
numbers (the crypto and its decision-equivalence tests are in place).

---

## v0.30.0 — Byzantine-ML Robustness Gate (P4, ADR-0007)

Closes the last deferred security scope (semantic robustness, named across ADR-0002/0003/
0005/0006). In-norm backdoors are an **ML-robustness** problem and collide with the privacy
guarantee — robust rules need the individual updates secure aggregation hides — so v1 is a
**privacy-preserving layered posture** (Option C), not detection-and-attribution:

- **`fl.robustness`** scores a round's *aggregate* (never an individual update) against a
  consortium-supplied clean validation set + canary/trigger suite; a round that fails (low
  score, regression, or a triggered canary) is **rolled back** — aggregate not applied, no DP
  budget charged, no `D4` emitted — and flagged on the ledger.
- It composes with the existing influence-bounding floor (proven L2 norm + per-client DP, both
  recognised poisoning mitigations) and the accountability layer (MPA + signed/ledgered
  contributions). Residual stated in SECURITY.md: a stealthy validation-passing backdoor can
  pass; v1 contains and attributes rather than detects.

**Deferred (ADR-0007):** a per-party cosine-band ZK increment (B) and robust-aggregation-under-
MPC (A) for a malicious majority of contributions.

---

## v0.31.0 — Strict Canonical Encoding + Provenance Parents (#68, #67)

Two integration gaps from the 2026-10-10 portfolio review, closed together because both
change what the D4 content hash covers.

**#68 — floats in hashed payloads.** `hashing.py` duplicated the family Layer-0
canonicaliser without its float rejection (presidio-evidence ADR-0001 D1), and D4 DP and
consortium content, authorization requests and ledger MACs all hashed Python floats.
Other implementations (presidio-evidence, treasury's Rust canonicaliser) refuse such
content, so the D4 refs could not sit in the shared evidence DAG.

- **R-C1 Strict profile for all new bytes.** `canonical_json` = sorted keys, compact
  separators, UTF-8, `allow_nan=False`, floats rejected at any depth. Verified against
  presidio-evidence's `canonical-json` (incl. rejected-float cases) and `signing` vectors,
  copied into `tests/vectors/` with a provenance note.
- **R-C2 Decimal strings (family ADR-0005 draft).** Non-integer values in signed payloads
  are plain-notation decimal strings, half-even at a per-field precision declared in
  `docs/schemas/signed-payloads.md` and encoded by one helper (`numeric.encode_field`):
  epsilon / max_epsilon / noise_multiplier / score / proven bounds 12 fractional digits;
  delta and sample_rate 18 (small probabilities); optimal_order 6, always a string (both
  order grids are multiples of 0.25). NaN/Infinity rejected; a non-zero delta or
  sample_rate that would round to `"0"` is rejected (it would overstate the guarantee).
- **R-C3 Legacy verification, no rewrite.** New ledger entries and authorization requests
  carry `canon: 1`. Untagged entries and pre-0.31 approvals verify through the frozen
  `_legacy_canonical_v0`, which never produces new bytes. Untagged-after-tagged and
  unknown tags are rejected. Removal trigger in `MIGRATION.md` (#74).
- **R-C4 Ingest hashes data bytes.** Source commitment over the input bytes as read
  (`raw-input-bytes`); scrubbed `content_hash` over `records-jsonl@1`, which `--out`
  writes byte-for-byte. Scopes recorded in the ledger entry and the evidence content.

**#67 — no provenance parents.** D4 refs from `dp-train` and the consortium round could
not name the ikigov gate certificate or dataset they were produced under, so the
storyline's gate → training-run edge was missing exactly where training happens.

- **R-P1** Top-level `parents` (ADR-0002 P1–P5) in DP (`dp-result@1`), consortium
  (`consortium-round@1`) and ingest (`ingest-record@1`) evidence content and the matching
  ledger entries: lowercase hex `^[0-9a-f]{8,128}$`, order-preserving, de-duplicated,
  omitted when empty, malformed entries rejected before any side effect, not resolved by
  the producer.
- **R-P2** Repeatable `--parent HEX` on `pai ingest`, `dp-train`, `dp-charge`,
  `consortium-round`; exit 1 on a malformed value.
- **R-P3** Parent-less content hashes are identical to the same record without the
  feature; two are pinned in `tests/test_provenance.py`.
- **Delivered in 0.32.0 (#77):** `--gate-certificate` with `--gate-trust` verifies the
  ikigov gate certificate before training (see v0.32.0 below). A `training-run@1`
  payload is still not emitted.

**Consequence:** content hashes of new DP/consortium/ingest refs differ from 0.30.0 for
the same run; existing refs still verify (their signatures are over float-free
`{content_hash, signer}`). The `EvidenceRef@1` contract is unchanged.

---

## Cross-cutting decisions

| Decision | Rationale |
|---|---|
| Commitments-only ledger | The audit log must never become a new breach surface; hashes/counts prove facts about data without holding it |
| Keyed MAC mandatory | An unkeyed hash chain is forgeable; tamper-evidence requires a secret |
| `EvidenceRef` owned here, consumed by ikigov | The governance spine stays framework-pure; each control owns and versions its own item→evidence map |
| Evidence is provenance, not score | Maturity (how complete) and evidence coverage (how verifiable) are orthogonal |
| Strict canonical JSON, decimal strings (v0.31.0) | A hash other family implementations cannot recompute is not evidence; floats have no portable canonical form |

## SDLC

Developed under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.

---

## v0.32.0 — Verified gate certificates, presidio-evidence dependency, Python 3.11+

**#77 — the gate edge was unverified.** `--parent` takes any well-formed hex value, so a
DP run could name a gate certificate that was expired, BLOCKED or never issued.
presidio-evidence 0.4.0 shipped the `gate-certificate@1` identity (family ADR-0006), and
arch-translucency verifies certificates the same way, so the edge can now be checked.

- **R-G1** `--gate-certificate PATH` (repeatable) with `--gate-trust PATH` on `dp-train`,
  `dp-charge` and `consortium-round`. Each certificate is verified with ikigov-assess's
  `verify_certificate` (schema, issuer signature against the trust store, predicate,
  expiry, embedded evidence-refs, recomputed decision); the decision must be `OPEN`.
- **R-G2** The certificate's identity (`presidio_evidence.gate_certificate_identity`:
  sha256 over the canonical document minus `signature`) is appended to the run's
  `parents` after the bare `--parent` values, once. `framework_content_hash` is never a
  parent.
- **R-G3** Fail closed before any side effect: any refusal, `--gate-certificate` without
  `--gate-trust` or the reverse, an unreadable, non-UTF-8, non-JSON or over-1-MiB file, or
  the `[gate]` extra missing exits 1 with no ledger entry and no evidence written. Refusals
  and acceptances are logged as security events (counts only).
- **R-G4** The verifier is the optional `[gate]` extra
  (`presidio-hardened-ikigov-assess[crypto]>=0.28.0,<1`), imported only when the option is
  used. The identity is pinned to presidio-evidence's
  `vectors/gate-certificate/valid-certificate.json`.
- **Not in scope:** emitting a `training-run@1` payload.

**Dependency and platform.**

- **R-E1** presidio-evidence (`>=0.5.1,<0.6`) supplies canonical JSON, the evidence signing
  message, HMAC/Ed25519 signing and verification, key generation and the envelope
  (presidio-evidence MIGRATION step 2); no signed byte changes.
- **R-E2** The pre-0.31 encoder is removed (#74); untagged ledger entries and approvals
  over untagged requests fail closed.
- **R-E3** Python 3.11+.

