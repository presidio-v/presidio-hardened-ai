# Architecture

This document describes the high-level design of `presidio-hardened-ai`: its
components, how data flows through them, and the trust boundaries the project is
built to enforce. For the security requirements and threat model that motivate
this design, see [SECURITY.md](SECURITY.md) and the assurance case in
[ASSURANCE.md](ASSURANCE.md). Design decisions are recorded in
[docs/adr/](docs/adr/) (index in [docs/adr/README.md](docs/adr/README.md)). How this
repository fits into the presidio-hardened-* family is described in the suite
architecture, [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Overview

`presidio-hardened-ai` is a training-time privacy library with a CLI (`pai`). It covers
four layers, built in phases P1 to P4:

- **P1, evidence layer.** PII scrubbing on ingest, a tamper-evident HMAC-chained lineage
  ledger, and signed `EvidenceRef` export for the governance items D1, D4 and O5.
- **P2, differential privacy.** A Rényi-DP accountant for DP-SGD, an ε budget whose spend
  is re-derived from the verified ledger, n-of-m authorization for high-ε jobs, and DP-SGD
  trainers (a dependency-free reference and an Opacus adapter).
- **P3, federated learning.** Local DP-SGD per silo, FedAvg, per-silo budgets and evidence.
- **P4, consortium rounds.** Secure aggregation between mutually distrusting parties, with
  verifiable secret sharing, signed survivor sets, homomorphic commitments, zero-knowledge
  norm proofs, guaranteed output delivery under an honest majority, and an aggregate
  validation gate.

The design stance is **commitments only, fail closed**: the ledger, the evidence and the
security log hold hashes, counts and privacy parameters, never record values or an
individual party's update, and every verification path raises or refuses rather than
returning a pass by default. Canonical JSON and evidence signing come from
`presidio-evidence`, so this repository and its verifiers share one implementation of the
wire format. The library makes no network calls except through the optional `[mpc]`
transport server.

## Components

Listed from the primitives outward.

| Component | Responsibility |
|---|---|
| `hashing.py` | Strict canonical JSON (delegated to `presidio_evidence.canonical_bytes`, floats rejected), SHA-256 content hashes, HMAC-SHA256, constant-time comparison. |
| `numeric.py` | Decimal-string encoding of non-integer values at per-field precisions (`PRECISION`), half-even rounding, NaN/Infinity rejected, non-zero `delta`/`sample_rate` that would round to `"0"` refused. |
| `ledger.py` | Append-only JSON-L ledger. Each entry's `entry_hash` is an HMAC over `(canon, seq, timestamp, event, payload, prev_hash)`; `verify_chain` checks every link, the `canon` tag and an optional anchor. File `0600`, directory `0700`. |
| `sanitize.py` | Validation of identifiers, silo ids (one filename component), paths, PII modes and actions. |
| `pii.py` | PII detection and redaction: curated regexes by default, Presidio + spaCy with the `[nlp]` extra. Actions `redact`, `block`, `warn`. |
| `ingest.py` | Scrubs records and writes one lineage entry: source and output hashes with their scopes, record counts, per-entity redaction counts. |
| `provenance.py` | Validation and normalisation of `parents` (upstream content hashes inside the hashed content). |
| `evidence.py` | `EvidenceRef` construction, HMAC and Ed25519 signing via presidio-evidence's signing message, the hashed content for ingest, DP and consortium evidence, and the export envelope. |
| `gate_certificate.py` | Reads an ikigov-assess `gate-certificate@1` and its trust store (bounded, regular UTF-8 files), verifies it with ikigov's `verify_certificate`, requires decision `OPEN`, returns its identity as a parent. Needs the `[gate]` extra. |
| `security.py` | Structural security log (`~/.presidio-ai/security.log`) and the per-session operation limit (`PRESIDIO_AI_MAX_OPS`). |
| `dp/accountant.py` | RDP of the subsampled Gaussian mechanism (integer and fractional orders), composition over steps, conversion to (ε, δ). Pure stdlib. |
| `dp/budget.py` | `EpsilonBudget`: spend re-derived from the verified chain, anchored to the live `Ledger` and optionally an external anchor; basic composition across jobs. |
| `dp/authorization.py` | n-of-m approval: HMAC countersignatures over the hash of a canonical request bound to job id and privacy parameters. |
| `dp/trainer.py` | Reference DP-SGD (per-example clipping, Gaussian noise; the library defaults to a seeded PRNG, CSPRNG with `secure_rng=True`, which the `pai` CLI uses unless `--seed` is given) and the Opacus adapter (`[torch]`). |
| `fl/coordinator.py`, `fl/aggregation.py`, `fl/governance.py` | Federated training across silos, FedAvg, per-silo budget charges and evidence. `SecureSumAggregator` is an in-process demonstration with a seeded PRNG. |
| `fl/secure_agg.py` | Pairwise and self masks in GF(2⁶¹−1), Shamir t-of-n recovery of dropped parties' seeds; seeds from a CSPRNG by default. |
| `fl/keyagreement.py` | X25519 + HKDF-SHA256 pairwise seeds, each DH key Ed25519-signed under the party's identity key and checked against a local trust store (`[mpc]`). |
| `fl/transport.py` | Signed wire format for masked submissions and commands, and `RoundCoordinator` (one submission per party, one aggregate). `serve()` exposes it over HTTP with Starlette/uvicorn (`[mpc]`). |
| `fl/commit.py` | Pedersen commitments and Feldman VSS over the RFC 3526 MODP-2048 prime-order subgroup; robust reconstruction. |
| `fl/zk.py` | Transparent ZK proofs over that group: bit OR-proofs, range proofs, two-sided L∞ bounds, L2 bounds with square proofs. |
| `fl/proof_backend.py`, `fl/_ristretto_backend.py`, `rust/` | Pluggable proof backend. The native Ristretto255 + Bulletproofs backend (`[zk]`, built with maturin over the dalek crates) is used when installed, otherwise the pure-Python MODP backend. Backends are never mixed within a round. |
| `fl/consortium.py` | Round composition: MPA authorization, secure aggregation, signed survivor sets, VSS and commitment checks, the norm gate, per-silo DP charges, one signed D4 per round; retry with cheater exclusion. |
| `fl/god.py` | Guaranteed output delivery: Feldman-shared inputs, local share addition, robust reconstruction; no coordinator. |
| `fl/robustness.py` | Aggregate validation gate: a consortium-supplied validation and canary callback; a failing round is rolled back and flagged. |
| `cli.py` | The `pai` CLI over all of the above; confirmations on stderr, JSON on stdout with `--quiet`. |

## Data / processing flow

**Ingest** (`pai ingest`): read the JSONL source (bounded path, validated identifiers) →
hash the raw bytes (`source_commitment`) → scrub each record with `PIIScrubber` (`block`
stops on a detection) → hash the scrubbed records (`content_hash`) → append one
`ingest` entry with hashes, scopes and counts → optionally build D1/D4 refs over the
ingest record and an O5 ref over the ledger head, sign them (Ed25519 by default) and
write the envelope.

**DP charge** (`pai dp-charge`, `pai dp-train`): validate parameters → optionally verify
gate certificates and add their identities to `parents` → account (ε, δ) with
`dpsgd_epsilon` → `EpsilonBudget.charge`: verify the chain against the live anchor, sum
recorded spend, refuse if over budget, require n-of-m approvals when ε meets the policy
threshold and record an `mpa-authorized` entry, then append the `dp-budget-charge` entry
with decimal-string parameters → optionally emit a signed D4 over `dp-result@1`.
Refusals happen before any write.

**Consortium round.** The malicious-secure round (`run_secure_consortium_round`) runs, in
order: (0) n-of-m authorization on the worst-case per-party ε, before anything is
computed, so a denied round reveals nothing; (1) the coordinator presents ≥ t Ed25519 party signatures over the survivor set
and round attempt, recorded to the ledger, before any recovery share is revealed; (2)
each survivor's DP-noised, quantised input is Pedersen-committed; (2b) with `clip_bound`
or `l2_bound`, each input's L∞ or L2 norm proof is verified against the same commitment;
(3) masked inputs are aggregated in the verifiable session (Feldman-checked
reconstruction); (4) the aggregate is checked against the product of the commitments;
then the optional robustness gate; and only then (5) per-silo charges to each silo's own
ledger, the round entry, and
one signed D4 over `consortium-round@1` (aggregate hash, worst-case (ε, δ), counts and,
when a gate ran, the proven norm). The GOD path
(`run_god_consortium_round`) replaces masking with Feldman-shared inputs and robust
reconstruction, with no coordinator; it too authorizes before any input is dealt.

The failure posture is fail closed throughout: a broken chain, a bad share, an invalid
proof, too few survivors, a false aggregate or a refused certificate raises or exits
non-zero, and nothing is charged or emitted for that operation.

## Trust boundaries

| Boundary | Kind | Control |
|---|---|---|
| **Data source → ingest** | Input validation | Paths and identifiers bounded, NUL and control characters rejected; JSONL parsed per line; PII scrubbed before anything is hashed for output; only hashes and counts leave the boundary. |
| **Operator → ledger file and key** | Integrity, secret handling | HMAC chain verified on every budget read and by `pai verify`; key from `--key` or `PRESIDIO_AI_LEDGER_KEY`, never written to the ledger or the log. The key holder is trusted; suffix truncation is detected only against an anchor. |
| **Library → ledger, evidence, security log** (persistence egress) | Egress | Commitments only; decimal strings; the log records event names, counts and flags, never paths, content or `ledger_ref` values. |
| **Producer → evidence → verifier** | Integrity | Ed25519 (default) or HMAC signatures over presidio-evidence's signing message; verifiers hold only public keys for Ed25519. |
| **Gate issuer → `--gate-certificate`** | Input validation | Bounded regular UTF-8 JSON (≤ 1 MiB, non-finite numbers rejected), verified by ikigov-assess against the operator's trust store, decision `OPEN`, before the ledger is opened for writing. |
| **Approvers → n-of-m authorization** | Input validation | HMAC countersignatures over the request hash, checked against the local approver key store; distinct recognised approvers only. |
| **Party ↔ party ↔ coordinator** (consortium round) | Input validation, confidentiality | Ed25519-signed DH keys and wire messages, canonical field elements only, one submission per party; signed survivor sets; Feldman VSS; Pedersen checks of the aggregate; ZK norm proofs. Threat model per [SECURITY.md](SECURITY.md): malicious coordinator or minority with abort, GOD under an honest majority. |
| **Transport server → network** | Egress / exposure | `serve()` serves HTTPS when given `ssl_certfile` and `ssl_keyfile` (Python's TLS defaults, TLS 1.2 minimum) and refuses to bind a non-loopback address without them; it binds `127.0.0.1` by default. Request size limits and rate limiting are deployment configuration. |
| **Python → native `[zk]` backend** | Integrity of proofs | Decision equivalence with the MODP backend checked in the `ci-zk` lane; inputs length-checked at the boundary. |
