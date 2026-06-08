# ADR-0001: Multi-party consortium training via secure aggregation

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** Vladimir Stantchev (architecture); FS design-partner risk/security leads
**Scope:** `presidio-hardened-ai` P4 — the deferred "consortium" prize

> **Implementation status (v0.11.0–v0.15.0).** Accepted and built out. The pure-Python secure-aggregation **core** — antisymmetric pairwise masks, self-masks, and Shamir t-of-n dropout recovery — ships in `presidio_ai.fl.secure_agg`, verified to reproduce plaintext FedAvg with and without dropout (action items 3 & 6). Still deferred to the `[mpc]` lane: authenticated pairwise key agreement (seeds modelled in-process today), the network transport, field-quantised exact arithmetic, and DP/MPA/evidence composition per round (items 2, 4, 5).

## Context

P4 is the platform prize named in the original plan: several **mutually-distrusting**
parties (e.g. banks jointly training an AML/fraud model) train together **without any
party — including the coordinator — seeing another party's raw data or its individual
model update**. v0.5.0 federated learning already keeps raw data in each silo and shares
only DP-noised updates, and ships a single-process `SecureSumAggregator` reference. P4 is
the step from "single process, honest coordinator" to a **distributed protocol with a
defined adversary**.

Forces at play:

- **Threat model.** The new adversary is the *coordinator* (and colluding subsets of
  parties). FedAvg's coordinator currently sees each silo's update in the clear — for a
  consortium that is unacceptable (an update can leak training data via inversion).
- **The computation is a sum.** FedAvg aggregation is a sample-weighted **sum** of
  updates, not an arbitrary function. This is the single most important constraint: it
  rules *out* the need for general-purpose MPC.
- **Composition with what exists.** Whatever we choose must compose with per-client DP
  (v0.5.0/v0.9.0), the tamper-evident ledger + signed `EvidenceRef`, n-of-m MPA (v0.3.0),
  and the Ed25519 trust model — not replace them.
- **Verifiability.** "Architecture is the defense": prefer a mechanism whose guarantee is
  cryptographic and whose core is testable in CI over one that shifts trust to hardware or
  ships unverifiable heavy crypto.
- **Real-world bar.** Parties drop out mid-round; the protocol must tolerate it. Latency
  and ops cost must stay sane for a handful (3–20) of institutional parties.

## Decision

Adopt **secure aggregation by additive masking** (Bonawitz et al., 2017) as the P4 v1
mechanism: clients mask their (DP-noised, weighted) updates with pairwise-cancelling
masks so the coordinator recovers **only the aggregate**, never an individual update.
Pair it with the existing **per-client DP** (so the aggregate itself is differentially
private — "distributed DP via secure aggregation") and bind each round to the **ledger +
signed evidence** (the aggregate's commitment is recorded; no individual update is ever
materialised). Authorize a consortium round with **n-of-m MPA**.

General MPC, homomorphic encryption, and TEEs are explicitly **deferred** as options for
stronger or different threat models (below), not v1.

## Options Considered

### Option A: Secure aggregation by additive masking (Bonawitz 2017)
Pairwise PRG masks (via authenticated key agreement between parties) that cancel in the
sum; threshold secret-sharing of mask seeds for dropout recovery; coordinator sees only Σ.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med — key agreement + dropout recovery; the masking core is what `SecureSumAggregator` already prototypes |
| Cost | Low — symmetric crypto + PRG; ~constant overhead per round, scales to many parties |
| Scalability | Good for 3–20 institutional parties (the consortium reality) |
| Team familiarity | High — extends existing FL/aggregator code; pure-Python core testable in CI |

**Pros:** right-sized for a *sum*; composes natively with FedAvg + per-client DP + ledger;
verifiable core; the v0.5.0 reference is a stepping stone. **Cons:** protects a sum only
(fine here); needs careful dropout handling; honest-but-curious coordinator + a collusion
bound `t` on parties (not malicious-secure without extra commitments).

### Option B: General MPC (secret-sharing / SPDZ)
Secret-share inputs; compute arbitrary functions on shares via an MPC framework (MP-SPDZ).

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — external MPC toolchain, circuit compilation, networking |
| Cost | Very high — 100–1000× overhead; heavy comms |
| Scalability | Poor for model-sized vectors |
| Team familiarity | Low — new dependency + paradigm |

**Pros:** computes *any* function; malicious-secure variants exist. **Cons:** massive
over-engineering for a sum; heavy unverifiable dependency; contradicts the "minimal
composition that closes the threat" principle.

### Option C: Homomorphic encryption (threshold) aggregation
Clients encrypt updates under a threshold key; coordinator sums ciphertexts; parties
threshold-decrypt the aggregate.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — threshold key management, ciphertext packing |
| Cost | High — large ciphertexts, slow ops |
| Scalability | Moderate; packing helps but still heavy |
| Team familiarity | Low |

**Pros:** strong confidentiality; no pairwise masks; natural dropout tolerance.
**Cons:** key-management and performance burden; heavier than the sum needs; a new
crypto dependency to vet. A credible **v2** if the threat model hardens.

### Option D: TEE / confidential-computing aggregation
Coordinator aggregates inside an enclave; clients send to the attested enclave.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med (ops-heavy: attestation, enclave deployment) |
| Cost | Med |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** simple data flow; fast. **Cons:** shifts trust to a **hardware vendor** and the
attestation chain — not a cryptographic guarantee; side-channel history; weakest fit for
"architecture is the defense." Useful as a deployment *option*, not the primary guarantee.

## Trade-off Analysis

The decisive factor is that the consortium computation is a **sum**. Secure aggregation
(A) provides exactly the needed guarantee — the coordinator learns only Σ — at symmetric-
crypto cost, and **layers with DP** so the revealed aggregate is itself private (defending
the residual: a sum can still leak if one party's contribution dominates; DP bounds that).
B and C buy generality the problem does not need, at large cost and new unverifiable
dependencies. D moves the trust root off the math and onto hardware. A also reuses the
most code (the `SecureSumAggregator` reference is the in-process model of the same masks)
and keeps the verifiable-core property: the masking/dropout logic is pure-Python and
CI-testable; only the network key-agreement layer is integration-tested.

Crucially, A is not weaker on the *data*: with masking the coordinator never sees an
individual update, and with per-client DP the aggregate carries a bounded ε — the same
two-line defense-in-depth (mask kills the obvious, DP bounds the residual) used elsewhere
in the suite.

## Consequences

**Easier:**
- The v0.5.0 `SecureSumAggregator` becomes the local model of the production protocol;
  the coordinator API (`Aggregator`) is unchanged.
- Per-client DP, ledger, signed evidence, and MPA all compose without modification — a
  consortium round emits the same signed `D4` evidence, now over a *jointly-trained*
  model.
- The guarantee is cryptographic and largely testable in CI.

**Harder:**
- A real **pairwise key-agreement + dropout-recovery** protocol (Bonawitz) must be built
  and network-integration-tested behind an extra (mirroring the `[torch]` lane): the
  pure-Python masking/secret-sharing core is unit-tested; the transport is not in the
  default lane.
- The threat model must be **stated and bounded**: honest-but-curious coordinator, a
  collusion threshold `t` of parties, malicious-security explicitly out of v1.
- Mask PRG must be a **CSPRNG** (the v0.4.0 `secure_rng` note applies); the reference's
  seedable masks are for tests only.

**Revisit when:**
- The threat model adds a **malicious** coordinator or parties → add commitments /
  verifiable secret sharing, or move to Option C (threshold HE).
- Party count grows beyond ~20, or WAN latency dominates → reconsider topology / HE
  packing.

> **Beyond the original items:** v0.12.0 also moved masking into exact field-quantised
> arithmetic (no float-cancellation error), and v0.15.0 tightened the per-party DP bound
> with a fractional-order RDP accountant. Remaining: malicious-security hardening
> (commitments / VSS) — the ADR's stated revisit trigger.

## Action Items
1. [x] Write the threat-model section (adversary = HbC coordinator + ≤`t` colluding
       parties; malicious-secure out of scope) — PRESIDIO-REQ v0.14.0 entry + SECURITY.md.
2. [x] Define the protocol: authenticated pairwise key agreement → per-pair PRG masks →
       Shamir secret-sharing of seeds for dropout recovery (Bonawitz §4).
       **Done v0.14.0** — `fl.keyagreement` (X25519 + HKDF + Ed25519-authenticated).
3. [x] Implement the **pure-Python core** (mask generation, share/reconstruct, dropout
       recovery) with CSPRNG; unit-test mask cancellation and t-of-n recovery.
       **Done in v0.11.0** — `presidio_ai.fl.secure_agg` (`SecureAggregationSession`,
       `shamir_split`/`shamir_reconstruct`); 11 tests.
4. [x] Wire the network/transport layer behind a `[mpc]` extra; integration-test in a
       dedicated CI lane (as the Opacus `[torch]` lane). **Done v0.14.0** — `fl.transport`
       + `ci-mpc` lane.
5. [x] Compose: per-client DP on inputs; n-of-m MPA to authorize a consortium round;
       one signed `D4` evidence + ledger entry per round (aggregate only).
       **Done v0.13.0** — `fl.consortium.run_consortium_round` / `pai consortium-round`.
6. [x] Cross-check the protocol's aggregate equals plaintext FedAvg (and the v0.5.0
       reference) within float tolerance. **Done in v0.11.0** (no-dropout aggregate
       == plain sum; dropout aggregate == survivor sum).
