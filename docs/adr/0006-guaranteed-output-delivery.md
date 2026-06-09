# ADR-0006: Guaranteed output delivery for the consortium round

**Status:** Accepted
**Date:** 2026-06-09
**Deciders:** Vladimir Stantchev (architecture); FS design-partner risk/security leads
**Scope:** `presidio-hardened-ai` P4 — deliver the correct aggregate even when a minority of
parties (or the coordinator) actively misbehave
**Amends:** [ADR-0002](0002-malicious-security-hardening.md) — upgrades its *security-with-
abort* to *guaranteed output delivery* (GOD); builds on the [ADR-0001](0001-multiparty-secure-aggregation.md)
sum aggregation and the ADR-0002 Feldman VSS.

> **Implementation status (v0.25.0–v0.27.0).** Accepted; built (Option A + interim D). v0.25.0
> ships exclude-and-retry liveness (`run_consortium_round_with_retry`); v0.26.0 the robust
> reconstruction (`commit.robust_reconstruct`); v0.27.0 the shared-input GOD aggregation
> (`fl.god`) + `run_god_consortium_round` (items 1–3, 5–7). **Remaining (item 4):** binding
> the bounded-norm ZK gate to the *shared* inputs is **done v0.28.0** via a commitment-
> equality proof. All pure-Python and verified in the default gate.

## Context

ADR-0002 gives **security-with-abort**: a deviating coordinator or party is detected and the
round aborts, attributably. That protects confidentiality and integrity but **not
availability** — a single malicious member (submitting garbage that fails a check) or a
malicious coordinator (refusing to produce the result) can force *every* round to abort,
starving the consortium of a model. For a production consortium of institutions training
together under an SLA, **liveness matters**: one compromised or obstructive member must not
be able to halt training for everyone. **Guaranteed output delivery (GOD)** means the
protocol *delivers the correct aggregate* as long as enough honest parties participate,
regardless of what the malicious minority does — abort, garbage, silence, or a hostile
coordinator.

The decisive, non-negotiable fact: **GOD is only achievable under an honest majority**
(`n > 2t` for `t` corruptions) — a dishonest majority can always withhold or corrupt the
output, so no protocol delivers GOD against it. Adopting GOD therefore means adopting an
**honest-majority trust assumption**, a real change from ADR-0001/0002's "honest-but-curious
coordinator + collusion bound `t`" (which made no majority assumption).

Forces at play:

- **The computation is still a sum.** As throughout P4, FedAvg is a *linear* function; this
  rules out general maliciously-secure MPC and means GOD is reachable with the lightest
  machinery (no multiplication gates).
- **Reuse the VSS.** ADR-0002 already ships Feldman VSS; GOD for a sum follows naturally from
  *sharing the inputs* and **robustly reconstructing** their sum — VSS lets honest parties
  *detect* bad shares, turning error-correction into error-*detection* (so `n ≥ 2t+1`, honest
  majority, suffices rather than `n ≥ 3t+1`).
- **Remove the coordinator as a single point of failure.** Security-with-abort tolerates a
  present-but-curious coordinator; GOD against a *malicious* coordinator requires that **any
  honest quorum can produce the output without it** — a shift from the star topology to a
  protocol where a quorum reconstructs.
- **Compose with the rest.** Per-client DP, the bounded-norm ZK gate (L∞/L2), the ledger +
  signed `D4` evidence, and MPA must continue to apply; GOD changes only *how the sum is
  computed and delivered*, not what is proven about inputs or recorded as evidence.

## Decision

Adopt **honest-majority robust secret-sharing aggregation** for the sum: each party
**Feldman-VSS-shares its (DP-noised, bounded-norm-proven) update** to all parties; shares are
**added locally** (the sum of shares is a sharing of the sum — no multiplication needed); and
the aggregate is recovered by **robust reconstruction** — verify each share against its VSS
commitments, **discard** the (≤ `t`) invalid ones, and Lagrange-interpolate from the `≥ t+1`
valid shares. This **delivers the correct sum** whenever `n ≥ 2t+1`, tolerating malicious
parties (bad-or-silent shares) and removing the coordinator (any honest quorum reconstructs).

This is right-sized for a sum and reuses ADR-0002's VSS and ADR-0003/0005's input proofs
unchanged; it replaces the *masking + dropout-recovery + homomorphic-check* aggregation with
*shared-inputs + robust reconstruction* when GOD is required. As a **pragmatic interim**,
keep the ADR-0002 security-with-abort round plus **cheater-identification + exclude-and-retry**
(below) for deployments that cannot yet assume honest majority. General GOD-MPC and
verifiable threshold HE are evaluated and **deferred**.

## Options Considered

### Option A: Robust secret-sharing aggregation (VSS-shared inputs + robust reconstruction)
Share inputs via Feldman VSS; add shares; reconstruct the sum by discarding VSS-invalid shares.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med–High — robust reconstruction + decentralised quorum agreement |
| Cost | `O(n·d)` shares + VSS commitments per round (heavier than masking's `O(d)`) |
| Scalability | Good for 3–20 institutional parties; comms grows with `n` |
| Team familiarity | Med — reuses Feldman VSS + Shamir reconstruct already in the suite |

**Pros:** **true GOD** for the sum under honest majority; reuses VSS; the linearity of the sum
means no multiplication gates; **no coordinator single-point-of-failure** (any honest quorum
reconstructs); composes with DP, bounded-norm ZK, evidence, MPA unchanged. **Cons:** requires
the **honest-majority** assumption (`n ≥ 2t+1`); heavier comms (`O(n·d)`); needs a decentralised
agreement on the valid-share set (can anchor on the signed survivor-set + ledger).

### Option B: General maliciously-secure GOD-MPC (honest-majority framework, e.g. BGW/MP-SPDZ)
Run the sum inside a general GOD-MPC engine.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — external MPC toolchain, circuits, networking |
| Cost | High — far beyond a sum |
| Scalability | Poor for model-sized vectors |
| Team familiarity | Low |

**Pros:** GOD for *any* function; mature frameworks. **Cons:** massive over-engineering for a
linear function (Option A *is* the sum-specialised case of this); heavy unverifiable
dependency — the same objection as ADR-0001 Option B. Rejected.

### Option C: Threshold HE with robust threshold decryption
Encrypt inputs under a threshold key; sum ciphertexts; an honest quorum robustly threshold-decrypts.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — threshold keygen + verifiable partial decryptions |
| Cost | High — HE ciphertext + threshold ops |
| Scalability | Moderate |
| Team familiarity | Low |

**Pros:** GOD with quorum decryption; no per-pair sharing. **Cons:** a heavy HE + threshold
stack to vet; more than a sum needs. A credible path **if** the suite moves to the HE world
for other reasons (the recurring ADR-0001 Option C). Deferred.

### Option D: Security-with-abort + cheater-identification + exclude-and-retry (interim)
Keep ADR-0002; on a detected/attributed cheat, exclude the culprit and re-run among the rest.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low — reuses ADR-0002 attribution + a retry loop |
| Cost | Low per attempt; up to `t+1` attempts worst case |
| Scalability | Good |
| Team familiarity | High |

**Pros:** **GOD-in-practice** under a bounded cheater count, **today**, with no new crypto and
no honest-majority assumption on confidentiality (only on termination); reuses the existing
malicious-secure round and its ledger attribution. **Cons:** **not cryptographic GOD** — it is
liveness via retries, so it costs extra rounds and assumes cheaters are eventually excluded;
a coordinator that lies about *who* cheated still needs the ADR-0002 signed-survivor-set
consistency to bound it. A pragmatic stepping stone, not the end state.

## Trade-off Analysis

GOD's hard precondition is honest majority — that is a *governance* decision (do the consortium
members accept that a majority is honest?), not just an engineering one, and the ADR surfaces
it rather than burying it. Given honest majority, **Option A is the right-sized cryptographic
GOD**: because the target is a *sum*, sharing inputs and adding shares needs no multiplication,
and Feldman VSS (already in the suite) converts the hard robust-*correction* problem into
cheap robust-*detection* — verify each share against its public commitments, drop the bad
ones, interpolate from the honest `t+1`. It also dissolves the coordinator: a quorum
reconstructs, so a hostile coordinator cannot halt the round. The cost is comms (`O(n·d)`
sharing) and a decentralised agreement on the valid set, which the existing signed
survivor-set + ledger can anchor.

B is the generic hammer for a problem that is one nail (a sum); A is literally B specialised
to linear functions, without the framework. C moves to the HE world — more than the sum needs.
D is the honest pragmatic answer for *right now*: it gives liveness under bounded cheating
with zero new crypto, but it is retry-based, not a cryptographic guarantee. The recommendation
is therefore **A as the target GOD architecture (honest majority), with D shipped first as the
interim** so deployments get robust liveness immediately while the share-based aggregation
lands.

## Consequences

**Easier:**
- The consortium **delivers a model even under active sabotage by a minority** — the liveness
  property institutional SLAs need; no single coordinator can halt training.
- Reuses Feldman VSS and Shamir reconstruction; the sum's linearity keeps the protocol light
  (no multiplication gates); DP, bounded-norm ZK, evidence, and MPA compose unchanged.

**Harder:**
- An **honest-majority assumption (`n ≥ 2t+1`)** — stricter than ADR-0001/0002's collusion
  bound; it must be stated in `SECURITY.md` and accepted by the consortium as a trust premise.
- **Robust reconstruction** (verify-against-VSS-commitments → discard invalid → interpolate
  from `t+1`) to implement and test, plus a **decentralised agreement** on the valid-share set
  (anchored on the signed survivor-set + ledger).
- **Heavier communication** (`O(n·d)` input sharing vs masking's `O(d)`), and a second
  aggregation path to maintain alongside the masking round.

**Revisit when:**
- The deployment **cannot** assume honest majority → GOD is impossible; fall back to ADR-0002
  security-with-abort (+ Option D retry) and document the liveness limitation.
- Aggregating **non-linear** statistics is needed → general GOD-MPC (Option B).
- The suite adopts threshold HE for other reasons → Option C becomes attractive.

## Action Items
1. [x] Threat-model delta: state the **honest-majority (`n ≥ 2t+1`)** premise, what GOD adds
       (liveness under active minority sabotage; no coordinator SPOF) and what it does not
       (nothing against a dishonest majority); record it in `SECURITY.md`.
2. [x] Ship **Option D first**: cheater-identification + exclude-and-retry on top of the
       ADR-0002 round (reuse ledger attribution + signed survivor-set), with a bounded retry
       count; tests for "one cheater → round still completes among the honest set".
3. [x] Implement **robust reconstruction** (verify shares against Feldman commitments, discard
       invalid, Lagrange-interpolate from `t+1`); pure-Python core + tests (≤`t` bad/silent
       shares → correct sum; `> t` → safe abort).
4. [x] Build the **shared-input aggregation** path: parties VSS-share DP-noised, bounded-norm-
       proven updates; shares added locally; sum robustly reconstructed by any honest quorum
       (no coordinator) **— done v0.27.0**. Bounded-norm ZK on the shared inputs via a
       commitment-equality proof **— done v0.28.0**.
5. [x] Decentralised **agreement on the valid-share set** anchored on the signed survivor-set +
       ledger; one signed `D4` per round (aggregate only), recording the GOD mode + honest-
       majority parameters.
6. [x] `run_consortium_round` mode selection: security-with-abort (ADR-0002, default) vs GOD
       (Option A) vs interim retry (Option D); document the trust/cost trade-off per mode.
7. [x] Cross-check the GOD aggregate equals the masking-round aggregate (and plaintext FedAvg)
       within tolerance; benchmark the `O(n·d)` sharing cost for 3–20 parties.
8. [ ] Defer to follow-up ADRs: general GOD-MPC (Option B) for non-linear aggregates and
       verifiable threshold HE (Option C).
