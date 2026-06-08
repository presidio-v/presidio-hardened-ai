# ADR-0003: Bounded-norm input validation via zero-knowledge proofs

**Status:** Proposed
**Date:** 2026-06-08
**Deciders:** Vladimir Stantchev (architecture); FS design-partner risk/security leads
**Scope:** `presidio-hardened-ai` P4 — proving each consortium contribution is *well-formed*
(within a norm bound) without revealing it
**Amends:** [ADR-0002](0002-malicious-security-hardening.md) — adds *input honesty* to the
*protocol honesty* ADR-0002 secured; both build on the [ADR-0001](0001-multiparty-secure-aggregation.md)
secure-aggregation core.

## Context

ADR-0001 hid individual updates; ADR-0002 stopped a *deviating* coordinator or party from
breaking the protocol (equivocation, false aggregate, inconsistent shares). A gap remains,
and it is the one ADR-0002 explicitly deferred: a party can submit a **well-formed but
adversarial update** — a vector that follows the protocol exactly but whose magnitude is
enormous. Because secure aggregation means **no one ever sees an individual update**, the
coordinator cannot clip or inspect it; a single party can therefore **dominate or poison**
the aggregate (a boosting / model-replacement attack) entirely within the rules.

The decisive observation ties this back to the suite's core. Per-client DP (v0.5.0/v0.9.0)
and the whole `(ε, δ)` accounting **assume** each client clips its update to a fixed L2
sensitivity before adding noise. Today that assumption is *unverified*: a malicious client
that does not clip silently breaks the DP guarantee the accountant reports and the ledger
attests. **Bounded-norm input validation closes exactly that gap** — it lets a client
*prove* its contribution respects the clip bound, turning the sensitivity from an assumption
into an enforced, cryptographically-checked fact. That is the feature: it makes the per-
client DP guarantee sound against a *malicious* client, not merely an honest one.

Forces at play:

- **Confidentiality must hold.** The check cannot reveal the update — the bound must be
  proven in **zero knowledge** over the same commitments ADR-0002 already publishes.
- **No trusted setup.** The suite's ethos (NUMS generators, "architecture is the defense")
  rules out a proving system that needs a trusted/structured-reference-string ceremony if
  an equally-good transparent option exists.
- **Compose, don't replace.** The proof should attach to the **existing Pedersen
  commitments** and the prime-order group, and gate admission inside the v0.18.0 secure
  round; per-client DP, MPA, the ledger, and signed evidence stay as they are.
- **The bound is the clip norm.** The norm being proven should be the **DP clip bound**, so
  the proof enforces the exact sensitivity the accountant assumes — not an arbitrary number.
- **Cost is the real constraint.** A proof per party per round at model dimension `d` is the
  expensive part; proof size, prover time, and (batched) verifier time decide feasibility.

## Decision

Adopt **Bulletproofs range proofs** (Bünz et al., 2018) over the existing Pedersen
commitments to enforce an **L∞ per-coordinate bound** (`|x_k| ≤ B` for every coordinate) as
**v1**, with the bound `B` fixed to the DP **clip sensitivity**. Each party submits, with
its committed update, a (single, aggregated) range proof that every committed coordinate
lies in `[-B, B]`; the coordinator/peers verify it before the contribution is admitted, and
a failing proof excludes the party (or aborts the round). Bulletproofs are **transparent**
(no trusted setup), `O(log d)` in size, and **aggregatable** so one short proof covers the
whole vector.

An **L2 norm bound** (`‖x‖₂ ≤ B`, matching the DP clip norm exactly) is the planned **v2**,
built on the same machinery plus an inner-product argument (ACORN / RoFL). General-purpose
zk-SNARKs and non-ZK statistical checks are evaluated and **deferred / rejected** below.

## Options Considered

### Option A: Bulletproofs range proofs, L∞ bound (transparent)
Prove each Pedersen-committed coordinate is in `[-B, B]`; aggregate into one short proof.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — inner-product argument, Fiat-Shamir transcript, vector commitments |
| Cost | Prover `O(d)`, proof `O(log d)`, verifier `O(d)` (batchable across parties) |
| Scalability | Good with batching/aggregation; the per-coordinate constant is the watch-item |
| Team familiarity | Med — extends the ADR-0002 Pedersen/group code; verifiable core testable |

**Pros:** **no trusted setup**; reuses the existing commitments and prime-order group;
short, aggregatable proofs; L∞ already caps any single coordinate's influence (real anti-
poisoning). **Cons:** L∞ is weaker than the L2 norm DP actually clips to (a v2 gap);
Bulletproofs are non-trivial to implement correctly; pure-Python proving is slow → likely a
curve group + possibly a vetted dependency.

### Option B: Bulletproofs + inner-product, L2 bound (matches the clip norm)
Prove `Σ x_k² ≤ B²` — commit to the squares and range-prove the squared-norm.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Very High — squared-norm gadget on top of A |
| Cost | Higher prover/verifier than A; still transparent and `O(log d)` proof |
| Scalability | Moderate; the squared-norm argument adds constant overhead |
| Team familiarity | Low — new gadget |

**Pros:** enforces the **exact** L2 sensitivity the DP accountant uses — the tightest tie
to the guarantee; transparent. **Cons:** materially more complex than A; best built *after*
A's machinery exists. The natural **v2**.

### Option C: zk-SNARKs (Groth16 / PLONK) for arbitrary validity
Compile "norm ≤ B (and any other well-formedness)" to a circuit; succinct proof.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Very High — circuit/R1CS toolchain, prover infra |
| Cost | Tiny constant-size proof, fast verify; **heavy prover**, big dependency |
| Scalability | Excellent verification; poor build/ops simplicity |
| Team familiarity | Low |

**Pros:** constant-size proofs, very fast verification, can prove arbitrary statements.
**Cons:** **trusted setup** (Groth16) or a universal-SRS ceremony (PLONK) — contradicts the
no-setup ethos; a heavyweight proving toolchain to vet. Deferred; revisit only if proof size
/ verify time become the bottleneck at scale.

### Option D: Non-ZK norm checks (second aggregation / MPC clipping)
Securely aggregate per-party squared norms, or clip inside an MPC, without per-party proofs.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med |
| Cost | Low–Med |
| Scalability | Good |
| Team familiarity | Med — reuses secure aggregation |

**Pros:** cheap; no proof system. **Cons:** does not *prove* a per-party bound — a party can
misreport its norm unless the reported value is cryptographically bound to the *same* input
(which is essentially the ZK problem again); MPC clipping is heavy and changes the trust
model. Weaker guarantee; noted as a fallback, not the primary mechanism.

## Trade-off Analysis

The requirement is a **per-party, confidentiality-preserving, verifiable** bound, with the
bound equal to the DP clip sensitivity. That trio points at ZK proofs over the existing
commitments, and among those Bulletproofs (A/B) are the only **transparent** option —
keeping the no-trusted-setup property the rest of the suite maintains. Between L∞ (A) and L2
(B): L2 is the "correct" norm (it is what DP-SGD clips), but the squared-norm argument is a
strictly larger build; L∞ is cheaper, still a strong anti-poisoning control, and crucially
**establishes the whole Bulletproofs pipeline** (commitments → range proof → Fiat-Shamir →
batched verify) that L2 then extends. So A is v1, B is v2.

C (SNARKs) buys succinctness the consortium scale does not yet need, at the cost of a
ceremony and a heavy toolchain — the same "don't add unverifiable heavy crypto" judgment as
ADR-0001 Option B. D is cheaper but cannot give a *sound per-party* guarantee without
re-introducing the binding problem ZK solves.

The honest cost of A is real and structural: Bulletproofs need many group operations, and
the MODP-2048 group from ADR-0002 is slow for that volume. Making ZK practical most likely
means **moving the commitment group to an elliptic curve (Ristretto255)** — which migrates
the ADR-0002 Pedersen commitments onto the curve — and probably **depending on a vetted
Bulletproofs/curve library** rather than hand-rolling the inner-product argument in pure
Python. That build-vs-depend choice, and the group migration, are the main decisions this
ADR puts on the table.

## Consequences

**Easier:**
- The per-client DP guarantee becomes **sound against malicious clients**: the proven norm
  *is* the sensitivity the accountant uses, so the `(ε, δ)` the ledger attests no longer
  rests on an unverified "the client clipped" assumption — a strong compliance story.
- Anti-poisoning/Byzantine resistance improves: a single party can no longer dominate the
  aggregate by magnitude, even though its update stays hidden.
- The proof attaches to commitments and a group that already exist (ADR-0002); admission
  gating slots into the v0.18.0 secure round.

**Harder:**
- **Significant new cryptography.** Bulletproofs (inner-product argument, Fiat-Shamir
  transcript binding all public inputs, vector Pedersen, multi-exponentiation) is a large,
  correctness-critical build; pure-Python is feasible for a small-param verifiable core but
  too slow for production.
- **Likely group migration + dependency.** Practical proving pushes the commitment group to
  a curve (Ristretto255), migrating ADR-0002's Pedersen commitments, and likely introduces a
  vetted ZK/curve dependency behind a new `[zk]` extra — a departure from the
  no-binary-dependency stance held so far, to be decided explicitly.
- **Per-round cost.** A proof per party per round at model dimension `d` is the dominant
  cost; aggregated proofs and **batched verification** are required, and a dimension
  benchmark gates making this a default.

**Revisit when:**
- The **L2** bound is needed (it usually is, to match the clip norm exactly) → implement
  Option B on A's machinery.
- Proof size / verification time dominate at large scale → reconsider a SNARK (Option C),
  accepting its setup.
- *Semantic* robustness is required — a **backdoored but in-norm** update — which ZK norm
  proofs do **not** address (a Byzantine-ML problem, not a cryptographic one); that needs a
  separate robustness ADR.

## Action Items
1. [ ] Threat-model delta: state precisely what bounded-norm validation adds (per-party norm
       honesty / anti-poisoning) and what it does **not** (in-norm backdoors, Sybil/identity)
       and tie the proven bound to the DP clip sensitivity.
2. [ ] Decide proof system (Bulletproofs) and **v1 norm = L∞**; specify the statement,
       generators, and the Fiat-Shamir transcript (must bind commitments, bound `B`, round id).
3. [ ] Decide the group: keep MODP-2048 vs **migrate Pedersen commitments to Ristretto255**
       for proving performance; and **build vs. depend** (hand-rolled core vs. vetted lib).
       Pin a cross-repo golden vector for whatever is chosen.
4. [ ] Implement the **pure-Python verifiable core** (range proof + inner-product argument,
       small params) with tests: a valid in-bound proof verifies; an out-of-bound or tampered
       proof **fails closed**; the transcript rejects a re-bound (weak-Fiat-Shamir) proof.
5. [ ] Wire admission gating into `run_secure_consortium_round`: a contribution is admitted
       only if its norm proof verifies; a failing proof excludes the party / aborts; record
       the proof's verification outcome (not the proof) on the ledger.
6. [ ] Bind the proven bound to the **DP clip sensitivity** so the accountant's per-client
       `(ε, δ)` is enforced, and surface "sensitivity: proven" in the signed `D4` evidence.
7. [ ] Benchmark prover/verifier at realistic model dimension with proof **aggregation +
       batched verification**; document the cost and the `[zk]` extra / dependency decision.
8. [ ] Defer to follow-up ADRs: the **L2** bound (Option B), a SNARK route (Option C) if
       size/verify dominate, and **semantic robustness** (in-norm backdoors).
