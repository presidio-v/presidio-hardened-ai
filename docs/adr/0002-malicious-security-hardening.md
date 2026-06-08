# ADR-0002: Malicious-security hardening for consortium secure aggregation

**Status:** Proposed
**Date:** 2026-06-08
**Deciders:** Vladimir Stantchev (architecture); FS design-partner risk/security leads
**Scope:** `presidio-hardened-ai` P4 — hardening the secure-aggregation protocol against
*active protocol deviation*
**Amends:** [ADR-0001](0001-multiparty-secure-aggregation.md) — extends its threat model
from honest-but-curious to malicious; does not change the v1 mechanism (additive masking).

## Context

ADR-0001 chose secure aggregation by additive masking and bounded its threat model to an
**honest-but-curious (HbC)** coordinator plus a collusion threshold `t` of parties: every
participant follows the protocol but may try to *learn* from what it legitimately sees.
v0.11.0–v0.14.0 built that out (exact field masking, Shamir dropout recovery, authenticated
X25519 key agreement, governed rounds, ledger-bound `D4` evidence). ADR-0001's explicit
revisit trigger was *"the threat model adds a malicious coordinator or parties → add
commitments / verifiable secret sharing."* This ADR is that amendment.

A **malicious** participant *deviates* from the protocol. The concrete attacks on the v1
construction:

- **Coordinator survivor-set equivocation (the Bonawitz unmasking attack).** Dropout
  recovery requires survivors to reveal Shamir shares of a *dropped* party's pairwise
  seeds. A malicious coordinator can lie about who dropped — tell survivors that a live
  target `T` "dropped" so they hand over shares that reconstruct `T`'s pairwise seeds —
  then combine those with `T`'s submitted masked vector to **unmask `T`'s individual
  update**. HbC ruled this out by assumption; malicious does not.
- **Coordinator false aggregate.** The coordinator returns a Σ that is not the true sum
  of submissions (drops/duplicates/edits contributions). Nothing in v1 lets a party check
  the returned aggregate.
- **Malicious party — inconsistent shares.** Shamir sharing trusts the dealer. A malicious
  party can hand *different* shareholders mutually inconsistent shares of its seed, so
  reconstruction yields garbage (selective corruption / abort) or a value of its choosing.
- **Malicious party — submission equivocation.** A party shows different masked vectors or
  different DH keys to different peers, breaking mask cancellation for a subset.

Forces at play (in addition to ADR-0001's):

- **Detect-and-abort is acceptable; guaranteed output delivery is not required.** A
  consortium of named institutions wants *integrity and confidentiality under deviation*,
  with a clean, attributable abort if someone cheats — not a protocol that forces a correct
  result against a saboteur (which costs far more).
- **The ledger is already a signed, append-only transcript.** "Architecture is the
  defense": we should make the existing ledger the **public bulletin board** that anchors
  commitments and the agreed survivor set, rather than invent a new consistency channel.
- **The computation is still a sum.** As in ADR-0001, this rules out reaching for
  general-purpose maliciously-secure MPC.
- **Confidentiality of a well-formed update is a different problem from its honesty.** A
  party submitting a *well-formed but adversarial* update (model poisoning) is a Byzantine-
  robustness concern, not a secure-aggregation one — it must be scoped separately.

## Decision

Adopt **security-with-abort against active deviation** by layering three composable
mechanisms onto the v1 masking protocol, all anchored in the existing ledger:

1. **Signed, ledger-anchored survivor-set agreement.** Before any party reveals shares for
   dropout recovery, the coordinator must collect and relay **≥ `t` party signatures over
   the same "alive set"**, and that signed set is appended to the ledger. A party reveals
   recovery shares **only** for a survivor set it has seen `t`-signed. This defeats
   coordinator equivocation: the coordinator cannot present two different alive-sets without
   producing two `t`-signed, ledger-recorded contradictions. (Bell et al. 2020 consistency
   check, made publicly auditable by the ledger.)
2. **Verifiable secret sharing (VSS) of mask seeds.** Replace plain Shamir with **Feldman
   VSS**: the dealer publishes commitments to its sharing-polynomial coefficients; each
   shareholder verifies its share against the public commitment and **aborts on
   inconsistency**. A malicious party can no longer distribute inconsistent seed shares.
3. **Homomorphically-committed inputs.** Each party publishes a **Pedersen commitment** to
   its (quantised) update alongside its masked vector. Pedersen commitments are *additively
   homomorphic*, so the product of the per-party commitments is a commitment to the true
   sum; a party checks the coordinator's returned aggregate against it and **aborts on a
   false aggregate**. Commitments are recorded on the ledger for post-hoc public
   verifiability.

**Explicitly out of scope for this amendment** (separate follow-ups, not this ADR):
**input poisoning** (well-formed adversarial updates → bounded-norm / range zero-knowledge
proofs, ACORN/RoFL line) and **liveness/DoS** (a coordinator or party that simply refuses
or forces aborts). This ADR provides confidentiality and *integrity-or-abort*, not Byzantine
robustness and not guaranteed output delivery.

General maliciously-secure MPC, verifiable threshold HE, and TEE attestation are evaluated
and **deferred** below.

## Options Considered

### Option A: Commitments + VSS + signed survivor-set consistency (ledger-anchored)
The three mechanisms above, layered on v1 masking; the ledger is the bulletin board.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med–High — adds a group (Pedersen/Feldman), a consistency round, ledger schema |
| Cost | Med — group exponentiations per round; commitment cost grows with vector dimension |
| Scalability | Good for 3–20 institutional parties; commitment cost is the watch-item |
| Team familiarity | Med — extends `secure_agg`/`keyagreement`/ledger; pure-Python verifiable core |

**Pros:** closes exactly the deviation attacks named (equivocation, false aggregate,
inconsistent shares); **reuses the ledger** as the public consistency anchor; Pedersen's
additive homomorphism composes with additive masking the way DP did in ADR-0001; verifiable
core stays CI-testable. **Cons:** security-*with-abort* only (a cheater can force a clean
abort = DoS, accepted); needs a discrete-log-hard group, which forces the secret-sharing
field up from GF(2⁶¹−1) (breaking change, below); commitment cost at model scale needs
mitigation (vector commitments / commit-to-seeds).

### Option B: Maliciously-secure general MPC (SPDZ-style, with MACs)
Information-theoretic MACs on secret-shared values give active security for arbitrary
circuits.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — external MPC toolchain, preprocessing, circuit compilation |
| Cost | Very high — active-secure preprocessing is 100–1000×+; heavy comms |
| Scalability | Poor for model-sized vectors |
| Team familiarity | Low — new dependency + paradigm |

**Pros:** strongest — active security *and* guaranteed correctness for any function, can add
input validation in-circuit. **Cons:** massive over-engineering for a *sum* (same objection
as ADR-0001 Option B); unverifiable heavy dependency; cost incompatible with model-sized
updates.

### Option C: Verifiable threshold HE (ZK proofs of correct encrypt/decrypt)
Threshold-HE aggregation (ADR-0001 Option C) plus zero-knowledge proofs that ciphertexts
are well-formed and threshold-decryptions are correct.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — threshold key mgmt + ZK proof system on top |
| Cost | High — large ciphertexts, proof generation/verification per party |
| Scalability | Moderate (packing helps; proofs dominate) |
| Team familiarity | Low |

**Pros:** strong confidentiality + verifiable correctness; natural dropout tolerance.
**Cons:** two heavy new dependencies (HE + a proof system) to vet; far beyond what a sum
needs. Remains the credible path **if** we later move to the HE world for other reasons.

### Option D: TEE-attested coordinator
Run the coordinator (and the consistency/aggregation logic) inside an attested enclave.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med (ops-heavy: attestation, enclave deployment) |
| Cost | Low–Med at runtime |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** defeats coordinator deviation cheaply at runtime; simple data flow. **Cons:**
shifts the integrity root to a **hardware vendor + attestation chain**, not a cryptographic
guarantee; side-channel history; same "architecture is the defense" objection as ADR-0001
Option D. A viable *deployment hardening option*, not the primary guarantee, and it does
nothing about malicious *parties*.

## Trade-off Analysis

The user's named adversary is a **deviating coordinator or colluding parties** — i.e.
*protocol-integrity* attacks on confidentiality, not arbitrary computation and not Byzantine
input honesty. Option A is the **minimal set that closes exactly those attacks** while
staying inside the suite's grain: each mechanism maps one-to-one onto one attack
(signed survivor-set → equivocation/unmasking; VSS → inconsistent shares; homomorphic
commitment → false aggregate), and all three reuse the **ledger as the public bulletin
board**, so verification is post-hoc and auditable rather than a new trusted channel.
The Pedersen commitment's additive homomorphism is the same compositional trick ADR-0001
used (masking ⊕ DP): the commitment to the sum *is* the product of commitments, so integrity
checking falls out of the algebra rather than bolting on a proof system.

B and C buy generality (arbitrary functions; encrypted compute) the sum does not need, at a
cost and dependency weight ADR-0001 already rejected. D moves integrity onto hardware. A's
honest limitation is that it is **security-with-abort**: a malicious participant can force a
detectable, attributable abort (a DoS), which we accept because availability is not
confidentiality or integrity — the round simply does not produce output, and the ledger
records who broke it.

The chief cost of A is structural: commitments and Feldman VSS require a group where the
discrete log is hard (~256-bit), whereas masking and Shamir live in **GF(2⁶¹−1)**. Adopting
VSS therefore forces the secret-sharing field up to a DL-hard prime (e.g. the Ristretto255
scalar field / Ed25519 group order) and a re-encoding of quantised updates — a breaking
change to `secure_agg.PRIME`, gated by version. This is real migration work, but it is the
price of cryptographic (not assumed) integrity, and it is contained behind the `[mpc]` lane.

## Consequences

**Easier:**
- The ledger gains a second role as a **public bulletin board / verifiable transcript**:
  commitments and the `t`-signed survivor set are recorded, so a round becomes auditable by
  any party (and any later evidence consumer) without a new channel.
- Integrity checking is *algebraic* (homomorphic commitments) rather than a bolted-on proof
  system; the verifiable core stays pure-Python and CI-testable for small parameters.
- The guarantee upgrades from "trust the coordinator" to "detect-and-abort on deviation,"
  with attribution, which is the bar institutional risk teams actually ask for.

**Harder:**
- **Field/group migration.** A DL-hard group is needed for commitments/VSS; the secret-
  sharing field must rise from GF(2⁶¹−1) to a ~256-bit prime, and quantised-update encoding
  must map into it. Breaking change to `secure_agg`, version-gated, with a back-compat note.
- **New dependency.** Pedersen/Feldman need group scalar-multiplication (e.g. Ristretto255).
  `cryptography` exposes X25519/Ed25519 but not general group arithmetic; this likely pulls
  in libsodium/PyNaCl (Ristretto255) behind the `[mpc]` extra, with a slow pure-Python
  prime-order group for the CI-verifiable core.
- **Performance.** A commitment per update coordinate is expensive at model scale; needs
  vector/multi-commitments or committing to *seeds* rather than every coordinate — to be
  benchmarked before this is the default.
- **Protocol rounds.** Adds a signed-survivor-set consistency round before share reveal, and
  a verification step before a party accepts the aggregate; more messages and ledger writes.

**Revisit when:**
- **Input poisoning** must be in scope → add bounded-norm / range **zero-knowledge proofs**
  on submissions (ACORN/RoFL line) — a separate ADR; orthogonal to this one.
- **Guaranteed output delivery** is required (not just abort) → maliciously-secure MPC
  (Option B) or identifiable-abort protocols.
- The **collusion bound `t`** must be removed, or party count grows past ~20 → reconsider
  topology / HE packing (Option C).

## Action Items
1. [ ] Threat-model delta doc: enumerate the active-deviation attacks (coordinator survivor-
       set equivocation/unmasking, false aggregate; party inconsistent-share, equivocation),
       map each to the mechanism that closes it, and state the **security-with-abort** bound
       (and what stays out: input poisoning, liveness/DoS, >`t` collusion).
2. [ ] Choose the commitment/VSS group (Ristretto255 vs a large prime field) and the
       dependency (PyNaCl/libsodium vs pure-Python); pin a cross-repo golden vector.
3. [ ] Raise the secret-sharing field to a DL-hard prime (or run a dedicated VSS field) and
       migrate `quantize`/encoding; version-gate and document the breaking change.
4. [ ] Implement **Feldman VSS** for mask seeds: dealer commitments on the ledger,
       shareholder-side verification, abort-on-inconsistency. Pure-Python core + tests
       (including a malicious-dealer inconsistent-share test that must abort).
5. [ ] Implement **Pedersen-committed inputs** with the homomorphic aggregate check: verify
       the coordinator's returned Σ against the product of per-party commitments; bind
       commitments to the ledger. Tests (including a false-aggregate test that must abort).
6. [ ] Implement the **signed survivor-set consistency round**: `≥t` signatures over one
       alive-set, relayed and ledger-anchored, gating any share reveal. Test the
       **equivocation/unmasking attack explicitly** — two alive-sets must force an abort.
7. [ ] Extend the `[mpc]` lane and `ci-mpc`: integration-test the malicious-secure path;
       **benchmark commitment cost at model dimension** and document the abort (DoS) residual.
8. [ ] Defer to follow-up ADRs: bounded-norm **ZK input validation** (poisoning) and
       **guaranteed-output-delivery** MPC.
