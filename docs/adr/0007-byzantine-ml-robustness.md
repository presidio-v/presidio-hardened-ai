# ADR-0007: Byzantine-ML robustness against in-norm backdoors

**Status:** Accepted
**Date:** 2026-06-09
**Deciders:** Vladimir Stantchev (architecture); FS design-partner risk/security leads
**Scope:** `presidio-hardened-ai` P4 — limit the damage a *well-formed, in-norm* but
adversarial model update can do (backdoor / targeted poison)
**Amends:** [ADR-0003](0003-bounded-norm-input-validation.md) — the explicitly-deferred
"semantic robustness" scope (also named in ADR-0002/0005/0006). This is an **ML-robustness**
problem, not a cryptographic one, and is treated as such.

## Context

The crypto stack now guarantees: confidentiality of individual updates (ADR-0001), protocol
honesty under a malicious minority (ADR-0002), a *proven* bound on each update's L∞/L2 norm
(ADR-0003/0005), and delivery despite sabotage (ADR-0006). A gap remains, deferred at every
step: a party can submit an update that is **well-formed and within the norm bound yet
adversarial** — a *backdoor* (make the model misclassify a chosen trigger) or a targeted
poison. Norm bounds cap a contribution's *magnitude/influence*; they do not constrain its
*direction or intent*, and a stealthy backdoor can hide inside a small, in-norm update.

The defining tension, specific to this suite: classical Byzantine-robust aggregation rules
(Krum, coordinate-wise median, trimmed mean, geometric median, Bulyan, FLTrust) all operate
by **inspecting and comparing the individual updates** — exactly what P4's secure aggregation
exists to **hide**. So robust filtering and update privacy are in direct conflict; resolving
it generically requires running the robust rule *inside* MPC, which is far heavier than the
linear sum P4 is built around. Honest framing: **cryptographic *detection* of a stealthy
in-norm backdoor on a hidden individual update is an open research problem**, and a full
robust rule conflicts with the privacy guarantee. This ADR therefore scopes *mitigation and
containment*, not detection-and-attribution.

Two facts make a right-sized posture defensible here:

- **Influence is already bounded — twice.** The proven L2 norm caps each update's magnitude,
  and **per-client DP provably bounds any single client's effect on the trained model** — DP
  is a recognised (partial) poisoning/backdoor mitigation precisely because it limits
  individual influence. The pipeline already provides a robustness *floor*.
- **The consortium is known-participant and accountable.** Unlike anonymous crowd FL, members
  are named institutions, every contribution is MPA-authorised, signed, and ledgered. This
  changes the threat *probability* and gives **post-hoc forensics**: an attack is attributable
  and costly to mount, which deters and enables response.

Forces at play: preserve update privacy (don't undo P4); right-size to the *sum* and to a
known-participant consortium; reuse existing primitives (DP, norm ZK, ledger, validation);
and be honest about the residual that no privacy-preserving mechanism fully removes.

## Decision

Adopt a **layered, privacy-preserving robustness posture** as v1 (Option C), composed of
controls that never inspect an individual update:

1. **Influence-bounding by construction** — the proven L2 norm (ADR-0005) + per-client DP
   (v0.5.0/v0.9.0) cap how far any one contribution can move the model; document the bound
   each provides as the robustness floor.
2. **Accountability layer** — known participants + n-of-m MPA + signed, ledgered contributions
   make an attack attributable and forensically traceable (deterrence + response).
3. **Aggregate-level validation gate + rollback** — each round's *candidate global model*
   (the aggregate only, never individuals) is scored on a server-held **clean validation set**
   and a **trigger/canary test**; a round whose robustness metric regresses beyond a threshold
   is **rejected and rolled back**, and a robustness flag is recorded on the ledger as evidence.

This contains damage without breaking privacy. As the *cryptographic increment*, scope
**(B) a ZK well-behavedness proof** — a zero-knowledge cosine-similarity-to-reference band on
the hidden update (reusing the ADR-0003/0005 commitment + proof machinery) — which catches
gross-direction attacks while keeping the update secret. **(A) robust aggregation under MPC**
(median/trimmed-mean/Krum on shares) is the heavy escalation reserved for a hardened threat
model. TEE-based filtering is rejected (below).

## Options Considered

### Option A: Robust aggregation rules under MPC (Krum / median / trimmed-mean on shares)
Compute a Byzantine-robust aggregation rule inside MPC so only the robust result is revealed.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Very High — non-linear (compare/sort) MPC beyond P4's linear sum |
| Cost | Very High — comparison gates per coordinate per round |
| Scalability | Poor at model dimension |
| Team familiarity | Low |

**Pros:** strongest — genuine robust filtering *and* update privacy. **Cons:** needs
maliciously-secure MPC comparison/sorting (P4 is linear-only by design); cost is prohibitive
at model scale; a large new dependency. The principled end-state if the threat model demands
true robust filtering — deferred, not v1.

### Option B: Extended ZK well-behavedness proofs (cosine-to-reference band)
Each party proves in ZK that its (hidden) update's direction lies within a band of a public
reference (e.g. the previous global), beyond the existing norm bound.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — an inner-product/cosine ZK gadget on the committed update |
| Cost | Med — extends the per-party ZK gate |
| Scalability | Good (per-party, aggregatable like the norm proof) |
| Team familiarity | Med — reuses ADR-0003/0005 commitments + proofs |

**Pros:** privacy-preserving and *per-party* (no MPC); reuses the ZK machinery; catches
scaling and gross-direction attacks. **Cons:** a cosine band does **not** catch stealthy
low-deviation backdoors; choosing the band trades false-positives against missed attacks. A
strong **cryptographic increment** on top of v1, not a complete answer.

### Option C: Aggregate-level validation + rollback, layered with DP/norm/accountability
Validate the candidate global each round on a clean held-out set; reject/rollback regressions;
lean on DP + norm + accountability as the influence/forensics floor. **(Recommended v1.)**

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low–Med — a validation hook + rollback + ledger flag |
| Cost | Low — one validation pass per round on the aggregate |
| Scalability | Good |
| Team familiarity | High — reuses the ledger, evidence, and existing DP/norm |

**Pros:** **privacy-preserving** (operates on the aggregate, never individuals); cheap;
composes with everything; gives a concrete reject/rollback backstop + a held-out canary test
for known triggers; honest about being containment, not attribution. **Cons:** coarse — no
per-party attribution; a stealthy backdoor that doesn't dent validation/canary metrics can
still pass; needs a trusted clean validation set.

### Option D: TEE-based robust filtering
Run a robust rule on individual updates inside an attested enclave.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med (ops-heavy: attestation) |
| Cost | Med |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** robust rule on individuals without revealing them to the coordinator. **Cons:**
shifts the privacy/robustness root to a **hardware vendor + attestation** — the same objection
the suite raised against TEEs at every prior ADR; side-channel history. Rejected as the
primary mechanism; a deployment option at most.

## Trade-off Analysis

The blunt truth is that **privacy and Byzantine-robust filtering pull against each other**:
the rules that detect a malicious update (A) need to see it, which P4 forbids, so genuine
detection costs heavy MPC. For a **known-participant, accountable, DP-bounded** consortium the
proportionate answer is not to buy that cost up front but to **layer cheap, privacy-preserving
containment** (C) on top of the influence-bounding the pipeline already provides, and to add
*cryptographic* robustness **incrementally** (B) where it stays per-party and private. The
non-obvious leverage is that **two controls already in place — the proven L2 norm and per-client
DP — are themselves recognised backdoor *mitigations*** (they bound individual influence), so v1
is mostly making that floor explicit and adding an aggregate validation/rollback backstop, not
inventing new machinery. A (MPC robust rules) is the honest end-state if the consortium ever
faces a malicious *majority of contributions*; D moves trust onto hardware. The residual — a
stealthy, low-deviation, validation-passing backdoor — is stated, not hidden: no
privacy-preserving control fully removes it, and the accountability layer is the backstop
(attributable, costly, forensically traceable).

## Consequences

**Easier:**
- A concrete, **privacy-preserving** robustness backstop (validation + rollback) that composes
  with secure aggregation, GOD, DP, and the ledger without seeing any individual update.
- Makes the existing **DP + norm** influence-bound an explicit, documented robustness control,
  and uses the accountability layer (MPA + signed/ledgered contributions) for forensics.

**Harder:**
- A **trusted clean validation set** (and a canary/trigger suite) must be curated and held by
  the coordinator/governance — a new operational asset and trust assumption.
- The cryptographic increment (B, cosine-band ZK) is a new gadget; the heavy escalation (A) is
  non-linear MPC the suite has deliberately avoided.
- **Residual risk is explicit:** stealthy in-norm backdoors that don't move validation/canary
  metrics can pass; v1 contains and attributes rather than detects.

**Revisit when:**
- The threat model hardens to a **malicious majority of contributions** or stealthy backdoors
  become a primary concern → implement (A) robust aggregation under MPC.
- A privacy-preserving **per-party** direction check is wanted → implement (B) cosine-band ZK.
- Reproducible-trigger backdoors are in scope → expand the canary/trigger test battery.

## Action Items
1. [x] Threat-model section: define in-norm backdoor / targeted poison precisely; state what
       v1 **mitigates/contains** vs **detects**, and the residual; record the DP + norm
       influence-bound as the robustness floor (with the bound each gives).
2. [x] Implement the **aggregate-validation gate + rollback**: score each round's candidate
       global on a clean held-out set + a canary/trigger suite; reject/rollback on regression
       beyond a configured threshold; record a robustness flag (aggregate-level, commitments-
       only) on the ledger; surface it in the round result and (optionally) `D4`.
3. [x] Document the **layered posture** (norm + DP + MPA/accountability + validation/rollback)
       in `SECURITY.md`, with the explicit residual and the escalation path.
4. [ ] Scope **(B) cosine-band ZK** as the next cryptographic increment: a ZK proof that the
       committed update's direction is within a band of a public reference, reusing the
       ADR-0003/0005 machinery; pin the predicate and false-positive/missed-attack trade-off.
5. [ ] Define the **escalation trigger** to (A) robust-aggregation-under-MPC and record it as a
       revisit condition (malicious majority of contributions / stealthy-backdoor priority).
6. [x] Cross-check the validation/rollback path composes with GOD and security-with-abort
       rounds and with per-silo DP charging (a rolled-back round must not double-charge ε).
