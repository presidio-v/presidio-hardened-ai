# ADR-0005: L2 bounded-norm proofs (proving the exact DP clip norm)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** Vladimir Stantchev (architecture); FS design-partner risk/security leads
**Scope:** `presidio-hardened-ai` P4 — prove a contribution's **L2** norm (not just L∞) is
within the clip bound, in zero knowledge
**Amends:** [ADR-0003](0003-bounded-norm-input-validation.md) — the deferred L2 (Option B)
follow-up; uses the [ADR-0004](0004-ristretto-bulletproofs-backend.md) pluggable backend.

> **Implementation status (v0.23.0–v0.24.0).** Accepted; built (Option A). The square-
> correctness Σ-protocol + `prove_l2_bounded`/`verify_l2_bounded` ship on the MODP backend
> (v0.23.0, verified) and the Ristretto native backend (v0.24.0, buildable/CI-validated
> source); `run_secure_consortium_round(l2_bound=…)` gates on `‖x‖₂ ≤ C` (items 1–5). The
> L∞ gate remains as a cheaper option; the default-norm policy (item 6) is left to the
> caller (pass `l2_bound` for the exact norm, `clip_bound` for L∞).

## Context

ADR-0003 ships an **L∞** bounded-norm gate: each committed coordinate is proven in
`[-B, B]`. DP-SGD, however, clips to an **L2** sensitivity — the accountant's `(ε, δ)` is
computed for `‖x‖₂ ≤ C`, not `‖x‖∞ ≤ C`. The two differ by up to a `√d` factor (`‖x‖₂ ≤
√d · ‖x‖∞`), so the L∞ gate is a *proxy*: proving `‖x‖∞ ≤ B` only bounds `‖x‖₂ ≤ √d·B`,
and proving the true L2 sensitivity with L∞ would force `B = C/√d`, rejecting legitimate
updates whose energy is concentrated in a few coordinates. To make the proven bound *exactly*
the sensitivity the accountant uses — closing the assumed-vs-enforced gap precisely rather
than approximately — the gate must prove `‖x‖₂ ≤ C`.

The technical crux: L∞ is a set of independent **range** proofs, but L2 is a **quadratic**
statement, `Σ x_k² ≤ C²`. Proving it in zero knowledge requires relating the committed
coordinates to a committed **squared-norm** — a multiplication/relation argument, which the
existing range-proof API does not provide on its own. This is the new construction this ADR
scopes; ADR-0004's "L2 uses this backend" did not specify *how* the squared-norm relation is
proven.

Forces at play:

- **Reuse the backend seam.** Whatever we choose must slot behind the ADR-0004
  `ProofBackend` so both the MODP fallback and the Ristretto255 native path implement it; the
  consortium gate dispatches `prove_l2`/`verify_l2` exactly as it does the L∞ proof today.
- **Stay audited / avoid experimental crypto.** dalek's general arithmetic-circuit (`r1cs`)
  API is **experimental and unaudited** (`yoloproofs`); the suite's bar rules out shipping it
  as the production path if a construction from *standard, vetted* primitives exists.
- **Fixed-point bookkeeping.** Coordinates are quantised `s_k = round(x_k·2^f)`; squares carry
  `2^{2f}` scale, so `S = Σ s_k²` and the bound `(C·2^f)²` live at double the fractional
  precision — the range proof must cover the wider bit-width and the field must not wrap.
- **Tie to DP.** As with L∞, the proven bound is the clip sensitivity, so a verifying L2 proof
  makes the per-client `(ε, δ)` sound against a malicious client — now at the *exact* norm.

## Decision

Adopt the **commit-squares construction** (RoFL-style), built only from standard, vetted
primitives so it works on both backends:

1. Each party commits to its coordinates `x_k` (already done) **and** to their squares
   `y_k = x_k²`.
2. For each coordinate, a **square-correctness proof** (a Σ-protocol over the Pedersen
   commitments) shows that `C_{y_k}` commits to the square of the value in `C_{x_k}` — no
   arithmetic-circuit / r1cs machinery.
3. The squared-norm commitment is the **homomorphic sum** `C_S = Σ C_{y_k}` (a commitment to
   `S = Σ x_k²`), so no extra proof links the squares to the total.
4. **Range-prove** `S ∈ [0, C²]` using the backend's **existing** range proof
   (Bulletproofs on Ristretto255; bit-decomposition on MODP).

This adds one new primitive — the square-correctness Σ-protocol — and otherwise reuses the
commitments and range proof already in each backend. Exposed as `prove_l2_bounded` /
`verify_l2_bounded` on `ProofBackend`; the consortium gate gains an `l2_bound` option
alongside (or instead of) `clip_bound`. The dalek r1cs circuit, an L∞ over-approximation,
and a probabilistic norm test are evaluated and **deferred / rejected** below.

## Options Considered

### Option A: Commit squares + square-correctness Σ-proof + range-prove the sum
The construction above: standard Pedersen + a square Σ-protocol + the existing range proof.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med–High — one new Σ-protocol; reuses commitments + range proof |
| Cost | ~2× commitments; `d` square-proofs + **one** aggregated range proof on `S` |
| Scalability | Good — the squared-norm range proof is a single value, not per-coordinate |
| Team familiarity | Med — Σ-protocols already used (Feldman, bit-OR); no new dependency |

**Pros:** built from **vetted** primitives (no experimental r1cs); works identically on MODP
and Ristretto behind the backend seam; the homomorphic sum gives the squared-norm for free;
proves the **exact** clip norm. **Cons:** a new square-correctness proof to implement and
test on both backends; doubles commitments; fixed-point squared-scale bookkeeping.

### Option B: Bulletproofs r1cs circuit proving `Σ x_k² ≤ C²` directly
Express the quadratic constraint as an arithmetic circuit in dalek's `r1cs` API.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — circuit/gadget authoring |
| Cost | Compact proof; fast verify |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** one proof object; elegant. **Cons:** dalek `r1cs` is **experimental and unaudited**
(`yoloproofs`) — fails the "audited backend" bar that ADR-0004 was built to uphold; and it has
**no MODP-fallback analogue**, breaking backend parity. Rejected for the production path;
revisit if an audited circuit backend appears.

### Option C: L∞ over-approximation (`‖x‖∞ ≤ C/√d ⇒ ‖x‖₂ ≤ C`)
Reuse the existing L∞ gate with a tightened per-coordinate bound.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low — already implemented |
| Cost | Same as L∞ today |
| Scalability | Good |
| Team familiarity | High |

**Pros:** **zero new crypto** — ships immediately on both backends. **Cons:** **conservative
and lossy** — rejects legitimate updates with energy concentrated in few coordinates (the
common case), so it is a poor enforcement of the true L2 sensitivity. Worth offering as an
*interim* mode, not the answer.

### Option D: Probabilistic norm test (random projection / JL)
Prove the norm of a few random projections is bounded.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med |
| Cost | Low |
| Scalability | Good |
| Team familiarity | Low |

**Pros:** cheap. **Cons:** **probabilistic** soundness (a cheating party passes with some
probability), and binding the projection to the committed vector reintroduces a relation
proof anyway. Weaker guarantee; rejected as the primary mechanism.

## Trade-off Analysis

The requirement is to prove the **exact** L2 clip norm, in ZK, behind the existing backend
seam, with audited primitives and MODP/Ristretto parity. Only A meets all of these: the
**non-obvious simplification** is that the squared-norm needs *no* dedicated aggregation
proof — Pedersen is additively homomorphic, so `Σ C_{y_k}` is already a commitment to
`Σ x_k²`, and the only genuinely new primitive is a per-coordinate square-correctness
Σ-protocol; the heavy lifting (the range proof on the resulting `S ≤ C²`) is the backend's
existing aggregated range proof. So L2 is "L∞'s range proof, applied once to a homomorphically
assembled squared-norm, plus a square proof," not a new proof system.

B is the textbook way but pulls in dalek's unaudited circuit API and has no fallback analogue
— exactly the trade ADR-0004 refused. C ships free but enforces the wrong (loose) bound. D is
cheap but probabilistic. A keeps the audited, dual-backend, exact-norm properties at the cost
of one new, testable Σ-protocol.

## Consequences

**Easier:**
- The gate enforces the **exact** DP clip norm (`‖x‖₂ ≤ C`), so the per-client `(ε, δ)` is
  sound against a malicious client at the real sensitivity, not a `√d`-loose proxy — the
  tightest version of the "proven, not assumed" property.
- Reuses each backend's range proof and Pedersen commitments; slots behind `ProofBackend`
  with no change to evidence, the threat model, or the consortium control flow.

**Harder:**
- A new **square-correctness Σ-protocol** to implement and test on **both** backends (MODP
  bit-group and Ristretto255), with Fiat–Shamir transcript binding.
- **~2× commitments** (coordinates + their squares) and the per-coordinate square proofs.
- **Fixed-point squared-scale bookkeeping:** `S = Σ s_k²` carries `2^{2f}` scale and the
  bound is `(C·2^f)²`; the range proof must cover the wider bit-width (e.g. 64-bit on
  Ristretto) and the field must not wrap (MODP `q` is ample; document the Ristretto range).

**Revisit when:**
- An **audited** arithmetic-circuit backend appears → Option B becomes attractive (one proof).
- Aggregating the square proofs across coordinates/parties is needed → extend the backend.

## Action Items
1. [x] Specify the **square-correctness Σ-protocol** (prove `C_y` commits to the square of
       `C_x`'s value) with a Fiat–Shamir transcript binding both commitments + the bound; pin
       a golden vector. Define the fixed-point squared-scale and bound `(C·2^f)²`.
2. [x] Add `prove_l2_bounded` / `verify_l2_bounded` to the `ProofBackend` interface; implement
       on the **MODP** backend first (pure-Python, fully testable in the default gate).
3. [x] Implement the square proof + squared-norm range proof on the **Ristretto255** backend
       (native), reusing dalek RangeProof on the homomorphic `S`; cross-validate native vs.
       MODP on **decision equivalence** in `ci-zk`.
4. [x] Wire an `l2_bound` option into `run_secure_consortium_round` (gate on `‖x‖₂ ≤ C`);
       record the enforced norm + bound on the ledger; surface "sensitivity: proven (L2)" in `D4`.
5. [x] Tests: square-proof completeness + soundness (wrong square rejected, tamper rejected,
       weak-FS rejected); an out-of-L2-norm contribution rejected even when every coordinate is
       within L∞; equivalence MODP↔Ristretto.
6. [ ] Keep **L∞** as a cheaper option and document **C** (the `C/√d` over-approximation) as a
       zero-new-crypto interim mode; default the consortium gate sensibly (L2 when available).
