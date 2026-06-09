# ADR-0004: Ristretto255 + Bulletproofs performance backend for bounded-norm proofs

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** Vladimir Stantchev (architecture); FS design-partner risk/security leads
**Scope:** `presidio-hardened-ai` P4 — make the ADR-0003 bounded-norm proofs production-fast
without changing their guarantee
**Amends:** [ADR-0003](0003-bounded-norm-input-validation.md) — a *performance* upgrade to the
ZK range proofs shipped there; same threat model, same `EvidenceRef@1` contract.

> **Implementation status (v0.21.0–v0.22.0).** Accepted; built. v0.21.0 ships the pluggable
> `ProofBackend` + MODP fallback + auto-dispatch (items 2, 8); v0.22.0 ships the Rust/dalek
> `presidio_ai_zk` crate, the `_ristretto_backend` adapter, the `ci-zk` lane, and the
> serialization (items 1, 3, 5). The native crate is buildable, CI-validated source — built
> and self-validated in `ci-zk`, not in the dev sandbox (no Rust toolchain). **Remaining:**
> the in-round commitment/homomorphic-check migration to Ristretto when the native backend
> is active is handled generically by the backend seam, but a Ristretto-path consortium
> integration test + the dimension **benchmark** (items 4, 6) await a CI run with the wheel.

## Context

ADR-0003 shipped a **correct** bounded-norm proof (v0.19.0–v0.20.0): a transparent Pedersen
bit-decomposition range proof over the prime-order **MODP-2048** group, gating consortium
admission so the DP clip sensitivity is *proven*. It deliberately deviated from the ADR's own
recommendation — Bulletproofs over Ristretto255 — because neither was available: the
environment's libsodium had no Ristretto255, and there is no vetted *Python* Bulletproofs
library. The deviation note named this ADR as the follow-up.

The cost of the v1 choice is purely performance, and it is real:

- **Proof size is `O(n)`.** A bit-decomposition proof carries one commitment + one OR-proof
  per bit, per coordinate. At model dimension `d` with `n`-bit coordinates that is `O(d·n)`
  group elements — large on the wire and in the ledger-adjacent transcript.
- **MODP exponentiation is slow.** Each operation is a ~2048-bit modular exponentiation
  (~milliseconds in pure Python); a range-proof round does many thousands of them, so prover
  and verifier time dominate the consortium round at realistic `d`.
- **No proof aggregation.** v1 proves each coordinate independently; there is no batching.

Nothing about the *guarantee* needs to change — it is already a transparent, no-trusted-setup
ZK range proof enforcing the clip bound. This ADR is only about the **proof system and group**
underneath, to get `O(log n)` proofs, fast curve arithmetic, and aggregation.

Forces at play:

- **Audited crypto.** The win comes from a *vetted* Bulletproofs implementation, not a
  hand-rolled inner-product argument — the dalek `bulletproofs` + `curve25519-dalek` (Rust)
  are the de-facto audited reference. Using them means a **compiled dependency**.
- **Keep the pure-Python property as a fallback.** The suite has held a "verifiable core runs
  anywhere, no binary dependency" line. A compiled backend should be an *acceleration*, not a
  hard requirement — the v1 MODP proof should remain as a dependency-free fallback.
- **No contract churn.** Ristretto255 is a *prime-order* abstraction over Edwards25519 (it
  exists precisely to remove the cofactor pitfalls that make raw ed25519 unsafe for
  commitments). The Pedersen *form* (`g^v h^r`) and the homomorphic aggregate check are
  identical on it; only the group and the proof object change. `EvidenceRef@1` and ikigov are
  untouched — the proof is a round-admission artifact, never part of the evidence.
- **Build/release reality.** A Rust extension means a Rust toolchain in CI and cross-platform
  wheels — real infrastructure, to be weighed.

## Decision

Introduce a **pluggable proof backend** with two implementations behind one interface:

1. a **Ristretto255 + Bulletproofs backend** (default when available) — a thin Rust-FFI
   extension (PyO3/maturin) over the audited dalek `bulletproofs` and `curve25519-dalek`
   crates, installed by the `[zk]` extra; and
2. the **v1 pure-Python MODP-2048 backend** (ADR-0003) — retained as a **dependency-free
   fallback** used automatically when the native wheel is absent.

`prove_bounded` / `verify_bounded` and `run_secure_consortium_round` dispatch through the
interface; a round picks **one** backend (and therefore one commitment group) and uses it
end to end — backends are never mixed within a round. Bulletproofs' **aggregated** range
proofs collapse a party's whole vector (and, optionally, the consortium) into one `O(log)`
proof. The guarantee is identical on both paths; only size and speed differ. zk-SNARKs
(trusted setup) and a pure-Python curve build remain rejected, below.

## Options Considered

### Option A: Rust-FFI to dalek `bulletproofs` + `curve25519-dalek` (default), MODP fallback
A maturin/PyO3 native module behind `[zk]`; the v1 MODP proof is the fallback.

| Dimension | Assessment |
|-----------|------------|
| Complexity | High — Rust extension, build/CI, serialization, dispatch |
| Cost | `O(log n)` proofs, fast curve ops, batched verify; one-time build infra |
| Scalability | Excellent — aggregated proofs across coordinates/parties |
| Team familiarity | Med — dalek is well-documented and audited; FFI surface is small |

**Pros:** **audited** Bulletproofs + Ristretto255; smallest/fastest proofs; aggregation; the
pure-Python fallback preserves "runs anywhere"; no change to the guarantee, evidence, or
threat model. **Cons:** a **compiled dependency** and Rust toolchain + cross-platform wheels
(maturin/cibuildwheel); a proof/point **serialization + golden vector** to pin; the round's
input-commitment group migrates to Ristretto when this backend is used.

### Option B: Pure-Python Bulletproofs over a Python Ristretto255
Implement the inner-product argument in Python over a Python/wrapped Ristretto255.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Very High — hand-rolled IPA, correctness-critical |
| Cost | Still slow (Python big-int curve ops); `O(log n)` size only |
| Scalability | Poor (prover time) |
| Team familiarity | Low |

**Pros:** no compiled dependency. **Cons:** **unvetted** (the exact thing ADR-0003 refused to
ship) *and* slow — worst of both worlds. The size win without the speed win, at the cost of
hand-rolling audited-grade crypto. Rejected.

### Option C: Depend on an existing maintained Python ZK library
Use a published EC/ZK library (e.g. petlib/zksk-style Σ-protocol toolkits).

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med |
| Cost | Varies; generally not audited Bulletproofs |
| Scalability | Moderate |
| Team familiarity | Low |

**Pros:** a real dependency rather than hand-rolled; some EC acceleration. **Cons:** none of
the maintained Python options is an **audited Bulletproofs** implementation — adopting one
trades our own unvetted code for someone else's. If it wraps OpenSSL EC it still lacks the
range-proof aggregation. Not a clear win over A; revisit only if a vetted pure-Python option
appears.

### Option D: Keep MODP, optimize (multi-exponentiation, batching, precompute)
Speed up v1 without a curve or new dependency.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Med |
| Cost | Constant-factor speedup; still `O(n)` size, still MODP modexp |
| Scalability | Limited |
| Team familiarity | High |

**Pros:** zero new dependency; pure-Python; easy. **Cons:** does not change the asymptotics —
proofs stay `O(n)` and MODP modexp stays slow; a stop-gap, not the production answer. Worth
doing **as part of the fallback** (it improves the no-`[zk]` path), but not the decision.

## Trade-off Analysis

The requirement is production performance *with audited crypto and no change to the
guarantee*. Only A delivers all three: dalek is the audited reference, Ristretto255 is the
correct prime-order group, and Bulletproofs give `O(log n)` aggregated proofs. The price is a
compiled dependency and Rust build infrastructure — a genuine departure from the suite's
pure-Python line.

The **non-obvious architectural move that resolves the tension**: make the proof system a
**pluggable backend** and keep the v1 MODP proof as a **dependency-free fallback**. Then the
`[zk]` extra is an *accelerator*, not a requirement: a deployment that cannot build the Rust
wheel still gets correct bounded-norm validation (slower, larger), and one that can gets
audited production performance — with an **identical security guarantee** either way, because
both paths are transparent ZK range proofs enforcing the same clip bound. This preserves
"verifiable core runs anywhere" while adding "production-fast where it matters."

B and C give up either vetting or the speed/aggregation the ADR exists for; D is a useful
fallback optimization but not the asymptotic fix.

A subtlety to design around: the native and fallback backends are **not byte-compatible** —
they are different proof systems over different groups — so cross-validation in CI checks that
they reach the **same accept/reject decision** on the same logical statement (in-bound →
accept, out-of-bound / tampered → reject), not that they produce the same bytes.

## Consequences

**Easier:**
- Production proof size (`O(log n)`) and speed (Ristretto255 ops, batched verification), with
  **aggregated** range proofs covering a whole vector (or consortium) in one proof.
- The crypto core is **audited** (dalek), not hand-rolled.
- No change to `EvidenceRef@1`, ikigov, the DP accounting, or the threat model — the proof is
  a round-admission artifact; only its representation improves.

**Harder:**
- A **compiled Rust dependency** behind `[zk]`, with a Rust toolchain in a new CI lane
  (mirroring `[torch]`/`[mpc]`) and **cross-platform wheels** (maturin + cibuildwheel) for
  release.
- A **serialization + golden vector** for Bulletproof bytes and Ristretto commitments, pinned
  in tests so producer/verifier agree across versions.
- When the Ristretto backend is used, the round's **input commitments and the homomorphic
  aggregate check (ADR-0002) move to Ristretto255**; a round is single-group (no mixing).
  (Feldman-VSS seed sharing stays on MODP — it is not the bottleneck and is independent.)
- Two backends to maintain and keep decision-equivalent.

**Revisit when:**
- A **vetted, dependency-free** (pure-Python or wasm) Bulletproofs/Ristretto option appears →
  reconsider dropping the Rust requirement.
- **Whole-consortium proof aggregation** (one proof for all parties) — **done v0.29.0**:
  `prove_bounded_batch` (cross-bound on MODP; one Bulletproof over the concatenated vector on
  the native backend).
- The **L2** bound ADR lands → it must use this backend (Bulletproofs inner-product), not the
  MODP fallback, for performance.

## Action Items
1. [x] Pin the dalek crates (`bulletproofs`, `curve25519-dalek`) and versions; define the
       PyO3/maturin native module surface (commit, prove_bounded, verify_bounded) for `[zk]`.
2. [x] Define the **proof-backend interface** and dispatch: native Ristretto/Bulletproofs when
       importable, else the v1 pure-Python MODP fallback; a round selects one backend end to end.
3. [x] Specify **serialization** for Ristretto commitments + Bulletproof bytes and pin a
       cross-repo **golden vector** (as for the Ed25519 evidence wire format).
4. [ ] On the Ristretto path, migrate the consortium **input commitments + homomorphic
       aggregate check** to Ristretto255; keep Feldman-VSS seed sharing on MODP; forbid mixing.
5. [x] Add a **CI lane** (Rust toolchain + maturin) that builds the wheel and runs the native
       tests; cross-validate native vs. fallback on **decision equivalence** (accept/reject),
       not bytes.
6. [ ] **Benchmark** prover/verifier time and proof size, native vs. v1 fallback, at realistic
       model dimension; record the speed-up and the size reduction.
7. [ ] Build **cross-platform wheels** (cibuildwheel) for release; document the `[zk]` install
       path and the automatic fallback when the wheel is unavailable.
8. [x] Keep the v1 MODP proof as the documented fallback (optionally apply Option D
       multi-exponentiation there); ensure the L2-bound ADR builds on this backend.
       **L2 scoped in [ADR-0005](0005-l2-bounded-norm.md) (Proposed)** - reuses this
       backend's range proof for the squared-norm.
