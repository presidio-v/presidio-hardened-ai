# Changelog

All notable changes to `presidio-hardened-ai`. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project uses 0.y.z pre-1.0 versioning.
Per-version design rationale lives in `PRESIDIO-REQ.md`; architecture decisions in `docs/adr/`.

The **P4 consortium** arc (v0.11.0–v0.30.0) hardens multi-party secure aggregation across seven
accepted ADRs. The cross-repo `EvidenceRef@1` contract is **unchanged** throughout, so the
`presidio-hardened-ikigov-assess` verifier interoperates with every version below.

## [0.30.0] — Byzantine-ML robustness gate (ADR-0007)

### Added
- `fl.robustness`: a privacy-preserving robustness layer that scores a round's **aggregate**
  (never an individual update) against a consortium-supplied clean validation set + canary/
  trigger suite. `RobustnessPolicy` / `evaluate` reject on a failed canary, a sub-threshold
  score, or a regression vs the previous round.
- Optional `robustness=` on `run_god_consortium_round` / `run_secure_consortium_round`: a
  rejected round is **rolled back** — aggregate not applied, **no DP budget charged**, no `D4`
  emitted — and a `consortium-round-rejected` flag is recorded on the ledger. Results gain
  `applied` + `robustness`.

### Security
- Documented the layered posture (L2 + per-client DP influence-bound · MPA/accountability ·
  aggregate validation/rollback) and the explicit residual in `SECURITY.md`.

## [0.29.0] — Whole-consortium proof aggregation (ADR-0004/0006)

### Added
- One round-level bounded-norm proof for all parties, cross-bound under a single Fiat–Shamir
  `domain` (tampering any one commitment fails the whole batch): `prove_bounded_batch` /
  `verify_bounded_batch` on the `ProofBackend`. Native backend aggregates via one Bulletproof
  over the concatenated consortium vector (`O(log)`); MODP returns the cross-bound collection.

## [0.28.0] — Bounded-norm gate on the GOD path (ADR-0006 item 4)

### Added
- `zk.prove_commitment_equality` / `verify_commitment_equality`: a Schnorr proof binding a
  Pedersen commitment (`g^s h^r`) to a Feldman commitment (`C_0 = g^s`) of the same value.
- `run_god_consortium_round(clip_bound=/l2_bound=)`: gates each party's **shared** input on its
  proven norm (bound to the VSS commitment by the equality proof) and excludes failures; the
  honest quorum still delivers.

## [0.27.0] — Guaranteed-output-delivery aggregation (ADR-0006, Option A)

### Added
- `fl.god`: honest-majority robust secret-sharing aggregation — parties VSS-share updates,
  shares add locally, and the sum is **robustly reconstructed** by any honest quorum.
  `run_god_consortium_round` delivers the aggregate despite a misbehaving minority (bad dealers
  excluded, bad holders discarded) with **no coordinator** single-point-of-failure.

## [0.26.0] — Robust reconstruction (ADR-0006)

### Added
- `commit.robust_reconstruct`: verify shares against Feldman commitments, discard invalid,
  interpolate from a valid quorum (robust *detection*; honest majority `n ≥ 2t+1`).

## [0.25.0] — Exclude-and-retry liveness interim (ADR-0006, Option D)

### Added
- `PartyMisbehavior` + `run_consortium_round_with_retry`: drop an attributable cheater and
  re-run among the rest (honest parties re-sign the smaller survivor set). GOD-in-practice for
  malicious parties with no new crypto.

## [0.24.0] — L2 bound on the Ristretto native backend (ADR-0005)

### Added
- Native square Σ-proof (via two generic point primitives) + L2 bounded-norm; CI-validated
  decision equivalence vs MODP. *(Buildable source; built in `ci-zk` on a Rust runner.)*

## [0.23.0] — L2 bounded-norm proofs on the MODP backend (ADR-0005)

### Added
- `zk.prove_square` / `prove_l2_bounded`: commit-squares construction — square-correctness
  Σ-proof + range-prove the homomorphic squared-norm `≤ C²`, enforcing the **exact** DP clip
  norm. `run_secure_consortium_round(l2_bound=)`.

## [0.22.0] — Ristretto255 + Bulletproofs native backend (ADR-0004)

### Added
- `rust/` PyO3/maturin crate over dalek `bulletproofs` + `curve25519-dalek` (audited, `O(log n)`
  aggregated range proofs); `fl._ristretto_backend` adapter; `ci-zk` lane.

### Notes
- Buildable, CI-validated source; not compiled in the dependency-light dev environment. The
  `[zk]` extra is an **accelerator**, not a requirement — the default lane runs the MODP fallback.

## [0.21.0] — Pluggable proof backend (ADR-0004)

### Added
- `ProofBackend` interface + `ModpBackend` (pure-Python fallback) + `get_backend()` auto-dispatch
  (native if installed, else MODP). `run_secure_consortium_round` dispatches via `backend=`.

### Fixed
- `verify_bounded` binds the proof to the *requested* bound (a party cannot satisfy a stricter
  policy with a looser proof).

## Earlier

P1–P3 + the P4 core (v0.1.0–v0.20.0): evidence layer, ε-accountant (CKS-2020 + fractional-order
RDP), MPA, DP-SGD (reference + Opacus), federated learning + per-silo governance, Ed25519
signing, and the P4 secure-aggregation core through malicious-security hardening and bounded-norm
input validation. See `PRESIDIO-REQ.md` and `docs/adr/`.

[0.30.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.30.0
[0.29.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.29.0
[0.28.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.28.0
[0.27.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.27.0
[0.26.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.26.0
[0.25.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.25.0
[0.24.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.24.0
[0.23.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.23.0
[0.22.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.22.0
[0.21.0]: https://github.com/presidio-v/presidio-hardened-ai/releases/tag/v0.21.0
