# Changelog

All notable changes to `presidio-hardened-ai`. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project uses 0.y.z pre-1.0 versioning.
Per-version design rationale lives in `PRESIDIO-REQ.md`; architecture decisions in `docs/adr/`.

The **P4 consortium** arc (v0.11.0–v0.30.0) hardens multi-party secure aggregation across seven
accepted ADRs. The cross-repo `EvidenceRef@1` contract is **unchanged** throughout, so the
`presidio-hardened-ikigov-assess` verifier interoperates with every version below.

## [Unreleased]

### Added
- `--gate-certificate PATH` (repeatable) with `--gate-trust PATH` on `dp-train`,
  `dp-charge` and `consortium-round` (#77). Each ikigov-assess `gate-certificate@1` is
  verified with ikigov's own `verify_certificate` (issuer signature, expiry, embedded
  evidence-refs, recomputed decision, which must be `OPEN`) before its identity
  (presidio-evidence ADR-0006) is appended to the run's `parents`. Any refusal exits 1
  before the ledger is touched. New optional `[gate]` extra.

### Changed
- **Requires Python 3.11 or newer.** Python 3.10 reached end of life in October 2026.
  CI runs the full gate on 3.11 and the test suite on 3.12 and 3.13.
- **presidio-evidence is a runtime dependency** (`>=0.5.1,<0.6`). Canonical JSON, the
  evidence signing message, HMAC and Ed25519 signing and verification, key generation
  and the `export_evidence` envelope come from the library; no signed byte changes (the
  pinned vectors pass unchanged and are checked against the installed library's). The
  `[crypto]` extra installs `presidio-evidence[crypto]`.
- The `EvidenceRef` contract test asserts against `presidio_evidence.EVIDENCE_REF_FIELDS`,
  in field order.

### Removed
- The pre-0.31 encoder and every path that used it (#74): `_legacy_canonical_v0`,
  `legacy_sha256_hex_v0`, the legacy branch of `canonical_for` and the untagged-request
  fallback in `authorize_request`. Untagged ledger entries and approvals over untagged
  requests now fail closed. See `MIGRATION.md` for pre-0.31 records.

## [0.31.0] — 2026-10-18 (not published)

Depends on the family numeric-encoding rule (presidio-evidence ADR-0005, in draft); see
`MIGRATION.md`.

### Added
- Provenance `parents` (presidio-evidence ADR-0002) in DP, consortium and ingest evidence
  content and the matching ledger entries: lowercase hex, order kept, duplicates dropped,
  omitted when empty, malformed values rejected before any write. Repeatable `--parent HEX`
  on `pai ingest`, `dp-train`, `dp-charge` and `consortium-round` (#67).
- `docs/schemas/signed-payloads.md`: per-field precisions for the `dp-result@1`,
  `consortium-round@1` and `ingest-record@1` payloads; `presidio_ai.numeric` encodes them.
- Conformance tests against presidio-evidence's `canonical-json` and `signing` vectors
  (copied to `tests/vectors/`), and a 0.30.0-produced legacy ledger + approvals fixture.

### Changed
- All new hashes, ledger MACs and authorization requests use the strict canonical profile
  (`hashing.canonical_json`: floats rejected, `allow_nan=False`). Privacy parameters in
  signed payloads are half-even decimal strings, so new DP and consortium D4 content
  hashes differ from 0.30.0 for the same run (#68).
- New ledger entries and authorization requests carry `canon: 1`; the `mpa-authorized`
  entry records `request_canon`. Untagged entries and pre-0.31 approvals verify through the
  frozen `_legacy_canonical_v0`; nothing stored is rewritten. Removal tracked in #74.
- Ingest: the source commitment is sha256 over the input bytes as read; the scrubbed
  `content_hash` covers the `records-jsonl@1` bytes that `--out` now writes exactly
  (compact, sorted keys). Hash scopes are recorded. Ingest D1/D4 refs commit to the
  ingest record (`ingest-record@1`) rather than to the bare data hash.

### Fixed
- `__version__` reported 0.10.0 since v0.11.0, so `pai version` and the `source_version`
  field of every evidence record named the wrong release. It now matches the package
  (0.30.0), and a test pins it to `pyproject.toml` (#70).

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
