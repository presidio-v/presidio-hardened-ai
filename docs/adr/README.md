# Architecture Decision Records

Accepted ADRs for `presidio-hardened-ai`, in order. Each records the decision, the options
considered, and consequences, with per-version implementation status noted inline. The
per-version deliberation log is in [`../../PRESIDIO-REQ.md`](../../PRESIDIO-REQ.md) and the
release summary in [`../../CHANGELOG.md`](../../CHANGELOG.md).

| ADR | Title | Status | Built in |
|-----|-------|--------|----------|
| [0001](0001-multiparty-secure-aggregation.md) | Multi-party consortium training via secure aggregation | Accepted | v0.11.0–v0.14.0 |
| [0002](0002-malicious-security-hardening.md) | Malicious-security hardening (commitments + VSS + signed survivor-set) | Accepted | v0.16.0–v0.18.0 |
| [0003](0003-bounded-norm-input-validation.md) | Bounded-norm input validation via zero-knowledge | Accepted | v0.19.0–v0.20.0 |
| [0004](0004-ristretto-bulletproofs-backend.md) | Ristretto255 + Bulletproofs performance backend | Accepted | v0.21.0–v0.22.0 |
| [0005](0005-l2-bounded-norm.md) | L2 bounded-norm proofs (exact DP clip norm) | Accepted | v0.23.0–v0.24.0 |
| [0006](0006-guaranteed-output-delivery.md) | Guaranteed output delivery (honest-majority robust aggregation) | Accepted | v0.25.0–v0.27.0 |
| [0007](0007-byzantine-ml-robustness.md) | Byzantine-ML robustness against in-norm backdoors | Accepted | v0.30.0 |

All seven are accepted and built. The pure-Python paths are verified in the default CI lane;
the `[mpc]` and `[zk]` native lanes build on a Rust-equipped runner. Remaining open items in
individual ADRs' Action Items (dimension benchmarks, cross-platform wheels, the cosine-band ZK
increment, robust-aggregation-under-MPC) are operational or scoped-future, not pending decisions.
