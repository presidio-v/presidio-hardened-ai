# Security Assurance Case

This document is the assurance case for `presidio-hardened-ai`: an explicit argument
for why the project's security requirements are met. It has four parts, as
required by the OpenSSF Best Practices silver criterion `assurance_case`:

1. the threat model,
2. the trust boundaries,
3. the argument that secure design principles are applied, and
4. the argument that common implementation weaknesses are countered.

It is a summary that links to the authoritative detail in
[`SECURITY.md`](SECURITY.md) (controls, per-version threat models, known limits,
reporting) and [`ARCHITECTURE.md`](ARCHITECTURE.md) (components, flow, boundaries) for
`presidio-v/presidio-hardened-ai`. Design decisions are in [`docs/adr/`](docs/adr/). Where
this document and SECURITY.md differ, SECURITY.md is authoritative.

## 1. Threat model

**Assets.** (a) The integrity of the privacy record: the ledger, the ε spend derived from
it, and the signed evidence that auditors and the governance spine rely on. A record that
understates spend, hides a run or claims a stronger guarantee than was computed is the
failure that matters. (b) The confidentiality of training data and of each consortium
party's individual update. (c) The soundness of the reported (ε, δ).

| Threat | Control |
|---|---|
| Editing, inserting, reordering or deleting an interior ledger entry without the key | HMAC-SHA256 chain over canonical bytes; `verify_chain` and `pai verify` fail on the first broken link (constant-time comparison). |
| Dropping trailing entries or the whole ledger to refund ε spend | Detected against an anchor: the live `Ledger` object (used by `EpsilonBudget`), `EpsilonBudget(anchor=…)`, or `pai verify --expect-entry SEQ:HEX` / `--min-entries N`. A missing ledger fails `pai verify`. |
| Stripping or swapping the canonicaliser tag to downgrade verification | `canon: 1` is inside the MAC; untagged and unknown tags fail closed. |
| Recording a weaker parameter than computed (float drift, `delta` rounded to 0) | Strict canonical JSON rejects floats; decimal strings at declared precisions; non-zero `delta`/`sample_rate` that would round to `"0"` refused. |
| Spending past the ε budget, or running a high-ε job without sign-off | Spend re-derived from the verified chain on every charge; over-budget charges refused; n-of-m approvals bound to job id and privacy parameters. |
| Replaying an approval onto another job or (ε, δ) | Approvals countersign the hash of the canonical request; a changed job or parameter changes the hash. |
| Forged or relabelled evidence | Ed25519 (default) or HMAC signatures over presidio-evidence's `{content_hash, signer}` message; `parents` inside the hashed content. |
| A training run naming a gate decision that did not admit it | `--gate-certificate` is verified by ikigov-assess against the operator's trust store and must be `OPEN`, before the ledger is opened for writing. |
| PII reaching a persisted artefact | Scrub on ingest; only hashes and counts are recorded; the security log is structural only. |
| A coordinator learning an individual party's update | Pairwise and self masks in an exact field; Shamir recovery fails closed below the threshold. |
| A coordinator substituting DH keys (MITM) | DH public keys Ed25519-signed under identity keys, checked against a local trust store. |
| A coordinator lying about dropouts to unmask a live party | ≥ t Ed25519 party signatures over the survivor set before any recovery share; honest parties sign one set per attempt. |
| A malicious dealer, a false aggregate | Feldman VSS share checks; Pedersen homomorphic check of the returned aggregate; abort. |
| An out-of-norm (poisoning) update hidden by secure aggregation | ZK L∞ or L2 bounded-norm proofs verified against the input commitments before aggregation. |
| A minority denying service | GOD path: honest-majority robust reconstruction excludes bad dealers and holders; exclude-and-retry for the abort path. |
| A forged or replayed wire message | Every submission and command Ed25519-signed by the sender; one submission per party; one aggregate per round. |

**Out of scope and known limits** (documented, not assumed away; detail in SECURITY.md):

- **The ledger key holder is trusted.** Whoever holds the key can rewrite the whole chain.
  Only signed exports held by others constrain that, and suffix truncation is detectable
  only against an anchor known from elsewhere.
- **HMAC is a shared secret.** With `--algorithm hmac-sha256` the CLI signs evidence with
  the ledger key, so a verifier that holds it can also write ledger entries. n-of-m
  approvals are HMACs, so whoever holds the approver key store can forge an approval.
  Ed25519 is the default for evidence.
- **PII detection has recall limits.** It favours precision. `nlp` mode falls back to the
  regex detector when the `[nlp]` extra is absent. Differential privacy is the backstop
  for training, not for the scrubbed output itself.
- **DP noise randomness.** Called as a library, the reference trainer draws noise from a
  seeded PRNG unless `secure_rng=True`; the `pai` CLI uses the CSPRNG unless `--seed` is
  given (since 0.32.1). Production DP needs the CSPRNG or the Opacus backend with
  `secure_mode`. Noise is sampled in floating point and is not
  hardened against floating-point attacks on the Gaussian sampler.
- **Accounting assumptions.** The bound assumes Poisson subsampling at `sample_rate` and
  per-step clipping. Across jobs the budget uses basic composition, which is sound but
  loose.
- **Consortium trust premises.** The `pai consortium-round` CLI and
  `run_consortium_round` are the ADR-0001 in-process reference (honest-but-curious
  coordinator, ≤ t colluding parties). The malicious-secure round gives
  integrity-or-abort, not liveness; a cheater can force an attributable abort. GOD holds
  only under an honest majority (`n ≥ 2t+1`). Survivor-set equivocation is provable only
  by someone who obtains both signed sets.
- **Norm proofs.** The L∞ gate bounds poisoning but does not prove DP sensitivity
  (`sensitivity_proven = false`); only the L2 gate does, and only when `l2_bound` equals the
  clip norm the noise was calibrated to.
- **In-norm backdoors.** The robustness gate contains and attributes; a stealthy backdoor
  that does not move the validation or canary metrics can pass. The consortium owns the
  validation set and canaries.
- **Exclude-and-retry leak.** Comparing aggregates before and after an exclusion reveals
  the excluded (attributed) party's update.
- **Transport deployment.** TLS, bind address, request size limits and rate limiting of
  `serve()` are deployment configuration.
- **Timestamps** in ledger entries and evidence are claims, not trusted time.

## 2. Trust boundaries

The boundary names match [ARCHITECTURE.md](ARCHITECTURE.md#trust-boundaries).

- **Data source → ingest** (input validation, the primary boundary for data). Paths and
  identifiers are bounded and checked; records are scrubbed; only hashes and counts cross
  into the ledger and evidence.
- **Operator → ledger file and key** (integrity, secret input). The chain is verified on
  every budget read and by `pai verify`; the key comes from an option or environment
  variable and is never persisted by the library.
- **Library → ledger, evidence, security log** (egress). Commitments only; the security
  log carries event names, counts and flags.
- **Producer → evidence → verifier** (integrity). Signatures over the presidio-evidence
  signing message; for Ed25519, verifiers hold public keys only.
- **Gate issuer → `--gate-certificate`** (input validation). Bounded file reads, then
  ikigov-assess verification and an `OPEN` decision, before side effects.
- **Approvers → n-of-m authorization** (input validation). Countersignatures checked
  against the local approver key store.
- **Party ↔ party ↔ coordinator** (input validation and confidentiality). Signed DH keys
  and messages, canonical field elements, signed survivor sets, VSS, commitments and ZK
  proofs, under the per-path threat models above.
- **Transport server → network** (exposure). Loopback by default; hardening is the
  deployer's.
- **Python → native `[zk]` backend** (integrity of proofs). Decision equivalence with the
  MODP backend is checked in CI.

## 3. Secure design principles applied

- **Fail-safe defaults / secure by default.** Ledger verification, budget reads,
  authorization, gate certificates, VSS checks, proof verification and the wire decoder
  all raise or refuse on bad input; none returns a pass by default. A keyed MAC is
  mandatory. Ed25519 is the default evidence algorithm. Since 0.32.0 the legacy
  float-tolerant encoder is gone, so untagged records fail closed. Refusals happen before
  side effects: an over-budget, unauthorised or ungated charge writes nothing. Two defaults
  are not production-safe and are documented as such: the seeded PRNG of the reference
  trainer's library API (the CLI defaults to the CSPRNG) and the HMAC option for evidence.
- **Complete mediation.** Every charge goes through `EpsilonBudget.charge`, which re-verifies
  the chain before computing spend. `pai verify` and the budget use the same
  `verify_chain`. In the malicious-secure round, every survivor's contribution passes the
  survivor-set check, the commitment, the optional norm gate and the aggregate check
  before any governance side effect.
- **Least privilege.** The library holds no long-lived keys of its own; ledger, signing,
  approver and identity keys are supplied by the operator. The ledger file is created
  `0600` and its directory `0700`. Persisted artefacts hold commitments, not content. The
  coordinator sees only masked vectors and the aggregate, and survivor-set verification
  needs public keys only.
- **Defense in depth.** Independent controls cover distinct threats: the MAC chain,
  anchors, the `canon` tag, decimal strings, n-of-m approval and gate certificates on the
  ledger side; masking, signed key agreement, signed survivor sets, VSS, homomorphic
  checks, ZK norm proofs, the robustness gate and per-client DP on the consortium side.
- **Economy of mechanism.** Canonical JSON, the evidence signing message and Ed25519 come
  from presidio-evidence (Ed25519 via `cryptography`); HMAC-SHA256, SHA-256 and the CSPRNG
  from the Python standard library; X25519, HKDF and Ed25519 for the consortium from
  `cryptography`; the native backend wraps the dalek `bulletproofs` and `curve25519-dalek`
  crates. The MODP group is the RFC 3526 2048-bit safe prime, and its primality is
  re-checked in tests. The commitment, VSS and range-proof constructions in `fl/commit.py`
  and `fl/zk.py` are textbook schemes (Pedersen, Feldman, Chaum–Pedersen OR-proofs)
  implemented here in pure Python over that group, because no vetted Python library
  provides them. They are tested, including against the native backend for decision
  equivalence, but have not had an independent cryptographic review.

## 4. Common implementation weaknesses countered

| Weakness class | How it is countered | Checked by |
|---|---|---|
| Improper input validation (CWE-20) | `sanitize.py` bounds identifiers and paths and rejects control and NUL bytes; silo ids are a single filename component; ledger lines are type-checked field by field; `parents` and `--expect-entry` are lowercase-hex checked; the wire decoder accepts canonical field elements of the expected length only; gate files are bounded regular UTF-8 JSON. | Unit tests; Atheris harnesses `fuzz_ledger.py` and `fuzz_wire.py`; CodeQL |
| Path traversal (CWE-22) | A silo id that becomes a per-silo ledger filename must match `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. | Unit tests; CodeQL |
| Injection (CWE-74, CWE-78, CWE-89) | No shell, SQL or template evaluation in the package. | ruff `S` rules; CodeQL |
| Log injection and sensitive data in logs (CWE-117, CWE-532) | The security log is written as JSON records of event names, counts and flags; no paths, content, keys or `ledger_ref` values. | Review; `test_security.py` (structural event shape) |
| Memory safety (CWE-119 family) | Python is memory-safe. The Rust crate contains no `unsafe` blocks of its own; PyO3 generates the FFI glue. | `ci-zk` lane |
| Cryptographic misuse (CWE-327, CWE-330, CWE-347) | Vetted primitives for hashing, MACs, signatures and key agreement; constant-time MAC comparison; CSPRNG (`secrets`) for seeds, blindings and proof randomness; Fiat–Shamir transcripts bind the group, commitment, bound and every bit commitment; HKDF info domain-separates seeds per session. Seeded PRNGs remain in the reference trainer default and `SecureSumAggregator`, marked `noqa: S311` with a reason. | ruff `S` (S311 and others); CodeQL; golden vectors; `ci-zk` decision-equivalence tests |
| Integer and numeric errors (CWE-190, CWE-681) | Masking is exact in GF(2⁶¹−1); fixed-point range documented; L2 proofs require `dim·B² < q` so squares cannot wrap; decimal strings avoid float round-trips in signed data. | Unit tests |
| Hard-coded or exposed secrets (CWE-798) | No secrets in code. The keys in `tests/vectors/` are published test fixtures (see SECURITY.md). Secret scanning and push protection are enabled on the repository. | GitHub secret scanning; ruff `S105`/`S106` |
| Insecure permissions (CWE-732) | Ledger file `0600`, directory `0700`; security log `0600`. | Unit tests |
| Cleartext transmission (CWE-319) | Not countered in code: `serve()` speaks plain HTTP and binds loopback by default. Message integrity and party authentication come from Ed25519 signatures, and the masked vectors reveal nothing individually, but TLS is the deployer's. | Documented limit |
| Unsafe deserialization (CWE-502) | Only `json.loads`; no pickle, YAML or object hooks. Floats rejected from canonical payloads; non-finite numbers rejected in gate files. | ruff `S` (S301, S506); CodeQL |
| Uncaught exceptions as a pass (CWE-755) | Verification paths raise typed errors (`LedgerError`, `TransportError`, `ProofError`, …) that the CLI maps to non-zero exits; the round coordinator answers every payload with a status code. | Atheris harnesses; CLI tests |
| Vulnerable dependencies (CWE-1104) | Two core runtime dependencies (`typer`, `presidio-evidence`); everything else is an optional extra. `pip-audit` runs in CI over the `dev` install (core, `cryptography`, the `[mpc]` server stack and ikigov-assess; not `[torch]` or `[nlp]`). Dependabot covers pip and GitHub Actions. Release, fuzz and SBOM toolchains are hash-pinned. The Rust crate's dependencies are pinned by `Cargo.lock` but not covered by Dependabot or `cargo audit` today. | `pip-audit`; Dependabot; OpenSSF Scorecard |

These classes are checked continuously: **CodeQL** (Python) on every push and pull request
to `main` and weekly; **ruff** with the `S` (flake8-bandit) security rule set as a required
CI step; `pip-audit` in CI; **OpenSSF Scorecard** weekly and on every push to `main`; and
**Atheris** fuzz harnesses over ledger parsing and verification and over the consortium wire
format and input validators, on pull requests that touch the source and weekly. The
`[mpc]` and `[torch]` lanes run on every pull request to `main`, the `[zk]` lane on pull
requests that touch `rust/` or `src/presidio_ai/fl/`. CI does not enforce a
coverage floor today, and there is no Rust static analysis (`clippy`, `cargo audit`) in CI.

**Reviews.** Before publication the code had a security review in two passes, with a
follow-up review of its findings; the fixes shipped in 0.32.0, and two further findings were fixed in 0.32.1 under
published security advisories (see the **Security** sections of [CHANGELOG.md](CHANGELOG.md)). That review was tool-assisted and run by the maintainer; it
is not an independent third-party review. A required second-person code-owner review on
`main` is being set up.

## Conclusion

The threats above are each matched to a control; the controls sit at explicit
trust boundaries; the design follows fail-safe, least-privilege, complete-
mediation, defense-in-depth, and economy-of-mechanism principles; and the common
implementation weakness classes are countered by design and checked by automated
analysis. The project's stated security requirements are therefore met, subject
to the documented out-of-scope assumptions and known limits above, in particular the
trusted ledger key holder, the per-path consortium trust premises, the seeded library default of
the reference trainer, and the absence of an independent cryptographic review of the
pure-Python commitment and proof code.
