---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — SILVER level (on top of passing)
project_url: https://github.com/presidio-v/presidio-hardened-ai
related:
  - cii-passing-answers.md
---

# CII Best Practices — SILVER answer sheet

Answers for the **silver** tab at bestpractices.dev, filled from the evidence in
this repository on 2026-11-03. It covers only the criteria silver *adds* on top of
passing; passing answers carry over unchanged (see `cii-passing-answers.md`).

Before submitting silver: earn the passing badge first. The project is registered
as [project 16301](https://www.bestpractices.dev/projects/16301) and the badge is
on the README.

Each row shows the **Status** to set in the dropdown and the **Justification** to
paste. `REPO` = `https://github.com/presidio-v/presidio-hardened-ai`.

## Badge embed

Silver uses the **same** embed code as passing; the badge image renders the
current level. It is on the README:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16301/badge)](https://www.bestpractices.dev/projects/16301)
```

## Backing docs

- `GOVERNANCE.md` — governance model, roles, continuity
- `ARCHITECTURE.md` — components, core flows, trust boundaries
- `ASSURANCE.md` — consolidated security assurance case (`assurance_case`)
- `allowed_signers` — public release signing key for local tag verification
- `CONTRIBUTING.md` — DCO sign-off requirement, test policy, style
- `SECURITY.md` — reporting, reporter credit, release verification, threat model
- `README.md` — 12-month roadmap + links to GOVERNANCE/ARCHITECTURE/ASSURANCE

---

## Governance & continuity

| Criterion | Status | Justification to paste |
|---|---|---|
| `dco` | **Met** | Contributions must carry a DCO `Signed-off-by` line (`git commit -s`), documented at `REPO/blob/main/CONTRIBUTING.md#licensing-and-developer-certificate-of-origin-dco`; checked in review (there is no automated DCO check). Inbound = outbound `MIT`. The requirement was adopted in November 2026; earlier commits by the maintainer predate it. |
| `code_of_conduct` | **Met** | Contributor Covenant at `REPO/blob/main/CODE_OF_CONDUCT.md` (standard location). |
| `governance` | **Met** | Maintainer-led, single-steward model documented at `REPO/blob/main/GOVERNANCE.md`: ordinary changes decided on the PR, security-relevant changes (the listed security-sensitive modules, signed payload schemas and vectors) need a written rationale and may not weaken a default, API changes follow `SEMVER.md`, disagreements escalate to PRESIDIO Group. |
| `roles_responsibilities` | **Met** | Key roles (steward org, maintainer, security contact, release manager, contributor) documented at `REPO/blob/main/GOVERNANCE.md#roles-and-responsibilities`. |
| `access_continuity` | **Met** | Continuity rests on the steward organisation: the repository is owned by the `presidio-v` GitHub organisation, not a personal account; PyPI publishing uses Trusted Publishing bound to this repository and the `release` environment, so no personal API token exists; the release signing key is held in the organisation password manager, with its public half in `allowed_signers`; PRESIDIO Group's access policy provides emergency access (Bitwarden Emergency Access) so a designated trustee can take over the owner credentials and signing key and reassign ownership, code-owner review and `release` approval; the release procedure is written down (`SECURITY.md`, `.github/workflows/publish.yml`); and a second person (`ceoofcyber`) holds write access, code-owner review and `release`-environment approval. URL: `REPO/blob/main/GOVERNANCE.md#project-continuity`. |
| `bus_factor` (SHOULD) | **Met** | Two people review, merge and approve releases (`vstantch`, `ceoofcyber`, both code owners and `release`-environment reviewers, with self-review prevented); repository ownership, the signing key and the release flow are organisation-held, documented, and covered by the emergency-access policy. See `REPO/blob/main/GOVERNANCE.md#project-continuity`. |

## Documentation

| Criterion | Status | Justification to paste |
|---|---|---|
| `documentation_roadmap` | **Met** | `REPO#roadmap` — next 12 months to 2027-Q4: now (OpenSSF silver, hash-pinned CI installs, Rust `clippy` and `cargo audit` in the `[zk]` lane), next (first production build and benchmarks of the `[mpc]` and `[zk]` lanes), later (the items ADR-0007 defers: a per-party cosine-band ZK increment and robust aggregation under MPC). |
| `documentation_architecture` | **Met** | `REPO/blob/main/ARCHITECTURE.md` — components (ledger, ingest, DP accountant and budget, authorization, trainers, federated and consortium rounds, secure aggregation, commitments and proofs, transport, evidence), the DP-charge and consortium-round flows, trust boundaries; linked from the README. |
| `documentation_security` | **Met** | `REPO/blob/main/SECURITY.md` (threat model per component, invariants, reporting, release verification), `REPO/blob/main/ASSURANCE.md` (threat table, out-of-scope assumptions, design and weakness arguments), `REPO/blob/main/ARCHITECTURE.md#trust-boundaries`, and the design rationale in `docs/adr/` (seven accepted ADRs). |
| `documentation_quick_start` | **Met** | README *Installation* (`pip install presidio-hardened-ai`, extras), *Quick start* (scrub a source, record lineage, export signed evidence, verify the ledger) and the DP and federated examples, each with the expected output. |
| `documentation_current` | **Met** | Docs are updated in the same PR as the code they describe (`CHANGELOG.md` per version, `SEMVER.md` public API, ADRs, `PRESIDIO-REQ.md` delivery status), and the README, `SECURITY.md` and `ASSURANCE.md` describe the current 0.32 line, including the 0.32.1 CLI noise and authorization-order changes. |
| `documentation_achievements` | **Met** | The README front page shows and links the OpenSSF Best Practices badge (project 16301) next to the OpenSSF Scorecard badge; the badge image renders the current level, so a newly earned level appears without an edit. |

## Change control & reporting

| Criterion | Status | Justification to paste |
|---|---|---|
| `contribution_requirements` | **Met** | `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — style, tests, security-change rules, dependency bar. |
| `report_tracker` | **Met** | GitHub Issues: `REPO/issues`. |
| `maintenance_or_update` | **Met** | `REPO/blob/main/SECURITY.md#supported-versions` states which lines are supported (0.32.x; nothing earlier was published); `REPO/blob/main/SEMVER.md` documents what counts as a breaking change and the signed-payload stability rules; `MIGRATION.md` covers the 0.31 → 0.32 ledger change. |
| `vulnerability_report_credit` | **Met** | `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — reporters are credited in the advisory and the `CHANGELOG.md` entry for the fix unless they ask not to be. No external report has been received yet. |
| `vulnerability_response_process` | **Met** | `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — private GitHub Security Advisory or email intake, acknowledgement within 5 business days, fix target 30 days, fixes to signed payload schemas coordinated with the consuming verifiers before disclosure. Applied on 2026-11-03: two maintainer-found issues were fixed in a private advisory fork and released as 0.32.1 before GHSA-7rj4-g3c7-mgh2 and GHSA-hgv4-xx36-g3vf were published. |

## Quality & testing

| Criterion | Status | Justification to paste |
|---|---|---|
| `tests_documented_added` | **Met** | `REPO/blob/main/CONTRIBUTING.md#tests` states the policy that changes adding/modifying functionality ship with tests in the same PR. |
| `test_policy_mandated` | **Met** | Formal written policy at `REPO/blob/main/CONTRIBUTING.md#tests`: functionality changes ship with tests; bug fixes include a regression test that fails before the fix. Enforced in review (required code-owner review) and by the CI coverage floor. |
| `automated_integration_testing` | **Met** | `REPO/blob/main/.github/workflows/ci.yml` runs the full suite on every push and PR (full gate on Python 3.11 with coverage and `pip-audit`, tests on 3.12 and 3.13), including end-to-end CLI tests and the presidio-evidence golden vectors; `ci-mpc.yml`, `ci-torch.yml` and `ci-zk.yml` run the `[mpc]`, `[torch]` and native `[zk]` lanes; `fuzz.yml` runs the Atheris harnesses. |
| `regression_tests_added50` | **Met** | Policy requires a regression test with every bug fix. In the last 6 months the product-code fixes carry them: the pre-publication review fixes (PR #81, tests across ledger, budget, CLI, consortium, secure-aggregation, transport and ZK modules), the two 0.32.1 advisory fixes (7 tests, all failing on 0.32.0), the runtime version fix (PR #72), and the ledger-parsing and digest-comparison fixes in PR #83 (24 tests). The one fix without a test (PR #73) corrected README examples. |
| `test_statement_coverage80` | **Met** | CI gate: 85% statement coverage (`[tool.coverage.report] fail_under = 85` in `pyproject.toml`, applied by `pytest --cov=presidio_ai` in `.github/workflows/ci.yml`); measured 89.8% on 2026-11-03 in the base `dev` install. |
| `warnings_strict` | **Met** | ruff with `E`, `F`, `I`, `B`, `UP` and `S` (flake8-bandit); exclusions are documented in `pyproject.toml` (`B008` for Typer defaults, `S101` in `tests/` and `fuzz/`, `N802` in `fuzz/`). CI fails on any finding. |
| `coding_standards` | **Met** | `REPO/blob/main/CONTRIBUTING.md#style` — ruff (lint and format, configured in `pyproject.toml`: line length 100, target Python 3.11). The Rust crate has no enforced formatter or linter yet (on the roadmap). |
| `coding_standards_enforced` | **Met** | `ruff check` and `ruff format --check` run in CI on every PR inside the required `test` check. |
| `installation_common` | **Met** | `pip install presidio-hardened-ai` from PyPI, with optional extras (`[nlp]`, `[torch]`, `[mpc]`, `[crypto]`, `[gate]`). |
| `installation_development_quick` | **Met** | `REPO/blob/main/CONTRIBUTING.md#local-verification` — create a venv, `pip install -e ".[dev]"`, then the ruff and pytest commands; `maturin` and `cargo` commands for the `[zk]` lane. |
| `build_repeatable` (SHOULD) | **Met** | Both release files are bit-for-bit reproducible: on 2026-11-03, rebuilding `v0.32.1` from the tagged source (`git archive v0.32.1`, `uv build --sdist` with `.github/constraints/release-build.txt`) gave the PyPI sdist exactly (SHA-256 `27253779…`), and building the wheel from that sdist twice gave the PyPI wheel exactly (`6418df6a…`). Release builds use a hash-pinned backend and SHA-pinned Actions. |
| `build_standard_variables` | **N/A** | The distributed package is pure Python built by `hatchling`; no compiler or linker is invoked. The optional Rust `[zk]` extension is built locally by `maturin`/`cargo` and is not distributed on PyPI. |
| `build_preserve_debug` | **N/A** | No compiled artefacts are distributed; the wheel is pure Python (`py3-none-any`). |
| `build_non_recursive` | **N/A** | A single PEP 517 build; there is no make or subdirectory build. |
| `installation_standard_variables` | **N/A** | Installed via pip; `DESTDIR`-style conventions do not apply. |

## Dependencies & components

| Criterion | Status | Justification to paste |
|---|---|---|
| `external_dependencies` | **Met** | Listed machine-readably in `pyproject.toml` (runtime: `typer`, `presidio-evidence`; optional extras for NLP, torch, MPC, crypto and gate verification) and `rust/Cargo.toml` with `Cargo.lock`; release, fuzz and SBOM toolchains are hash-pinned in `.github/constraints/*.txt`. A CycloneDX SBOM of the runtime dependencies is generated, attested and attached to each release by `publish.yml`. |
| `updateable_reused_components` | **Met** | All reused components are PyPI or crates.io packages installed by the package manager (no vendored copies; `tests/vectors/` are verbatim test fixtures with recorded provenance); Dependabot tracks pip, cargo and GitHub Actions updates. |
| `interfaces_current` | **Met** | Dependencies are kept current by Dependabot (pip, cargo, Actions) with security updates enabled; ruff's `UP` rules flag outdated Python idioms. |

## Security

| Criterion | Status | Justification to paste |
|---|---|---|
| `assurance_case` | **Met** (URL required) | URL: `REPO/blob/main/ASSURANCE.md`. Threat model with out-of-scope assumptions and known limitations, trust boundaries matching `ARCHITECTURE.md#trust-boundaries`, the secure-design-principles argument and the common-weakness argument. It states that the pre-publication review was tool-assisted and run by the maintainer, and that the pure-Python commitment and proof code has had no independent cryptographic review. |
| `implement_secure_design` | **Met** | Fail-safe defaults: ledger, budget, authorization, gate certificates, VSS, proofs and the wire decoder all raise or refuse on bad input. Refusals happen before side effects: an over-budget, unauthorised or ungated charge writes nothing, and since 0.32.1 a consortium round is authorized before anything is computed. Complete mediation: every charge goes through `EpsilonBudget.charge`, which re-verifies the chain. Least privilege: `0600`/`0700` files, commitments-only ledger, plaintext transport only on loopback. Economy of mechanism: one canonical encoder (from presidio-evidence) for every hash, MAC and signature. See `REPO/blob/main/ASSURANCE.md#3-secure-design-principles-applied`. |
| `input_validation` | **Met** | All external input is untrusted: `sanitize.py` bounds and allow-lists identifiers and paths (length limits, no control/NUL bytes); ledger lines are type-checked field by field before verification; `decode_submission` validates party id, vector length and that every element is a canonical field element; gate certificates and approvals are verified against local trust stores. Failures raise before any state changes. See `ARCHITECTURE.md#trust-boundaries`. |
| `hardening` | **Met** | Ledger files `0600` in `0700` directories; a keyed MAC is mandatory; MAC and signature comparison is constant-time; `serve()` refuses plaintext HTTP beyond loopback and serves TLS with Python's defaults; structural-only security log (`~/.presidio-ai/security.log`); per-session operation limit (`PRESIDIO_AI_MAX_OPS`). Supply chain: SHA-pinned GitHub Actions with least-privilege `permissions:`, hash-pinned release toolchains, Trusted Publishing behind a two-reviewer `release` environment with self-review prevented, branch protection with required code-owner review, secret scanning with push protection. |
| `crypto_weaknesses` | **Met** | Security functions use SHA-256, HMAC-SHA256, Ed25519, X25519/HKDF-SHA256 and groups of at least 112-bit strength (RFC 3526 2048-bit MODP, Ristretto255); no MD5, SHA-1 or DES. |
| `crypto_algorithm_agility` (SHOULD) | **Met** | The evidence signature algorithm is selectable (`ed25519` default, `hmac-sha256`), and the commitment and proof backend is pluggable (native Ristretto255 + Bulletproofs when the `[zk]` extension is installed, otherwise the 2048-bit MODP backend; a call site can pass an explicit backend). The content-hash function (SHA-256) is fixed by the shared evidence wire format; replacing it would be a new schema major in presidio-evidence, not a runtime switch. |
| `crypto_credential_agility` | **Met** | No key is in the source tree (test keys under `tests/` are documented as test-only). The ledger key comes from `PRESIDIO_AI_LEDGER_KEY` or an explicit argument, signing keys from operator-supplied files, approver and identity trust stores from operator-supplied configuration, so every credential rotates without a new release. |
| `crypto_used_network` | **Met** | The only network component is the optional `[mpc]` coordinator `serve()`: it serves HTTPS when given `ssl_certfile`/`ssl_keyfile` and refuses to bind a non-loopback address without them (`check_bind`, tested in `tests/test_transport.py`). Every message is also Ed25519-signed end to end. |
| `crypto_tls12` | **Met** | `serve()` uses Python's TLS server defaults through uvicorn, whose minimum protocol is TLS 1.2 (`ssl.SSLContext(PROTOCOL_TLS_SERVER).minimum_version`, checked on Python 3.11). |
| `crypto_certificate_verification` | **N/A** | The package contains no TLS client. |
| `crypto_verification_private` | **N/A** | The package contains no TLS client. |
| `signed_releases` | **Met** | Wheel, sdist and CycloneDX SBOM carry GitHub build-provenance attestations (`gh attestation verify <file> --repo presidio-v/presidio-hardened-ai`), PyPI files carry PEP 740 attestations from Trusted Publishing, and release tags are SSH-signed with the public key in `REPO/blob/main/allowed_signers`. Documented at `REPO/blob/main/SECURITY.md#verifying-releases-and-obtaining-public-signing-keys`. Checked for `v0.32.0` and `v0.32.1` on 2026-11-03. |
| `version_tags_signed` | **Met** | Every release tag (`v0.32.0`, `v0.32.1`; earlier versions were never published or tagged) is SSH-signed with the organisation release key and shown as Verified on GitHub; `git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag <tag>` checks it locally. |
| `sites_password_security` | **N/A** | The project runs no site and stores no passwords. |

## Analysis & monitoring

| Criterion | Status | Justification to paste |
|---|---|---|
| `static_analysis_common_vulnerabilities` | **Met** | CodeQL for Python (`REPO/blob/main/.github/workflows/codeql.yml`) on every push/PR and weekly, and ruff's `S` (flake8-bandit) security rules in the required `test` check; OpenSSF Scorecard (`scorecard.yml`) weekly and on every push to `main`. |
| `dynamic_analysis_unsafe` | **N/A** | Python is memory-safe and the Rust `[zk]` extension has no `unsafe` blocks in `rust/src`. The Atheris harnesses (`fuzz/`, `fuzz.yml`) run regardless; their first CI run found a `TypeError` in digest comparison, fixed in PR #83. |
| `dependency_monitoring` | **Met** | Dependabot (pip, cargo, GitHub Actions) with security updates enabled; `pip-audit` on every push and PR (`ci.yml`); OpenSSF Scorecard weekly. |

## Accessibility & internationalization

| Criterion | Status | Justification to paste |
|---|---|---|
| `accessibility_best_practices` | **N/A** | A library and a command-line tool with no graphical or end-user UI; CLI output is plain text or JSON. |
| `internationalization` | **N/A** | No user-facing localizable UI; CLI messages are short English diagnostics for developers and operators. |

---

## Notes

- Any silver criterion **not** listed here carries over unchanged from the passing
  sheet.
- `bus_factor`, `build_repeatable` and `crypto_algorithm_agility` are SHOULD
  criteria.
- Rust static analysis (`clippy`, `cargo audit`) is not in CI yet; it is on the
  roadmap and is not claimed above.
