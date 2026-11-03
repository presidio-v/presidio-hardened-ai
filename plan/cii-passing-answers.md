---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — passing level
project_url: https://github.com/presidio-v/presidio-hardened-ai
---

# CII Best Practices — passing-level answer sheet

Answers for <https://www.bestpractices.dev> (passing level), filled from the evidence in
this repository on 2026-11-03 for [project 16301](https://www.bestpractices.dev/projects/16301).

## Before you start

1. **Register the URL as exactly** `https://github.com/presidio-v/presidio-hardened-ai`.
   Scorecard does a literal DB string match. A trailing slash, `www.`, or the
   package-index URL returns `NotFound` → score 0 despite a real badge.
2. **Log in with GitHub but decline the org grant.** BadgeApp requests `read:org`
   and no code path consumes it. Entry ownership is internal to its database.
3. **Confirm the community-health and process docs are on `main` first** —
   `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`,
   `SEMVER.md`. Every URL cited below must resolve on `main` before you answer.
4. Record your badge id in `hardening.toml` (`[badge] bestpractices_id`) once the
   project is created; this sheet's silver counterpart references it as
   `16301`.

Shorthand below: `REPO` = `https://github.com/presidio-v/presidio-hardened-ai`.

---

## Basics — project website content

| Criterion | Status | Justification / URL |
|---|---|---|
| `description_good` | **Met** | `REPO#readme` — the README opens with what the package does (training-time privacy controls: PII scrubbing, a tamper-evident lineage ledger, DP-SGD accounting and ε-budgets, n-of-m authorization, federated and secure-aggregation rounds) and the problem it solves (governance evidence for a training job that a verifier can check rather than trust). |
| `interact` | **Met** | `REPO#readme` — README covers obtaining (presidio_ai on the package index), feedback (issues), security reports (`SECURITY.md`), and contributing. |
| `contribution` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md` — documents the fork → branch → PR flow against `main`. |
| `contribution_requirements` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — style config, test policy, security-change rules, dependency bar. |

## Basics — FLOSS license

| Criterion | Status | Justification / URL |
|---|---|---|
| `floss_license` | **Met** | `MIT`. |
| `floss_license_osi` | **Met** | `MIT` is OSI-approved. |
| `license_location` | **Met** | URL: `REPO/blob/main/LICENSE` |

## Basics — documentation

| Criterion | Status | Justification / URL |
|---|---|---|
| `documentation_basics` | **Met** | README sections *Installation* (pip extras), *Quick start*, *Differential-privacy accounting & budget*, *Federated learning across silos* and *Library*; `CONTRIBUTING.md#local-verification` for a development install. |
| `documentation_interface` | **Met** | The public Python API and the `pai` CLI (subcommands, options, exit codes, signed payload schemas) are enumerated in `REPO/blob/main/SEMVER.md`; the README *Library* section and the module docstrings document usage; `pai --help` documents every subcommand. |

## Basics — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `sites_https` | **Met** | The project runs no site of its own; GitHub and PyPI are HTTPS. |
| `discussion` | **Met** | GitHub Issues: `REPO/issues` — searchable, URL-addressable, open, no proprietary client. |
| `english` | **Met** | All docs and issue handling in English. |
| `maintained` | **Met** | Actively maintained: v0.32.0 (first public release, 2026-11-03) and v0.32.1 (security fix, 2026-11-03) on PyPI; weekly Dependabot and Scorecard runs. |

## Change control — repository

| Criterion | Status | Justification / URL |
|---|---|---|
| `repo_public` | **Met** | `REPO` |
| `repo_track` | **Met** | git. |
| `repo_interim` | **Met** | Feature and fix branches are pushed between releases; PR-based flow. |
| `repo_distributed` | **Met** | git. |

## Change control — versioning

| Criterion | Status | Justification / URL |
|---|---|---|
| `version_unique` | **Met** | Semver per release, tagged. |
| `version_semver` | **Met** | URL: `REPO/blob/main/SEMVER.md` — documents the semver profile. |
| `version_tags` | **Met** | Every release is a git tag, SSH-signed and GitHub-verified. |

## Change control — release notes

| Criterion | Status | Justification / URL |
|---|---|---|
| `release_notes` | **Met** | URL: `REPO/blob/main/CHANGELOG.md` — Keep a Changelog format, hand-written, not VCS log output. |
| `release_notes_vulns` | **Met** | `CHANGELOG.md` [0.32.1] names GHSA-7rj4-g3c7-mgh2 and GHSA-hgv4-xx36-g3vf (no CVEs assigned); [0.32.0] lists the pre-publication security fixes under *Security*. |

## Reporting — bug reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `report_process` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#reporting-bugs-and-requesting-features` |
| `report_tracker` | **Met** | GitHub Issues. |
| `report_responses` | **Met** | All issues so far were opened by the maintainer from the weekly review (for example #66, #70 and #71, opened 2026-10-10 to 2026-10-17 and fixed and closed 2026-10-18; #77 closed 2026-11-02). No external bug report has been received yet; the documented process (`CONTRIBUTING.md#reporting-bugs-and-requesting-features`) applies when one arrives. |
| `enhancement_responses` | **Met** | Enhancement requests so far came from the weekly review: #67 (provenance parents, shipped in 0.31.0) and #77 (verified `--gate-certificate`, shipped in 0.32.0). No external feature request has been received yet. |
| `report_archive` | **Met** | URL: `REPO/issues?q=is%3Aissue` — public and searchable. |

## Reporting — vulnerability reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerability_report_process` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` |
| `vulnerability_report_private` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — private GitHub Security Advisory via the Security tab; acknowledgement and patch targets stated. |
| `vulnerability_report_response` | **N/A** | No vulnerability has been reported externally. The two 2026-11-03 advisories (GHSA-7rj4-g3c7-mgh2, GHSA-hgv4-xx36-g3vf) were found by the maintainer and fixed in 0.32.1 the same day. |

## Quality — build system

| Criterion | Status | Justification / URL |
|---|---|---|
| `build` | **Met** | PEP 517 build with `hatchling`: `python -m build` (or `uv build`) rebuilds the sdist and wheel from source; the release job uses a hash-pinned backend (`.github/constraints/release-build.txt`, `--no-isolation`). |
| `build_common_tools` | **Met** | pip, `build`/`uv` and `hatchling`; `maturin` and `cargo` for the optional Rust `[zk]` extension. |
| `build_floss_tools` | **Met** | The entire toolchain is FLOSS. |

## Quality — automated test suite

| Criterion | Status | Justification / URL |
|---|---|---|
| `test` | **Met** | 37 pytest modules under `tests/` (ledger, sanitisation, DP accounting and budget, authorization, trainers, federated and consortium rounds, secure aggregation, ZK proofs, transport, evidence, CLI) plus the presidio-evidence golden vectors in `tests/vectors/`. |
| `test_invocation` | **Met** | `pytest tests/` (after `pip install -e ".[dev]"`). |
| `test_most` | **Met** | CI enforces an 85% statement-coverage floor (`[tool.coverage.report] fail_under = 85`, `pytest --cov=presidio_ai` in `ci.yml`); measured coverage is about 90%. End-to-end CLI tests run `pai` ingest → verify → evidence export. |
| `test_continuous_integration` | **Met** | GitHub Actions on every push and PR: full gate on Python 3.11 (lint, tests with coverage, `pip-audit`), tests on 3.12 and 3.13, plus the `[mpc]` and `[torch]` lanes and the native `[zk]` lane on PRs touching `rust/` or `src/presidio_ai/fl/`. |

## Quality — new functionality testing

| Criterion | Status | Justification / URL |
|---|---|---|
| `test_policy` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#tests` — written policy that functional changes ship with tests and fixes ship with regression tests. |
| `tests_are_added` | **Met** | PR #83 (`REPO/pull/83`): the new ledger fuzzer found that a non-ASCII `entry_hash` made `verify_chain` raise `TypeError`; commit a7c8b11 fixed `constant_time_equals` and added 8 regression tests (`tests/test_ledger.py`, `tests/test_evidence.py`, `tests/test_authorization.py`), 7 of which fail without the fix. |
| `tests_documented_added` | **Met** | The policy is stated in the contribution instructions themselves (`CONTRIBUTING.md#tests`). |

## Quality — warning flags

| Criterion | Status | Justification / URL |
|---|---|---|
| `warnings` | **Met** | ruff (lint and format) in CI; `ruff check` and `ruff format --check` are part of the required `test` check. |
| `warnings_fixed` | **Met** | CI fails on any finding; `main` is clean. |
| `warnings_strict` | **Met** | ruff rule sets `E`, `F`, `I`, `B`, `UP` and `S` (flake8-bandit), beyond the default `E`/`F`; exclusions are documented in `pyproject.toml`: `B008` (Typer's `Option()` defaults), `S101` in `tests/` and `fuzz/`, `N802` in `fuzz/`. |

## Security — secure development knowledge

| Criterion | Status | Justification / URL |
|---|---|---|
| `know_secure_design` | **Met** | The maintainer applies and documents secure design in `REPO/blob/main/ASSURANCE.md#3-secure-design-principles-applied`: fail-closed verification everywhere (ledger, budget, authorization, gate certificates, VSS, proofs, wire decoder), refusals before side effects, a mandatory keyed MAC, complete mediation through `EpsilonBudget.charge`, least privilege (`0600`/`0700` files, no network by default, plaintext transport only on loopback), and explicit trust boundaries (`ARCHITECTURE.md#trust-boundaries`). The pre-publication review was tool-assisted and run by the maintainer, not independent. |
| `know_common_errors` | **Met** | `ASSURANCE.md` maps common weakness classes (CWE-20 input validation, CWE-327/330/347 cryptographic misuse, CWE-319 cleartext transmission, CWE-1104 vulnerable dependencies, path and permission handling) to named countermeasures and the tests or tools that check them; `SECURITY.md` documents the threat model per component. |

## Security — cryptographic practices

<!-- If this project performs NO cryptographic operations of its own, most of these
are N/A — say so explicitly per row rather than leaving them blank. If it does,
resolve each FILL against the actual primitives used. -->

| Criterion | Status | Justification / URL |
|---|---|---|
| `crypto_published` | **Met** | SHA-256, HMAC-SHA256, Ed25519, X25519 + HKDF-SHA256 (`[mpc]`), Pedersen commitments and Schnorr-style / Bulletproofs range proofs over the RFC 3526 2048-bit MODP group or Ristretto255, Shamir and Feldman secret sharing. |
| `crypto_call` (SHOULD) | **Met** | Hashes and MACs come from `hashlib`/`hmac`, signatures and key agreement from `cryptography` (via presidio-evidence), the native proof backend from `curve25519-dalek`, `bulletproofs` and `merlin`. The commitment, secret-sharing and proof protocols are part of the project's purpose (verifiable secure aggregation) and are implemented over those standard groups; `ASSURANCE.md` states that this pure-Python protocol code has not had an independent cryptographic review. |
| `crypto_floss` | **Met** | All crypto libraries (Python stdlib, `cryptography`, `curve25519-dalek`, `bulletproofs`, `merlin`) are FLOSS. |
| `crypto_keylength` | **Met** | SHA-256, HMAC-SHA256 with keys from the operator, Ed25519/X25519 and Ristretto255 (~128-bit security), the 2048-bit MODP group (112-bit, NIST minimum through 2030). |
| `crypto_working` | **Met** | Confirmed: no MD4, MD5, single DES, RC4 or Dual_EC_DRBG anywhere in the code. |
| `crypto_weaknesses` | **Met** | Confirmed: no SHA-1 and no CBC mode; no encryption mode is used at all. |
| `crypto_pfs` | **N/A** | The package implements no transport-session protocol of its own; forward secrecy on the wire comes from TLS (Python's default ECDHE suites) when `serve()` is given a certificate. |
| `crypto_password_storage` | **N/A** | Confirmed: stores no user passwords. |
| `crypto_random` | **Met** | `secrets` (CSPRNG) for secure-aggregation seeds, commitment blindings and proof randomness; DP noise uses `secrets.SystemRandom` in the CLI and with `secure_rng=True` in the library. Seeded PRNGs remain only as documented test/library defaults (`ruff S311`, marked with reasons). |

## Security — delivery

| Criterion | Status | Justification / URL |
|---|---|---|
| `delivery_mitm` | **Met** | PyPI via Trusted Publishing (OIDC, no long-lived token) behind the reviewer-gated `release` environment; PEP 740 and GitHub build-provenance attestations on every file. |
| `delivery_unsigned` | **Met** | No hash is fetched over plain HTTP. Release tags are SSH-signed and GitHub-verified. |

## Security — known vulnerabilities

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerabilities_fixed_60_days` | **Met** | `pip-audit` on every push and PR (`ci.yml`), Dependabot (pip, cargo, Actions) with security updates; 0 open Dependabot and code-scanning alerts on 2026-11-03. |
| `vulnerabilities_critical_fixed` | **Met** | No critical vulnerability has arisen. The project's own high and medium advisories were fixed in 0.32.1 the day they were found, and the pyo3 Dependabot alerts were fixed before the first public release. |

## Security — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `no_leaked_credentials` | **Met** | Checked on 2026-11-03: no credential-shaped file (`.env`, `.pem`, `.key`, SSH keys) in any commit, a history-wide `git grep` for token and private-key patterns finds nothing, and GitHub secret scanning reports 0 alerts. Test keys under `tests/` are documented as test-only (`SECURITY.md#test-keys-in-this-repository`). |

## Analysis — static

| Criterion | Status | Justification / URL |
|---|---|---|
| `static_analysis` | **Met** | CodeQL for Python (`codeql.yml`) and ruff's `S` (flake8-bandit) security rules as part of the required `test` check. |
| `static_analysis_common_vulnerabilities` | **Met** | ruff `S` rules on every PR; OpenSSF Scorecard (`scorecard.yml`) on every push to `main` and weekly. |
| `static_analysis_fixed` | **Met** | Findings are triaged and fixed before release. |
| `static_analysis_often` | **Met** | CodeQL runs on every push and PR to `main`, plus a weekly scheduled run. |

## Analysis — dynamic

| Criterion | Status | Justification / URL |
|---|---|---|
| `dynamic_analysis` | **Met** | Atheris fuzz harnesses (`fuzz/fuzz_ledger.py` for the ledger parser and chain verifier, `fuzz/fuzz_wire.py` for the federated wire decoder and `RoundCoordinator`) run time-boxed in `fuzz.yml` on Linux / Python 3.12 on PRs and weekly. On its first run it found a `TypeError` in digest comparison, fixed in PR #83. |
| `dynamic_analysis_unsafe` | **N/A** | Python is memory-safe; the Rust `[zk]` extension is Rust with no `unsafe` blocks in `rust/src`. |
| `dynamic_analysis_enable_assertions` | **Met** | Confirmed: the pytest suite and the fuzz oracles are assertion-based and run with assertions enabled (no `-O`). |
| `dynamic_analysis_fixed` | **Met** | No unfixed medium+ findings. |

---

## Notes

- Any passing criterion not listed here is answerable **Met** by an existing
  rendered artefact or **N/A** (library vs. website/app). Check
  `SECURITY.md` / `CONTRIBUTING.md` / `ci.yml` before writing anything new.
- Silver (score 7) is generally **not** honestly reachable while a project is
  single-maintainer: `access_continuity` is a silver MUST requiring the project to
  survive the loss of any one person within a week, and `bus_factor`,
  `governance`, and `roles_responsibilities` share that root cause. A second
  person with org access and release capability resolves all four and also moves
  Scorecard's Code-Review check off 0. See the silver sheet for how the reference
  project answered these via organisational continuity rather than a lone
  maintainer.
