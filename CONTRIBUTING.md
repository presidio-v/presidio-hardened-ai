# Contributing to presidio-hardened-ai

Thanks for your interest. This project is held to a stricter bar than a typical library — the
checklist below is what a change needs to clear before it can be merged.

## Reporting a security vulnerability

**Do not open a public issue for a security vulnerability.** Use the private reporting
process in [SECURITY.md](SECURITY.md) — GitHub Security Advisories, via the repository's
"Security" tab, or contact security@presidio-group.eu. You will get an acknowledgement
within 5 business days.

## Reporting bugs and requesting features

Open a [GitHub issue](https://github.com/presidio-v/presidio-hardened-ai/issues). Search existing
issues first. For a bug, include:

- the installed version (`pip show presidio-hardened-ai` or `pai version`), the Python version,
  and which extras are installed (`[crypto]`, `[mpc]`, `[torch]`, `[zk]`, `[gate]`, `[nlp]`)
- what you expected to happen, and what happened instead
- a minimal reproduction if you can produce one

Please strip any secrets, credentials, ledger keys, or personal data from anything you paste
into a public issue. A ledger file holds no content, but its key does not belong in an issue.

## New to the project?

Issues labelled [`good first issue`](https://github.com/presidio-v/presidio-hardened-ai/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
are scoped to be approachable without deep knowledge of the codebase and are a good place to
start.

## How changes are made

All changes go through a pull request against `main`, and every PR must pass the CI checks
before it is merged.

1. Fork the repository and create a branch off `main`.
2. Make your change, with tests (see the test policy below).
3. Run the local verification block until it is clean.
4. Update `CHANGELOG.md` under `## [Unreleased]`.
5. Open a PR describing what changed and why.

## Code review

Every pull request — including a maintainer's own — is reviewed before it merges, by a code
owner ([CODEOWNERS](.github/CODEOWNERS)) who is **not** the author of the change. Branch
protection that enforces this on `main` (required review, code-owner review, stale-approval
dismissal, last-push re-approval, admins included) is being set up; until it is in place the
rule is applied by the maintainers.

What a reviewer confirms before approving:

- **Tests** — new or changed functionality ships with tests; bug fixes include a regression
  test.
- **Security reasoning** — for changes to a security-sensitive area (see below), the PR
  explains the reasoning, and no existing default is weakened without an explicit rationale.
- **Compatibility** — changes to the public API surface, the signed payload schemas, ledger
  entry shapes, CLI exit codes or exception types follow [SEMVER.md](SEMVER.md); breaking
  changes are called out.
- **Style and scope** — the linter is clean, the change is focused, and `CHANGELOG.md` is
  updated.

Reviewers approve via GitHub's review flow. A change that needs rework is returned with
specific requested changes rather than merged with caveats.

## Requirements for acceptable contributions

A change is merged when it meets all of the following.

### Style

Formatting and linting are enforced by the project linter and are not a matter of taste — CI
rejects anything that does not conform.

The linter and formatter is **ruff**, configured in `pyproject.toml`: line length 100, target
Python 3.11, rule sets `E`, `F`, `I`, `B`, `UP` and `S` (flake8-bandit security rules). `B008`
is ignored because Typer declares options in parameter defaults; `S101` is allowed in
`tests/` and `fuzz/`. A `# noqa: S...` on a line needs a reason on the same line.

Each module uses a single consistent import style. Do not mix conventions for the same
dependency within one module.

### Tests

**Test policy: any change that adds or modifies functionality must ship with tests in the
same pull request.** Bug fixes must include a regression test that fails before the fix and
passes after it. This is enforced in review.

Coverage: CI runs `pytest tests/ -x -q` and does not enforce a coverage floor today.
`pytest-cov` is in the `dev` extra, so `pytest --cov=presidio_ai` reports coverage locally.
Golden vectors are part of the test bar: `tests/vectors/` holds verbatim copies of
presidio-evidence's vectors (see `tests/vectors/PROVENANCE.txt`). Never edit them; new
vectors are copied in as new files. A change that alters a signed byte fails
`tests/test_canonical_conformance.py`.

### Security-sensitive changes

This project's security controls are the product. If your change touches any of the
security-sensitive modules, then the reviewer bar above applies in full:

- `src/presidio_ai/ledger.py`, `hashing.py`, `numeric.py`: the HMAC chain, canonical JSON
  and decimal strings (byte-stability contracts)
- `src/presidio_ai/evidence.py`, `provenance.py`, `gate_certificate.py`: what is signed and
  what admits a run
- `src/presidio_ai/pii.py`, `sanitize.py`, `security.py`, `cli.py`: the ingest boundary,
  input validation, the security log, key handling and exit codes
- `src/presidio_ai/dp/`: the accountant, the budget, n-of-m authorization and the trainers
- `src/presidio_ai/fl/secure_agg.py`, `commit.py`, `zk.py`, `proof_backend.py`,
  `_ristretto_backend.py`, `keyagreement.py`, `transport.py`, `consortium.py`, `god.py`,
  `robustness.py`, and `rust/src/`: the consortium protocol and its proofs
- `docs/schemas/signed-payloads.md` and `tests/vectors/`: the contract

For these:

- explain the security reasoning in the PR description, not only the mechanics
- do not weaken a default. New controls are opt-in; relaxations of existing controls need
  an explicit rationale
- never re-implement cryptographic primitives — call a vetted standard library or crypto
  dependency instead
- functions that produce a stable serialized or digest output are byte-stability contracts.
  Changing their output for existing input is a breaking change even if no signature changes
- a change to the accountant must keep the reported ε a sound upper bound; the torch lane
  cross-checks it against Opacus

### Public API and compatibility

The public API surface and what counts as a breaking change are defined in
[SEMVER.md](SEMVER.md). Read it before changing anything exported from the public API, and
note that the signed payload schemas, ledger entries, CLI exit codes and exception types are
part of the contract that downstream consumers depend on.

### Dependencies

New runtime dependencies are a high bar for a security-focused library and need justification
in the PR. The core depends on `typer` and `presidio-evidence` only. Prefer the standard
library. Optional functionality belongs in an optional dependency group (`[crypto]`, `[mpc]`,
`[torch]`, `[zk]`, `[gate]`, `[nlp]`) rather than the core dependency set.

## Local verification

Run this before opening a PR, and fix anything it reports:

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m ruff check . \
  && .venv/bin/python -m ruff format --check . \
  && .venv/bin/python -m pytest tests/ -x -q --tb=short
.venv/bin/pip-audit
```

CI runs this gate (lint, tests, `pip-audit`) on Python 3.11 and the test suite on 3.12 and
3.13. A change must pass on all of them.

### Optional lanes

These run in CI on pull requests to `main` and are worth running locally when you touch the
code they cover.

- **`[mpc]`** (`ci-mpc.yml`) — key agreement and the HTTP transport:

  ```bash
  .venv/bin/pip install -e ".[dev,mpc]"
  .venv/bin/python -m pytest tests/test_keyagreement.py tests/test_transport.py -q
  ```

- **`[torch]`** (`ci-torch.yml`) — the Opacus trainer and the cross-check of Opacus'
  accountant against `presidio_ai.dp.accountant`:

  ```bash
  .venv/bin/pip install -e ".[dev,torch]"
  .venv/bin/python -m pytest tests/test_opacus.py -q
  ```

- **`[zk]`** (`ci-zk.yml`, on changes to `rust/` or `src/presidio_ai/fl/`) — builds the
  native Ristretto255 + Bulletproofs backend with maturin and checks decision equivalence with
  the pure-Python MODP backend. Needs a Rust toolchain:

  ```bash
  .venv/bin/pip install maturin
  maturin build --release --locked -m rust/Cargo.toml --out dist
  .venv/bin/pip install dist/*.whl
  .venv/bin/python -m pytest tests/test_ristretto_backend.py tests/test_secure_consortium.py \
    tests/test_god.py tests/test_zk.py -q
  ```

- **Fuzzing** (`fuzz.yml`, Linux only: Atheris has no macOS wheel) — the Atheris harnesses in
  `fuzz/` cover ledger parsing and verification (`fuzz_ledger.py`) and the consortium wire
  format and input validators (`fuzz_wire.py`):

  ```bash
  .venv/bin/pip install -e ".[fuzz]"
  .venv/bin/python fuzz/make_corpus.py fuzz/corpus
  .venv/bin/python fuzz/fuzz_ledger.py fuzz/corpus -max_total_time=60
  .venv/bin/python fuzz/fuzz_wire.py fuzz/corpus -max_total_time=60
  ```

## Commit messages

Write in the imperative mood ("add anchor check", not "added" or "adds"). Explain *why* the
change is being made where that is not obvious from the diff.

## Licensing and Developer Certificate of Origin (DCO)

The project is MIT licensed, and contributions are accepted under the same
terms (inbound = outbound).

To assert that you have the right to submit your contribution, every commit must
be **signed off** under the [Developer Certificate of Origin](https://developercertificate.org/)
1.1. Signing off means adding a `Signed-off-by` line to the commit message with
your real name and email:

```
Signed-off-by: Jane Developer <jane@example.com>
```

`git commit -s` adds this line for you. By signing off you certify the DCO —
in short, that you wrote the change or otherwise have the right to submit it
under the project's MIT license. Pull requests whose commits are not signed off
will be asked to amend before merge.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
