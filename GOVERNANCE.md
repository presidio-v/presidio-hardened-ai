# Project Governance

`presidio-hardened-ai` is developed and maintained by **PRESIDIO Group**
and published under the `presidio-v` GitHub organisation. This document
describes how the project is governed, who holds which responsibilities, and how
the project continues to function if any single individual becomes unavailable.

## Governance model

The project follows a **maintainer-led, single-steward** model.
PRESIDIO Group is the steward organisation: it owns the repository,
the release infrastructure, and the published artefacts, and it sets the security
bar the project is held to.

Day-to-day technical decisions are made by the maintainers by rough consensus:

- **Ordinary changes** (bug fixes, tests, documentation, dependency floors) are
  decided by the reviewing maintainer on the pull request.
- **Security-relevant changes** (anything touching the project's
  security-sensitive modules, listed below) require an explicit security
  rationale in the pull request and must not weaken an existing default. See
  [CONTRIBUTING.md](CONTRIBUTING.md#security-sensitive-changes).
  For this project they are:
  - the lineage ledger and its primitives: the HMAC chain and its verification
    (`ledger.py`), canonical JSON and keyed MACs (`hashing.py`), decimal-string
    encoding of privacy parameters (`numeric.py`);
  - signed evidence: `EvidenceRef` signing and the hashed evidence content
    (`evidence.py`), provenance `parents` (`provenance.py`), gate-certificate
    verification (`gate_certificate.py`);
  - the ingest boundary: PII detection and scrubbing (`pii.py`), input validation
    (`sanitize.py`), the structural security log and session guard (`security.py`),
    and the `pai` CLI, its key handling and exit codes (`cli.py`);
  - differential privacy: the accountant (`dp/accountant.py`), the ledger-backed
    budget (`dp/budget.py`), n-of-m authorization (`dp/authorization.py`) and the
    DP-SGD trainers (`dp/trainer.py`);
  - the consortium protocol: secure aggregation (`fl/secure_agg.py`), Pedersen
    commitments and Feldman VSS (`fl/commit.py`), zero-knowledge norm proofs and
    their backends (`fl/zk.py`, `fl/proof_backend.py`, `fl/_ristretto_backend.py`,
    `rust/src/`), key agreement (`fl/keyagreement.py`), the wire format and round
    coordinator (`fl/transport.py`), round composition (`fl/consortium.py`),
    guaranteed output delivery (`fl/god.py`) and the robustness gate
    (`fl/robustness.py`);
  - the signed payload schemas (`docs/schemas/signed-payloads.md`) and the pinned
    golden vectors (`tests/vectors/`).
- **Public-API and compatibility changes** are governed by [SEMVER.md](SEMVER.md);
  a breaking change requires a major/minor bump per the documented policy.
- **Disagreements** that cannot be resolved on the pull request are escalated to
  the steward organisation (PRESIDIO Group), whose decision is final.

There is no pay-to-play influence: contribution weight is earned through review
history and sustained, high-quality contribution, not funding.

## Roles and responsibilities

| Role | Held by | Responsibilities |
|---|---|---|
| **Steward organisation** | PRESIDIO Group (`presidio-v` GitHub org) | Owns the repository and release infrastructure; holds and can recover all release credentials; final escalation authority; ensures continuity (see below). |
| **Maintainer** | PRESIDIO Group engineering | Reviews and merges pull requests; enforces the test, style, and security bars; cuts releases; triages issues; is the point of accountability for the codebase. |
| **Security contact** | PRESIDIO Group security | Receives and triages private vulnerability reports (see [SECURITY.md](SECURITY.md)); coordinates fixes, advisories, and reporter credit. Reachable at `security@presidio-group.eu` and via GitHub Security Advisories. |
| **Release manager** | PRESIDIO Group engineering | Owns the signed-tag release flow; verifies provenance and SBOM attach on each release. |
| **Contributor** | Anyone | Opens issues and pull requests under [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). |

Roles are held by function within PRESIDIO Group rather than being
tied to one named individual, so responsibilities transfer without a change to
this document.

## Becoming a maintainer

A contributor with a sustained track record of merged, high-quality changes —
particularly to the security-sensitive modules — may be invited by the steward
organisation to become a maintainer. Maintainership is granted by
PRESIDIO Group and recorded by adding the person to the
`presidio-v` organisation with the appropriate repository role.

## Project continuity

The project is structured so that it continues to function — issues can be
triaged and closed, contributions can be reviewed and accepted, and new versions
can be released — within one week even if any single individual becomes
unavailable. This is a property of the **organisation**, not of any one person:

- **Repository ownership** is held by the `presidio-v` GitHub organisation,
  not by a personal account. Organisation owners can grant repository and release
  access to another member at any time.
- **Release credentials are not personal.** Publishing uses GitHub **Trusted
  Publishing (OIDC)** bound to the `presidio-v/presidio-hardened-ai` repository and a
  gated `release` environment — there is no personal API token that dies with an
  individual. The release signing key is held in the organisation's password
  manager (custody ultimately with PRESIDIO Group's leadership), not
  solely on any one contributor's machine, so it is recoverable.
- **The release process is documented** in
  [SECURITY.md](SECURITY.md#verifying-releases-and-obtaining-public-signing-keys)
  and `.github/workflows/publish.yml`: bump the version, date the `CHANGELOG.md`
  entry, merge the release pull request, push a signed tag (`git tag -s vX.Y.Z`),
  and a maintainer approves the `release` environment before the publish job runs.
  The `release` environment has one required reviewer today. A second release
  reviewer and the two-person code-owner review gate on `main` are being set up.
  Any authorised PRESIDIO Group engineer can cut a release by following the
  process.
- **Access is covered by an organisation policy.** PRESIDIO Group's access
  policy for the GitHub organisation and the password manager provides
  emergency access (Bitwarden Emergency Access): a designated PRESIDIO Group
  trustee can take over the organisation-owner credentials and the release
  signing key if the owner becomes unavailable, and then grant organisation
  ownership, code-owner review and `release`-environment approval to another
  member.
- **PRESIDIO Group is a staffed organisation** with more than one
  person able to assume the maintainer, security-contact, and release-manager
  roles above.

The project's bus factor is therefore backed by the steward organisation rather
than a lone maintainer.
