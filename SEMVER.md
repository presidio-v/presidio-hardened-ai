# Stability & semver guarantees — presidio-hardened-ai

For downstream integrators depending on this project.

## What is the public API

The public API is:

- every name in `presidio_ai.__all__`, `presidio_ai.dp.__all__`, `presidio_ai.fl.__all__`
  and `presidio_ai.gate_certificate.__all__`, with its documented signature and return type;
- the exception types those names raise, at their defining modules:
  `presidio_ai.ledger.LedgerError`, `presidio_ai.hashing.CanonicalError`,
  `presidio_ai.sanitize.ValidationError`, `presidio_ai.provenance.ParentError`,
  `presidio_ai.pii.PIIBlockedError`, `presidio_ai.dp.accountant.AccountantError`,
  `presidio_ai.gate_certificate.GateCertificateError`, and the error classes exported from
  `presidio_ai.dp` and `presidio_ai.fl` (`BudgetExceeded`, `MPADenied`, `ConsortiumError`,
  `PartyMisbehavior`, `GODError`, `CommitmentError`, `ProofError`, `KeyAgreementError`,
  `TransportError`);
- the `pai` CLI: the subcommands `ingest`, `verify`, `dp-account`, `dp-authorize`,
  `dp-charge`, `dp-budget`, `dp-train`, `fl-train`, `consortium-round`, `keygen` and
  `version`, their options, and the exit codes:

  | Code | Meaning |
  |---|---|
  | 0 | success; for `verify`, the chain is intact (and matches `--expect-entry` / `--min-entries` when given) |
  | 1 | failure: a tampered, truncated or missing ledger, a missing key, invalid input, a refused gate certificate, or any other error |
  | 2 | the charge would exceed the ε budget (`dp-train`, `dp-charge`, `fl-train`, `consortium-round`) |
  | 3 | n-of-m authorization denied (`dp-charge`, `consortium-round`) |

  Typer also exits 2 on a command-line usage error, before any command runs. A caller that
  must tell the two apart reads stderr (`BUDGET EXCEEDED:` prefixes a budget refusal);
- the signed payload schemas in [`docs/schemas/signed-payloads.md`](docs/schemas/signed-payloads.md)
  (`dp-result@1`, `consortium-round@1`, `ingest-record@1`, ledger entries and authorization
  requests), the per-field precisions in `presidio_ai.numeric.PRECISION`, and the
  `EvidenceRef` field set.

Underscore-prefixed modules and names (`presidio_ai.fl._ristretto_backend` and the rest) are
internal. Module-level names that are not listed above (for example the helpers in
`presidio_ai.hashing` and `presidio_ai.numeric` other than the documented ones) are internal
and may change in a minor release. The Rust crate in `rust/` (`presidio_ai_zk`, versioned
separately, currently 0.1.0) is an implementation of the `[zk]` backend, reached only through
`presidio_ai.fl.proof_backend`; its Python module is not a public API.

## Versioning rules (semver, pre-1.0 profile)

- **Patch (0.x.Y):** bug fixes, security fixes, dependency floor bumps. No API
  change, no behaviour change except the fixed defect. Safe to auto-upgrade; this
  is the channel security releases ship on.
- **Minor (0.X.0):** additive API (new exports, new optional parameters with
  defaults, new optional extras). Existing code keeps working, including the
  documented public behaviour. Deprecations are announced here (docstring +
  CHANGELOG) at least one minor before any change.
- **Major (1.0.0+):** the only place deprecated surface may be removed.

Before 1.0 a minor release has removed a fail-open path without a deprecation cycle when
keeping it would have left a security hole (0.32.0 removed verification of untagged pre-0.31
ledger entries, see `MIGRATION.md`). Such a change is called out under **Changed** or
**Security** in `CHANGELOG.md` with migration steps.

**Pin guidance for integrators:** pin `presidio-hardened-ai` to the current minor
in production and run the verification step (below) in your CI on every upgrade.

## Behavioural guarantees (stronger than API stability)

These are security invariants, not just interfaces; weakening any of them is
treated as a breaking change regardless of which version component moves.

- **Fail-closed ledger verification.** `verify_chain` returns the entries only if every link
  holds. It raises `LedgerError` on a MAC mismatch, a non-contiguous `seq`, a `prev_hash`
  that does not match, an untagged or unknown `canon` tag, a malformed line or non-UTF-8
  file, a missing file (unless `missing_ok`), fewer than `min_entries` entries, or an
  `anchor` whose entry is absent or differs. `pai verify` exits 0 only when that call
  succeeds.
- **A keyed MAC is mandatory.** `Ledger` and `verify_chain` raise `LedgerError` when no key
  is given and `PRESIDIO_AI_LEDGER_KEY` is unset; there is no unkeyed mode. MAC comparison
  is constant-time.
- **The `canon` tag is covered by the MAC.** Every entry written carries `canon: 1`, inside
  the MAC, so it cannot be stripped or changed without breaking the chain. Authorization
  requests carry the same tag and an untagged request fails closed.
- **Strict canonical JSON.** Every content hash, ledger MAC, authorization request and
  signing message is computed over presidio-evidence's strict canonical profile. Floats and
  NaN are rejected at any depth (`CanonicalError`; `LedgerError` on `Ledger.append`).
  `canonical_json`, `sha256_hex` and the signing messages return the same bytes for the
  same input across releases.
- **Decimal-string privacy parameters.** Non-integer values in signed payloads are encoded
  once, at the producer, as plain-notation decimal strings rounded half-even to the
  field's declared precision. NaN and ±Infinity are rejected, and a non-zero `delta` or
  `sample_rate` that would round to `"0"` is refused rather than recorded as a stronger
  guarantee. Verifiers compare the strings byte-wise.
- **DP accounting does not under-report.** `dpsgd_epsilon` returns an upper bound on ε for
  the stated mechanism (Poisson-subsampled Gaussian, sensitivity 1 after clipping) and
  `delta`. Adding orders to the grid can only lower the minimum, never below a sound
  bound. The recorded decimal string can sit below the computed value by at most `5e-13`
  (half-even at 12 digits), which the budget's `1e-12` admission tolerance covers.
- **The budget is re-derived from the verified ledger.** `EpsilonBudget` sums recorded
  charges only after `verify_chain` passes, checked against the `Ledger` object's own
  tail and, when given, an external `anchor`. A tampered or truncated ledger raises
  instead of returning a spend figure. A charge over budget raises `BudgetExceeded`, and
  a charge that needs n-of-m approval and lacks it raises `MPADenied`; neither writes a
  ledger entry.
- **Approvals bind the job.** An n-of-m approval countersigns the hash of the canonical
  request (`canon`, `job_id` and the job's privacy parameters), so it does not verify for
  another job or another (ε, δ). Approvals are counted only for distinct, recognised
  approvers with a key in the local trust store.
- **Evidence signing uses the presidio-evidence wire format.** An `EvidenceRef` is signed
  over presidio-evidence's `{content_hash, signer}` signing message; Ed25519 is the
  default and HMAC-SHA256 remains available. Verification returns `False` for a wrong key,
  another signer or a changed hash. The pinned golden vectors in `tests/vectors/` hold
  these bytes.
- **Commitments only.** The ingest, DP and consortium producers in this package write
  hashes, counts, identifiers and privacy parameters to the ledger and to evidence, never
  record values or an individual party's update. The security log holds event names,
  counts and mode flags only.
- **Provenance is validated and hashed.** `parents` entries must be lowercase hex of 8 to
  128 characters; a malformed entry is refused before anything is written. They sit inside
  the hashed content, and a payload without parents hashes as it did before the field
  existed.
- **Gate certificates are verified before side effects.** With `--gate-certificate`, a
  certificate becomes a parent only after ikigov-assess's `verify_certificate` passes
  against `--gate-trust` and the recomputed decision is `OPEN`. Any refusal exits 1 before
  the ledger is opened for writing.
- **Consortium rounds fail closed.** Fewer than `threshold` survivors abort the round
  instead of reconstructing. A round over the L∞ gate records `sensitivity_proven = false`;
  only the L2 gate records `true`.

## Verifying an installation

Run this against the installed package. It checks the canonical encoding against the golden
vectors shipped inside presidio-evidence, and the fail-closed ledger and accountant paths:

```bash
pip install "presidio-hardened-ai==<version>"
python - <<'PY'
import json, tempfile
from pathlib import Path

from presidio_evidence import vectors_dir
from presidio_ai import Ledger, dpsgd_epsilon, verify_chain
from presidio_ai.hashing import CanonicalError, canonical_json
from presidio_ai.ledger import LedgerError

canon = json.loads((vectors_dir() / "canonical-json" / "vectors.json").read_text())
for case in canon["cases"]:
    assert canonical_json(case["payload"]) == case["canonical"].encode(), case["name"]
for case in canon["rejected"]:
    try:
        canonical_json(case["payload"])
    except CanonicalError:
        continue
    raise AssertionError(case["name"])

path = Path(tempfile.mkdtemp()) / "ledger.jsonl"
ledger = Ledger(path, key="smoke-test-key")
for i in range(3):
    ledger.append("smoke", {"n": i})
anchor = ledger.anchor
assert len(verify_chain(path, key="smoke-test-key", anchor=anchor)) == 3
path.write_text("\n".join(path.read_text().splitlines()[:2]) + "\n")  # drop the last entry
for kwargs in ({"key": "smoke-test-key", "anchor": anchor}, {"key": "wrong-key"}):
    try:
        verify_chain(path, **kwargs)
    except LedgerError:
        continue
    raise AssertionError(kwargs)

result = dpsgd_epsilon(noise_multiplier=1.1, sample_rate=0.01, steps=1000, delta=1e-5)
assert 0 < result.epsilon < 10 and isinstance(result.signed_dict()["epsilon"], str)
print("ok")
PY
```

A passing run prints `ok`. For a release artefact, also verify its provenance:
`gh attestation verify <wheel> --repo presidio-v/presidio-hardened-ai`.

## Schema/wire stability

The signed payloads are versioned per schema id (`dp-result@1`, `consortium-round@1`,
`ingest-record@1`), independently of the package version:

- Within a schema major, the bytes an existing payload hashes to do not change. New
  optional fields may be added only if a payload without them hashes exactly as before
  (`parents` and, since 0.32.0, `proven_norm` / `norm_bound` follow this rule).
- A change to a required field, a field's encoding or a declared precision is a new major
  of that schema, never an edit of the old one.
- The `EvidenceRef` field set and its signing message are presidio-evidence's
  `evidence-ref@1` contract and move only with that library. The dependency is pinned to
  `presidio-evidence>=0.5.1,<0.6`, and the pinned vectors in `tests/vectors/` are checked
  against both this code and the installed library.
- Ledger entries are versioned by the MAC-covered `canon` tag. Only `canon: 1` verifies
  today; a future canonicaliser would get a new tag rather than change the bytes of `1`.

## Security response

See [SECURITY.md](SECURITY.md). Security fixes ship as patch releases on the
latest minor; any minimum-safe dependency floors are bumped in the same release.
