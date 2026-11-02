# Migration notes

## 0.32.0: presidio-evidence dependency, legacy encoder removed, Python 3.11+

### What changed

- **presidio-evidence is a dependency.** Canonical JSON (`hashing.canonical_json`,
  alias `canonical_bytes`), the evidence signing message, HMAC and Ed25519 signing and
  verification, key generation and the evidence envelope written by `export_evidence`
  now come from the `presidio-evidence` package (its `docs/MIGRATION.md` step 2). No
  signed byte changes: the pinned vectors in `tests/vectors/` pass unchanged, and a
  test checks them against the installed library's vectors. The HMAC ledger chain stays
  in this repository (ledger is not evidence). `[crypto]` now installs
  `presidio-evidence[crypto]`.
- **The pre-0.31 encoder is removed** ([#74](https://github.com/presidio-v/presidio-hardened-ai/issues/74)).
  `_legacy_canonical_v0`, `legacy_sha256_hex_v0`, the legacy branch of `canonical_for` and the
  untagged-request fallback in `authorize_request` are gone. `verify_chain` rejects any
  untagged entry (`untagged pre-0.31 entry at seq N`), `request_hash` rejects an
  untagged request, and approvals countersigned over one no longer authorize a charge.
  `EpsilonBudget` reads only verified, strict-canonical entries, so a recorded float is
  rejected. The removal comes earlier than the trigger #74 set (2027-10-18 or v1.0.0)
  because no release containing the legacy path was ever published: the package's first
  public release is 0.32.0, so no user holds a pre-0.31 ledger or approval.
- **Python 3.11+.** Python 3.10 reached end of life in October 2026.

### If you hold pre-0.31 records

Verify them with a 0.31 checkout (`pai verify --ledger <file> --quiet`) and archive the
output with the ledger before upgrading. Re-sign pending approvals over the tagged
request (`pai dp-authorize`). Start a new ledger for 0.32.

## 0.31.0: strict canonical encoding, `canon` tags, provenance parents

### What changed

- **One canonicaliser for new bytes.** `presidio_ai.hashing.canonical_json` (alias
  `canonical_bytes`) is the presidio-evidence Layer-0 strict profile: sorted keys,
  compact separators, UTF-8, `allow_nan=False`, floats rejected at any depth. Every new
  content hash, ledger MAC, authorization request and signing message uses it. It passes
  presidio-evidence's `canonical-json` and `signing` vectors (copied into
  `tests/vectors/`), so the planned import swap (presidio-evidence `docs/MIGRATION.md`
  step 2) changes no signed bytes.
- **Decimal strings instead of floats.** Privacy parameters in signed payloads (epsilon,
  delta, optimal order, noise multiplier, sample rate, max epsilon, per-silo epsilon,
  robustness score, proven bounds) are plain-notation decimal strings rounded half-even
  to a declared precision (family ADR-0005 draft; per-field precisions in
  `docs/schemas/signed-payloads.md`).
- **`canon` tags.** New ledger entries carry `"canon": 1` (covered by the entry MAC);
  new authorization requests carry `"canon": 1` as a top-level key.
- **Ingest hashes data bytes.** The source commitment is sha256 over the input file as
  read (`raw-input-bytes`); the scrubbed `content_hash` is sha256 over the
  `records-jsonl@1` serialisation, which `pai ingest --out` writes byte-for-byte. Both
  scopes are recorded in the ledger entry and in the evidence content.
- **Ingest D1/D4 refs commit to the ingest record**, not to the bare data hash: the
  content is `ingest-record@1` (commitments, counts, hash scopes, `parents`). The data
  hash is a field inside it.
- **Provenance `parents`** (presidio-evidence ADR-0002) in DP, consortium and ingest
  evidence content and in the matching ledger entries; `--parent HEX` (repeatable) on
  `pai ingest`, `dp-train`, `dp-charge` and `consortium-round`. Omitted when empty.

### What did not change

- **Stored bytes are never rewritten.** Existing ledgers keep their untagged entries;
  appending to an old ledger adds tagged entries after them.
- **Existing evidence refs still verify.** An `EvidenceRef` signature is over
  `{content_hash, signer}`, which is float-free, so strict and legacy encoders produce
  identical bytes for it. The `EvidenceRef@1` contract is unchanged.
- Approval countersignatures, survivor-set MACs and key-agreement fingerprints are over
  float-free messages and are byte-identical under both encoders.

### Legacy verification (0.31 only, removed in 0.32)

In 0.31, `_legacy_canonical_v0` (a frozen copy of the pre-0.31 encoder) verified
ledger entries without a `canon` tag and approvals collected before the upgrade over
the untagged request. 0.32 removed it; see above.

### Hashes that change for new records

Content hashes of *new* DP and consortium D4 refs differ from what 0.30.0 would have
produced for the same run (decimal strings instead of floats), and so do ingest D1/D4
content hashes and the ingest source and content commitments (new scopes). Old refs
are unaffected. Parent-less records hash exactly as they would without the `parents`
feature; `tests/test_provenance.py` pins two such hashes.

### Removal of the legacy encoder

Done in 0.32.0 ([#74](https://github.com/presidio-v/presidio-hardened-ai/issues/74)); see
the 0.32.0 section.
