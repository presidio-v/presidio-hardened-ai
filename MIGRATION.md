# Migration notes

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

### Legacy verification

`presidio_ai.hashing._legacy_canonical_v0` is a frozen copy of the pre-0.31 encoder,
used **only** to verify:

- ledger entries without a `canon` tag. `verify_chain` uses it for those entries and
  the strict encoder for tagged ones. An untagged entry *after* a tagged one is rejected
  (that would be a downgrade), as is any tag other than `1`;
- approvals collected before the upgrade for a job not yet charged. `authorize_request`
  tries the tagged request first; if its approvals fall short of the threshold it tries
  the untagged legacy request (`_legacy_request_v0`). A charge is authorized by one
  form or the other, never by a mix. The `mpa-authorized` ledger entry records which in
  `request_canon` (`1` or `0`). A legacy request binds the raw float epsilon, which is
  recomputed at charge time, so pre-0.31 approvals authorize only where the accountant
  reproduces that float bit for bit, in practice the same platform and library versions
  that produced it. Anywhere else the charge is denied (fail-closed); collect new,
  tagged approvals instead.

`EpsilonBudget.spent()` sums legacy float epsilons and new decimal-string epsilons
exactly (`decimal.Decimal`).

`tests/fixtures/legacy-v0.30/` holds a ledger and pending approvals produced by the
0.30.0 code; `tests/test_legacy_canon.py` keeps them verifying.

### Hashes that change for new records

Content hashes of *new* DP and consortium D4 refs differ from what 0.30.0 would have
produced for the same run (decimal strings instead of floats), and so do ingest D1/D4
content hashes and the ingest source and content commitments (new scopes). Old refs
are unaffected. Parent-less records hash exactly as they would without the `parents`
feature; `tests/test_provenance.py` pins two such hashes.

### Removal trigger for the legacy encoder

Tracked in [#74](https://github.com/presidio-v/presidio-hardened-ai/issues/74):
remove `_legacy_canonical_v0` and the legacy request fallback in the first release on
or after **2027-10-18**, or at **v1.0.0**, whichever comes first. Before that release,
run `pai verify --ledger <file> --quiet` on every ledger that still holds untagged
entries and archive the output with the ledger; pending pre-0.31 approvals must be
re-signed over the tagged request. After removal, untagged entries fail closed.
