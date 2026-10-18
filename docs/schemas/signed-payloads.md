# Signed payload schemas

Every payload this repo hashes or MACs is encoded with the strict canonical JSON
profile (`presidio_ai.hashing.canonical_json`, presidio-evidence ADR-0001 D1:
sorted keys, compact separators, UTF-8, `allow_nan=False`, floats rejected).
Non-integer numbers are therefore **decimal strings**, following the family numeric
rule (ADR-0005, draft at the time of writing):

> Non-integer numeric values in signed payloads are encoded as decimal strings in
> plain notation: no exponent, no trailing zeros (and no trailing decimal point),
> optional leading '-', at least one digit before the point. Each payload schema
> declares, per field, its precision (maximum fractional digits); producers round
> half-even to that precision before encoding. JSON numbers are integers only. NaN
> and ±Infinity are rejected at the producer; 'unbounded' is a schema-declared
> sentinel string or an omitted field, never a float. Verifiers compare strings
> byte-wise and never parse them to float.

All encoding goes through one helper, `presidio_ai.numeric.encode_field(name, value)`,
which looks the precision up in `presidio_ai.numeric.PRECISION`. The table below is
that dictionary; `tests/test_numeric.py` fails if the two drift apart.

## Field precisions

| Field | Type | Precision | Why this precision |
|---|---|---|---|
| `epsilon` | decimal string | 12 | Epsilons sit in roughly [0.01, 100]; 12 digits keep at least 10 significant digits. The budget admits charges with a 1e-12 tolerance, so half-even rounding (at most 5e-13 per charge) stays inside it. |
| `max_epsilon` | decimal string | 12 | Same quantity as `epsilon` (the worst-case per-party epsilon of a round). |
| `noise_multiplier` | decimal string | 12 | Sigma is an operator input, typically 0.3 to 20 with few digits; 12 is exact for any realistic input. |
| `delta` | decimal string | 18 | A probability that is routinely 1e-5 to 1e-10 and can be smaller; 12 digits would keep only 2 significant digits at 1e-10. A non-zero delta that rounds to `"0"` is rejected (it would claim pure DP). |
| `sample_rate` | decimal string | 18 | Poisson rate q = batch/N, which reaches 1e-7 for large datasets. A non-zero rate that rounds to `"0"` is rejected. |
| `optimal_order` | decimal string | 6 | Rényi order chosen by the accountant. Always a string (never an integer for integral orders), so verifiers have one type per field. Both shipped order grids are multiples of 0.25, so 6 digits are exact (`"8"`, `"1.25"`, `"128"`). |
| `score` | decimal string | 12 | Robustness validation score (accuracy-like), recorded on rejected rounds. |
| `clip_bound` | decimal string | 12 | L-inf clip bound proven for a secure round (ADR-0003); `null` when not proven. |
| `l2_bound` | decimal string | 12 | L2 bound proven for a secure round (ADR-0005 of this repo); `null` when not proven. |

Integers (`steps`, `n_parties`, `n_survivors`, `threshold`, counts) stay JSON
integers. No field uses an "unbounded" sentinel today.

## Payloads

### `dp-result@1`: DP D4 evidence content

Hashed by `build_dp_evidence` (`evidence.dp_evidence_content`). Also the body of a
`dp-budget-charge` ledger entry (plus `job_id`) and of an authorization request
(plus `canon` and `job_id`).

| Key | Encoding |
|---|---|
| `epsilon`, `delta`, `optimal_order`, `noise_multiplier`, `sample_rate` | decimal strings, precisions above |
| `steps` | integer |
| `accountant` | string, `"rdp-subsampled-gaussian"` |
| `parents` | optional, ADR-0002 (below) |

### `consortium-round@1`: consortium D4 evidence content

Hashed by `build_consortium_evidence` over `evidence.consortium_commitment`.

| Key | Encoding |
|---|---|
| `round_id` | string |
| `aggregate_sha256` | lowercase hex, sha256 over `{"agg": [field-domain integers]}` |
| `max_epsilon`, `delta` | decimal strings |
| `n_parties`, `n_survivors` | integers |
| `parents` | optional, ADR-0002 |

The round's ledger entry repeats `max_epsilon` and `delta` byte-for-byte and adds
`per_silo_epsilon` (decimal strings at `epsilon` precision).

### `ingest-record@1`: ingest D1/D4 evidence content

Hashed by `build_ingest_evidence` over `evidence.ingest_evidence_content`. Commitments
and counts only.

| Key | Encoding |
|---|---|
| `source_id` | string |
| `n_records`, `n_fields_scrubbed` | integers |
| `redaction_counts` | object of entity -> integer |
| `source_commitment` | lowercase hex sha256 |
| `source_commitment_scope` | `"raw-input-bytes"` (sha256 of the input file as read) or `"records-jsonl@1"` (in-memory records, serialised as below) |
| `content_hash` | lowercase hex sha256 of the scrubbed records |
| `content_hash_scope` | `"records-jsonl@1"` |
| `parents` | optional, ADR-0002 |

`records-jsonl@1` is one line per record:
`json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"`,
UTF-8. It hashes data, not a signed payload, so record values may contain any JSON
number. `pai ingest --out` writes exactly these bytes, so `sha256sum` of that file
equals `content_hash`, and `sha256sum` of the input file equals `source_commitment`.

### Ledger entries and authorization requests

New ledger entries carry `"canon": 1` next to `seq`, `timestamp`, `event`,
`payload` and `prev_hash`, and the tag is covered by the entry MAC. New
authorization requests carry `"canon": 1` as a top-level key. Untagged entries and
requests predate 0.31 and verify only through the frozen legacy encoder; see
`MIGRATION.md`.

## `parents` (presidio-evidence ADR-0002)

A top-level array of upstream evidence content hashes inside the hashed content:
lowercase hex matching `^[0-9a-f]{8,128}$`, order preserved, duplicates dropped
(first occurrence wins), omitted when empty, so a parent-less payload hashes exactly
as it would without the feature. A malformed entry is rejected and nothing is
emitted. The producer does not resolve parents; walking the DAG is the consumer's
job. The CLI takes them as a repeatable `--parent HEX` on `ingest`, `dp-train`,
`dp-charge` and `consortium-round`, and records them in the matching ledger entry
as well as in the evidence content.
