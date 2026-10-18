"""Ingest layer: scrub records, record lineage to the ledger, emit nothing sensitive.

The ledger entry written here is the cornerstone evidence for IKI-Gov items **D1**
(data inventory & lineage) and **D4** (DPIA inputs) — and the ledger itself is the
evidence for **O5** (immutable audit log). It contains only commitments: a hash of
the source set, a hash of the scrubbed output, record counts, and per-entity
redaction counts. No field value — scrubbed or raw — is ever recorded.

Hash scopes (recorded next to each hash in the ledger entry and the evidence):

* ``raw-input-bytes`` — sha256 over the source file's bytes exactly as read. Used for
  the source commitment whenever the caller passes ``raw_bytes`` (the CLI always does),
  so ``sha256sum input.jsonl`` reproduces it without re-serialising anything.
* ``records-jsonl@1`` — sha256 over :func:`records_jsonl_bytes` of the records: one
  line per record, ``json.dumps(sort_keys=True, separators=(",", ":"),
  ensure_ascii=False, allow_nan=False)`` plus ``\n``, UTF-8. Used for the source
  commitment of in-memory records and always for the scrubbed ``content_hash``; the
  CLI's ``--out`` file is exactly these bytes, so ``sha256sum`` reproduces it too.

These are hashes of data bytes, not canonical payloads: record values may be any JSON,
including non-integer numbers, which the strict canonicaliser would reject.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from presidio_ai.hashing import sha256_bytes_hex
from presidio_ai.ledger import Ledger
from presidio_ai.pii import PIIScrubber
from presidio_ai.provenance import normalize_parents, with_parents

INGEST_EVENT = "data-ingested"
SCOPE_RAW_BYTES = "raw-input-bytes"
SCOPE_RECORDS_JSONL = "records-jsonl@1"


@dataclass(frozen=True)
class IngestResult:
    source_id: str
    n_records: int
    n_fields_scrubbed: int
    redaction_counts: dict[str, int]
    source_commitment: str  # sha256 over the raw input (one-way); see source_commitment_scope
    content_hash: str  # sha256 over the scrubbed output (what training will see)
    ledger_seq: int
    records: list[dict[str, Any]] = field(default_factory=list)
    source_commitment_scope: str = SCOPE_RECORDS_JSONL
    content_hash_scope: str = SCOPE_RECORDS_JSONL
    parents: tuple[str, ...] = ()

    @property
    def redactions_total(self) -> int:
        return sum(self.redaction_counts.values())


def _coerce_record(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return dict(record)
    if isinstance(record, str):
        return {"text": record}
    raise TypeError(f"records must be mappings or strings, got {type(record).__name__}")


def records_jsonl_bytes(records: Iterable[Mapping[str, Any]]) -> bytes:
    """Serialise records as ``records-jsonl@1`` bytes (see the module docstring)."""
    try:
        return "".join(
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
            for record in records
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"records are not JSON-serialisable (NaN/Infinity?): {exc}") from exc


def ingest_records(
    records: Iterable[Any],
    *,
    source_id: str,
    ledger: Ledger,
    scrubber: PIIScrubber | None = None,
    fields: Sequence[str] | None = None,
    raw_bytes: bytes | None = None,
    parents: Iterable[str] | None = None,
) -> IngestResult:
    """Scrub ``records``, write a lineage commitment to ``ledger``, return the result.

    ``fields`` restricts scrubbing to named string fields; when ``None`` every string
    field is scrubbed. Strings are treated as a single ``{"text": ...}`` field.
    ``raw_bytes`` are the exact source bytes ``records`` were parsed from; when given,
    the source commitment covers them (scope ``raw-input-bytes``) instead of a
    re-serialisation. ``parents`` are ADR-0002 upstream content hashes (validated,
    de-duplicated, omitted when empty).
    """
    if not source_id or not isinstance(source_id, str):
        raise ValueError("source_id must be a non-empty string")
    if raw_bytes is not None and not isinstance(raw_bytes, bytes):
        raise TypeError("raw_bytes must be bytes")
    parent_list = normalize_parents(parents)
    scrubber = scrubber or PIIScrubber()

    raw = [_coerce_record(r) for r in records]
    scrubbed: list[dict[str, Any]] = []
    redactions: dict[str, int] = {}
    n_fields_scrubbed = 0

    for record in raw:
        out: dict[str, Any] = {}
        for key, value in record.items():
            scrub_this = isinstance(value, str) and (fields is None or key in fields)
            if not scrub_this:
                out[key] = value
                continue
            result = scrubber.scrub(value)
            out[key] = result.text
            if result.total:
                n_fields_scrubbed += 1
                for entity, count in result.counts.items():
                    redactions[entity] = redactions.get(entity, 0) + count
        scrubbed.append(out)

    if raw_bytes is not None:
        source_commitment = sha256_bytes_hex(raw_bytes)
        source_scope = SCOPE_RAW_BYTES
    else:
        source_commitment = sha256_bytes_hex(records_jsonl_bytes(raw))
        source_scope = SCOPE_RECORDS_JSONL
    content_hash = sha256_bytes_hex(records_jsonl_bytes(scrubbed))

    entry = ledger.append(
        INGEST_EVENT,
        with_parents(
            {
                "source_id": source_id,
                "n_records": len(raw),
                "n_fields_scrubbed": n_fields_scrubbed,
                "redaction_counts": dict(sorted(redactions.items())),
                "source_commitment": source_commitment,
                "source_commitment_scope": source_scope,
                "content_hash": content_hash,
                "content_hash_scope": SCOPE_RECORDS_JSONL,
                "pii_mode": scrubber.effective_mode,
                "pii_action": scrubber.action,
            },
            parent_list,
        ),
    )

    return IngestResult(
        source_id=source_id,
        n_records=len(raw),
        n_fields_scrubbed=n_fields_scrubbed,
        redaction_counts=dict(sorted(redactions.items())),
        source_commitment=source_commitment,
        content_hash=content_hash,
        ledger_seq=entry.seq,
        records=scrubbed,
        source_commitment_scope=source_scope,
        content_hash_scope=SCOPE_RECORDS_JSONL,
        parents=tuple(parent_list),
    )
