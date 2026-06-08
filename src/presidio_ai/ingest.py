"""Ingest layer: scrub records, record lineage to the ledger, emit nothing sensitive.

The ledger entry written here is the cornerstone evidence for IKI-Gov items **D1**
(data inventory & lineage) and **D4** (DPIA inputs) — and the ledger itself is the
evidence for **O5** (immutable audit log). It contains only commitments: a hash of
the source set, a hash of the scrubbed output, record counts, and per-entity
redaction counts. No field value — scrubbed or raw — is ever recorded.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from presidio_ai.hashing import sha256_hex
from presidio_ai.ledger import Ledger
from presidio_ai.pii import PIIScrubber

INGEST_EVENT = "data-ingested"


@dataclass(frozen=True)
class IngestResult:
    source_id: str
    n_records: int
    n_fields_scrubbed: int
    redaction_counts: dict[str, int]
    source_commitment: str  # sha256 over the raw input set (one-way)
    content_hash: str  # sha256 over the scrubbed output (what training will see)
    ledger_seq: int
    records: list[dict[str, Any]] = field(default_factory=list)

    @property
    def redactions_total(self) -> int:
        return sum(self.redaction_counts.values())


def _coerce_record(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return dict(record)
    if isinstance(record, str):
        return {"text": record}
    raise TypeError(f"records must be mappings or strings, got {type(record).__name__}")


def ingest_records(
    records: Iterable[Any],
    *,
    source_id: str,
    ledger: Ledger,
    scrubber: PIIScrubber | None = None,
    fields: Sequence[str] | None = None,
) -> IngestResult:
    """Scrub ``records``, write a lineage commitment to ``ledger``, return the result.

    ``fields`` restricts scrubbing to named string fields; when ``None`` every string
    field is scrubbed. Strings are treated as a single ``{"text": ...}`` field.
    """
    if not source_id or not isinstance(source_id, str):
        raise ValueError("source_id must be a non-empty string")
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

    source_commitment = sha256_hex(raw)
    content_hash = sha256_hex(scrubbed)

    entry = ledger.append(
        INGEST_EVENT,
        {
            "source_id": source_id,
            "n_records": len(raw),
            "n_fields_scrubbed": n_fields_scrubbed,
            "redaction_counts": dict(sorted(redactions.items())),
            "source_commitment": source_commitment,
            "content_hash": content_hash,
            "pii_mode": scrubber.effective_mode,
            "pii_action": scrubber.action,
        },
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
    )
