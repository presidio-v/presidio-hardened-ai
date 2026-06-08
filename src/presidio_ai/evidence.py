"""Signed ``EvidenceRef`` export — the cross-repo contract with IKI-Gov v0.13.0.

An ``EvidenceRef`` lets the IKI-Gov governance spine upgrade a checklist affirmation
from "someone ticked it" to *affirmed-by-evidence*: the assessor (or an agent) can
verify the reference against this producer's ledger. The field set matches the
``EvidenceRef`` schema in ``presidio-hardened-ikigov-assess`` PRESIDIO-REQ.md v0.13.0
**verbatim** — it is the integration contract; keep the two in lockstep.

P1 emits evidence only for the items this producer can substantiate with high
confidence: **D1** (data inventory & lineage), **D4** (DPIA inputs: scrub record),
and **O5** (immutable audit log). Partial-credit items (T4/T5/D2/I4) are deferred to
later phases so the export never overstates what the ledger proves.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from presidio_ai import __version__
from presidio_ai.hashing import constant_time_equals, hmac_hex
from presidio_ai.ingest import IngestResult
from presidio_ai.ledger import Ledger

SOURCE = "presidio-hardened-ai"

# Items this producer can sign evidence for, with the human-readable basis.
SUPPORTED_ITEMS: dict[str, str] = {
    "D1": "Data inventory & end-to-end lineage (ingest source + content commitments)",
    "D4": "DPIA inputs: PII-scrub record (per-entity redaction counts)",
    "O5": "Immutable, auditor-verifiable audit log (HMAC-chained ledger head)",
}


@dataclass(frozen=True)
class EvidenceRef:
    item_id: str
    source: str
    source_version: str
    ledger_ref: str
    content_hash: str
    signer: str
    signature: str
    claimed_at: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sign_evidence(content_hash: str, key: bytes | str, signer: str) -> str:
    """Detached HMAC-SHA256 signature over ``content_hash`` bound to ``signer``."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac_hex(key_bytes, {"content_hash": content_hash, "signer": signer})


def verify_evidence(ref: EvidenceRef, key: bytes | str) -> bool:
    """Verify a reference's detached signature (timing-safe). Fail-closed."""
    expected = sign_evidence(ref.content_hash, key, ref.signer)
    return constant_time_equals(expected, ref.signature)


def _make_ref(item_id: str, content_hash: str, ledger_ref: str, key, signer: str) -> EvidenceRef:
    return EvidenceRef(
        item_id=item_id,
        source=SOURCE,
        source_version=__version__,
        ledger_ref=ledger_ref,
        content_hash=content_hash,
        signer=signer,
        signature=sign_evidence(content_hash, key, signer),
        claimed_at=_utc_now(),
    )


def build_ingest_evidence(
    result: IngestResult,
    *,
    ledger: Ledger,
    signing_key: bytes | str,
    signer: str,
) -> list[EvidenceRef]:
    """Build signed D1/D4/O5 evidence references from an ingest result.

    D1 and D4 commit to the scrubbed-content hash of the ingested source; O5 commits
    to the current ledger head (the tamper-evident chain tip). The ``ledger_ref`` is
    an opaque, commitment-based pointer — never a path that could leak content.
    """
    ingest_ref = f"pai-ledger:seq/{result.ledger_seq}"
    refs = [
        _make_ref("D1", result.content_hash, ingest_ref, signing_key, signer),
        _make_ref("D4", result.content_hash, ingest_ref, signing_key, signer),
        _make_ref("O5", ledger.head_hash, "pai-ledger:head", signing_key, signer),
    ]
    return refs


def export_evidence(refs: list[EvidenceRef], path: str | Path, *, use_case: str) -> Path:
    """Write refs as the JSON document ``iga assess --evidence`` consumes."""
    path = Path(path)
    document = {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": use_case,
        "source": SOURCE,
        "source_version": __version__,
        "generated_at": _utc_now(),
        "evidence": [r.to_dict() for r in refs],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
