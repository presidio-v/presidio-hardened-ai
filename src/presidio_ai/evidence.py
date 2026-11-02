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

import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import presidio_evidence

from presidio_ai import __version__
from presidio_ai.hashing import constant_time_equals, sha256_hex
from presidio_ai.ingest import IngestResult
from presidio_ai.ledger import Ledger
from presidio_ai.numeric import encode_field
from presidio_ai.provenance import with_parents

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
    return datetime.now(UTC).isoformat()


def sign_evidence(content_hash: str, key: bytes | str, signer: str) -> str:
    """Detached HMAC-SHA256 signature over ``content_hash`` bound to ``signer``.

    The message is presidio-evidence's ``signing_message``; a ``str`` key gives the
    same bytes as :func:`presidio_evidence.sign_hmac`, and a ``bytes`` key is used
    as is.
    """
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    message = presidio_evidence.signing_message(content_hash, signer)
    return hmac.new(key_bytes, message, hashlib.sha256).hexdigest()


def verify_evidence(ref: EvidenceRef, key: bytes | str) -> bool:
    """Verify a reference's detached signature (timing-safe). Fail-closed."""
    expected = sign_evidence(ref.content_hash, key, ref.signer)
    return constant_time_equals(expected, ref.signature)


# ── Public-key signing (Ed25519) — optional [crypto] extra ───────────────────
# The primitives are presidio-evidence's. The signing algorithm is a property of
# the verifier's trust store (the verifier knows whether signer X uses an HMAC
# secret or an Ed25519 public key), so the EvidenceRef contract stays unchanged.
# Ed25519 (the default since 0.8.0) signatures are 64 bytes / 128 hex, within the
# contract's hex bound.
SIGNING_ALGORITHMS = ("hmac-sha256", "ed25519")


def generate_ed25519_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex). Keep the private key secret."""
    return presidio_evidence.generate_ed25519_keypair()


def sign_ed25519(content_hash: str, signer: str, private_key_hex: str) -> str:
    """Detached Ed25519 signature over the canonical {content_hash, signer} message."""
    return presidio_evidence.sign_ed25519(content_hash, signer, private_key_hex)


def verify_ed25519(content_hash: str, signer: str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature against a public key (fail-closed)."""
    return presidio_evidence.verify_ed25519(content_hash, signer, signature_hex, public_key_hex)


def _sign(content_hash: str, signer: str, *, algorithm: str, signing_key: bytes | str) -> str:
    if algorithm == "hmac-sha256":
        return sign_evidence(content_hash, signing_key, signer)
    if algorithm == "ed25519":
        if not isinstance(signing_key, str):
            raise ValueError("ed25519 signing_key must be the private key hex string")
        return sign_ed25519(content_hash, signer, signing_key)
    raise ValueError(f"unknown signing algorithm: {algorithm!r} (use one of {SIGNING_ALGORITHMS})")


def _make_ref(
    item_id: str,
    content_hash: str,
    ledger_ref: str,
    signing_key: bytes | str,
    signer: str,
    algorithm: str = "ed25519",
) -> EvidenceRef:
    return EvidenceRef(
        item_id=item_id,
        source=SOURCE,
        source_version=__version__,
        ledger_ref=ledger_ref,
        content_hash=content_hash,
        signer=signer,
        signature=_sign(content_hash, signer, algorithm=algorithm, signing_key=signing_key),
        claimed_at=_utc_now(),
    )


def ingest_evidence_content(result: IngestResult) -> dict[str, object]:
    """The hashed content behind ingest D1/D4 refs (schema ``ingest-record@1``).

    Commitments and counts only, no field values. ``parents`` is omitted when empty.
    """
    return with_parents(
        {
            "source_id": result.source_id,
            "n_records": result.n_records,
            "n_fields_scrubbed": result.n_fields_scrubbed,
            "redaction_counts": dict(sorted(result.redaction_counts.items())),
            "source_commitment": result.source_commitment,
            "source_commitment_scope": result.source_commitment_scope,
            "content_hash": result.content_hash,
            "content_hash_scope": result.content_hash_scope,
        },
        result.parents,
    )


def build_ingest_evidence(
    result: IngestResult,
    *,
    ledger: Ledger,
    signing_key: bytes | str,
    signer: str,
    algorithm: str = "ed25519",
) -> list[EvidenceRef]:
    """Build signed D1/D4/O5 evidence references from an ingest result.

    D1 and D4 commit to the ingest record (:func:`ingest_evidence_content`): the
    scrubbed-content hash, the source commitment, the scope each hash covers, and
    the record's ``parents``. O5 commits to the current ledger head (the
    tamper-evident chain tip). The ``ledger_ref`` is an opaque, commitment-based
    pointer — never a path that could leak content.
    """
    ingest_ref = f"pai-ledger:seq/{result.ledger_seq}"
    record_hash = sha256_hex(ingest_evidence_content(result))
    refs = [
        _make_ref("D1", record_hash, ingest_ref, signing_key, signer, algorithm),
        _make_ref("D4", record_hash, ingest_ref, signing_key, signer, algorithm),
        _make_ref("O5", ledger.head_hash, "pai-ledger:head", signing_key, signer, algorithm),
    ]
    return refs


def export_evidence(refs: list[EvidenceRef], path: str | Path, *, use_case: str) -> Path:
    """Write refs as the JSON document ``iga assess --evidence`` consumes."""
    path = Path(path)
    document = presidio_evidence.build_envelope(
        [r.to_dict() for r in refs],
        source=SOURCE,
        source_version=__version__,
        use_case=use_case,
        generated_at=_utc_now(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# ── Differential-privacy evidence (P2) ──────────────────────────────────────
# DP-SGD's (epsilon, delta) bound is a quantified re-identification / membership
# limit — a direct DPIA input. P2 emits D4 only (high confidence); robustness
# (T4) / EU AI Act Art. 15 framing is deferred so the export never overstates.
SUPPORTED_DP_ITEMS: dict[str, str] = {
    "D4": "DPIA input: quantified (epsilon, delta) bound from DP-SGD accounting",
}


def dp_evidence_content(result, *, parents: Iterable[str] | None = None) -> dict[str, object]:
    """The hashed content behind a DP D4 ref (schema ``dp-result@1`` + ``parents``)."""
    return with_parents(result.signed_dict(), parents)


def build_dp_evidence(
    result,
    *,
    signing_key: bytes | str,
    signer: str,
    charge_seq: int,
    algorithm: str = "ed25519",
    parents: Iterable[str] | None = None,
):
    """Build a signed D4 EvidenceRef from a DP accounting result.

    ``result`` is a ``presidio_ai.dp.accountant.DPResult``; ``charge_seq`` is the
    ledger sequence of the budget-charge entry the evidence points at. The content
    hash commits to the privacy parameters (epsilon, delta, noise, rate, steps) as
    decimal strings, plus any ADR-0002 ``parents`` (:func:`dp_evidence_content`).
    """
    content_hash = sha256_hex(dp_evidence_content(result, parents=parents))
    ledger_ref = f"pai-ledger:seq/{charge_seq}"
    return [_make_ref("D4", content_hash, ledger_ref, signing_key, signer, algorithm)]


# ── Consortium-round evidence (P4) ──────────────────────────────────────────
# A consortium round produces one aggregate update via secure aggregation; the
# coordinator never sees an individual party's update. The evidence commits to
# the *aggregate only* — its content hash and the round's privacy parameters —
# never to any single member's contribution, consistent with commitments-only.
SUPPORTED_CONSORTIUM_ITEMS: dict[str, str] = {
    "D4": "DPIA input: secure-aggregation round (aggregate commitment + max (epsilon, delta))",
}


def consortium_commitment(
    *,
    round_id: str,
    aggregate_field: list[int],
    max_epsilon: float,
    delta: float,
    n_parties: int,
    n_survivors: int,
    parents: Iterable[str] | None = None,
) -> dict[str, object]:
    """Canonical, content-free commitment for a secure-aggregation round.

    Commits to the *aggregate* (the exact field-domain sum), the round's worst-case
    per-party ``(epsilon, delta)`` as decimal strings (schema ``consortium-round@1``),
    the participation counts, and any ADR-0002 ``parents`` (omitted when empty) —
    never an individual update.
    """
    return with_parents(
        {
            "round_id": round_id,
            "aggregate_sha256": sha256_hex({"agg": list(aggregate_field)}),
            "max_epsilon": encode_field("max_epsilon", max_epsilon),
            "delta": encode_field("delta", delta),
            "n_parties": n_parties,
            "n_survivors": n_survivors,
        },
        parents,
    )


def build_consortium_evidence(
    commitment: dict[str, object],
    *,
    signing_key: bytes | str,
    signer: str,
    round_seq: int,
    algorithm: str = "ed25519",
) -> list[EvidenceRef]:
    """Build one signed D4 EvidenceRef for a consortium round.

    ``commitment`` is a :func:`consortium_commitment` dict; ``round_seq`` is the
    ledger sequence of the consortium-round entry the evidence points at.
    """
    content_hash = sha256_hex(commitment)
    ledger_ref = f"pai-ledger:seq/{round_seq}"
    return [_make_ref("D4", content_hash, ledger_ref, signing_key, signer, algorithm)]
