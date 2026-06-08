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
from presidio_ai.hashing import canonical_bytes, constant_time_equals, hmac_hex, sha256_hex
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


# ── Public-key signing (Ed25519) — optional [crypto] extra ───────────────────
# The signing algorithm is a property of the verifier's trust store (the verifier
# knows whether signer X uses an HMAC secret or an Ed25519 public key), so the
# EvidenceRef contract stays unchanged. Ed25519 signatures are 64 bytes / 128 hex,
# within the contract's hex bound. HMAC remains the default until consumers verify
# Ed25519; flip the default once the trust stores are provisioned with public keys.
SIGNING_ALGORITHMS = ("hmac-sha256", "ed25519")


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "Ed25519 signing needs the optional extra: pip install 'presidio-hardened-ai[crypto]'"
        ) from exc
    return ed25519


def generate_ed25519_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex). Keep the private key secret."""
    ed25519 = _require_crypto()
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def sign_ed25519(content_hash: str, signer: str, private_key_hex: str) -> str:
    """Detached Ed25519 signature over the canonical {content_hash, signer} message."""
    ed25519 = _require_crypto()
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return sk.sign(canonical_bytes({"content_hash": content_hash, "signer": signer})).hex()


def verify_ed25519(content_hash: str, signer: str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature against a public key (fail-closed)."""
    from cryptography.exceptions import InvalidSignature

    ed25519 = _require_crypto()
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(
            bytes.fromhex(signature_hex),
            canonical_bytes({"content_hash": content_hash, "signer": signer}),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


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


def build_ingest_evidence(
    result: IngestResult,
    *,
    ledger: Ledger,
    signing_key: bytes | str,
    signer: str,
    algorithm: str = "ed25519",
) -> list[EvidenceRef]:
    """Build signed D1/D4/O5 evidence references from an ingest result.

    D1 and D4 commit to the scrubbed-content hash of the ingested source; O5 commits
    to the current ledger head (the tamper-evident chain tip). The ``ledger_ref`` is
    an opaque, commitment-based pointer — never a path that could leak content.
    """
    ingest_ref = f"pai-ledger:seq/{result.ledger_seq}"
    refs = [
        _make_ref("D1", result.content_hash, ingest_ref, signing_key, signer, algorithm),
        _make_ref("D4", result.content_hash, ingest_ref, signing_key, signer, algorithm),
        _make_ref("O5", ledger.head_hash, "pai-ledger:head", signing_key, signer, algorithm),
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


# ── Differential-privacy evidence (P2) ──────────────────────────────────────
# DP-SGD's (epsilon, delta) bound is a quantified re-identification / membership
# limit — a direct DPIA input. P2 emits D4 only (high confidence); robustness
# (T4) / EU AI Act Art. 15 framing is deferred so the export never overstates.
SUPPORTED_DP_ITEMS: dict[str, str] = {
    "D4": "DPIA input: quantified (epsilon, delta) bound from DP-SGD accounting",
}


def build_dp_evidence(
    result,
    *,
    signing_key: bytes | str,
    signer: str,
    charge_seq: int,
    algorithm: str = "ed25519",
):
    """Build a signed D4 EvidenceRef from a DP accounting result.

    ``result`` is a ``presidio_ai.dp.accountant.DPResult``; ``charge_seq`` is the
    ledger sequence of the budget-charge entry the evidence points at. The content
    hash commits to the privacy parameters (epsilon, delta, noise, rate, steps).
    """
    content_hash = sha256_hex(result.as_dict())
    ledger_ref = f"pai-ledger:seq/{charge_seq}"
    return [_make_ref("D4", content_hash, ledger_ref, signing_key, signer, algorithm)]
