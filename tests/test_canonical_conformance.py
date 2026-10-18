"""Conformance of presidio_ai.hashing against the presidio-evidence golden vectors.

The files under tests/vectors/ are verbatim copies from presidio-evidence (see
tests/vectors/PROVENANCE.txt). Passing them means the planned import swap to
presidio-evidence (its MIGRATION.md step 2) changes no signed bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from presidio_ai.evidence import sign_evidence, verify_evidence
from presidio_ai.hashing import (
    CanonicalError,
    _legacy_canonical_v0,
    canonical_bytes,
    canonical_json,
    hmac_hex,
    sha256_hex,
)

VECTORS = Path(__file__).parent / "vectors"
CANON = json.loads((VECTORS / "canonical-json" / "vectors.json").read_text(encoding="utf-8"))
HMAC = json.loads((VECTORS / "signing" / "hmac-sha256-golden.json").read_text(encoding="utf-8"))
ED25519 = json.loads((VECTORS / "signing" / "ed25519-golden.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CANON["cases"], ids=lambda c: c["name"])
def test_canonical_vector(case):
    encoded = canonical_json(case["payload"])
    assert encoded == case["canonical"].encode("utf-8")
    assert sha256_hex(case["payload"]) == case["sha256_hex"]
    assert hashlib.sha256(encoded).hexdigest() == case["sha256_hex"]


@pytest.mark.parametrize("case", CANON["rejected"], ids=lambda c: c["name"])
def test_rejected_vector(case):
    with pytest.raises(CanonicalError):
        canonical_json(case["payload"])
    with pytest.raises(CanonicalError):
        sha256_hex(case["payload"])
    with pytest.raises(CanonicalError):
        hmac_hex(b"k", case["payload"])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 0.0, 1e-5])
def test_strict_rejects_every_float(value):
    with pytest.raises(CanonicalError):
        canonical_json({"a": [{"b": value}]})


def test_strict_rejects_float_keys_and_unserialisable():
    with pytest.raises(CanonicalError):
        canonical_json({1.5: "x"})
    with pytest.raises(CanonicalError):
        canonical_json({"a": object()})


@pytest.mark.parametrize("case", CANON["cases"], ids=lambda c: c["name"])
def test_legacy_matches_strict_on_float_free_payloads(case):
    # Why existing string-only signatures verify unchanged after the switch.
    assert _legacy_canonical_v0(case["payload"]) == canonical_json(case["payload"])


def test_canonical_bytes_is_the_strict_encoder():
    assert canonical_bytes is canonical_json


def test_hmac_signing_vector():
    sig = sign_evidence(HMAC["content_hash"], HMAC["key"], HMAC["signer"])
    assert sig == HMAC["signature_hex"]
    message = {"content_hash": HMAC["content_hash"], "signer": HMAC["signer"]}
    assert canonical_json(message) == HMAC["message_canonical"].encode("utf-8")


@pytest.mark.parametrize("case", HMAC["tamper_cases"], ids=lambda c: c["reason"])
def test_hmac_tamper_cases_fail_closed(case):
    from presidio_ai.evidence import EvidenceRef

    ref = EvidenceRef(
        item_id="D4",
        source="presidio-hardened-ai",
        source_version="test",
        ledger_ref="pai-ledger:seq/0",
        content_hash=case["content_hash"],
        signer=case["signer"],
        signature=case["signature_hex"],
        claimed_at="2026-01-01T00:00:00+00:00",
    )
    assert verify_evidence(ref, case["key"]) is case["verifies"]


def test_ed25519_signing_vector():
    pytest.importorskip("cryptography")
    from presidio_ai.evidence import sign_ed25519, verify_ed25519

    sig = sign_ed25519(ED25519["content_hash"], ED25519["signer"], ED25519["private_key_hex"])
    assert sig == ED25519["signature_hex"]
    assert verify_ed25519(
        ED25519["content_hash"], ED25519["signer"], sig, ED25519["public_key_hex"]
    )
    for case in ED25519["tamper_cases"]:
        ok = verify_ed25519(
            case["content_hash"], case["signer"], case["signature_hex"], case["public_key_hex"]
        )
        assert ok is case["verifies"], case["reason"]
