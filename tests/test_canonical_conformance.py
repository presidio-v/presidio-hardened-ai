"""Conformance of presidio_ai.hashing against the presidio-evidence golden vectors.

Since 0.32 the encoding and the signing primitives come from the presidio-evidence
package. The files under tests/vectors/ are this repository's own pinned copies of
the library's vectors (see tests/vectors/PROVENANCE.txt), so a library release that
changed any signed byte fails here, independently of the library's own tests.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import presidio_evidence
import pytest

from presidio_ai.evidence import sign_evidence, verify_evidence
from presidio_ai.hashing import (
    CanonicalError,
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
def test_encoding_is_the_library_encoding(case):
    assert canonical_json(case["payload"]) == presidio_evidence.canonical_bytes(case["payload"])


def test_canonical_bytes_is_the_strict_encoder():
    assert canonical_bytes is canonical_json


def test_hmac_signing_matches_the_library():
    for key in (HMAC["key"], HMAC["key"].encode("utf-8")):
        assert sign_evidence(HMAC["content_hash"], key, HMAC["signer"]) == (
            presidio_evidence.sign_hmac(HMAC["content_hash"], HMAC["signer"], HMAC["key"])
        )


def test_export_uses_the_library_envelope(tmp_path):
    from presidio_ai.evidence import EvidenceRef, export_evidence

    ref = EvidenceRef(
        item_id="D4",
        source="presidio-hardened-ai",
        source_version="test",
        ledger_ref="pai-ledger:seq/0",
        content_hash=HMAC["content_hash"],
        signer=HMAC["signer"],
        signature=HMAC["signature_hex"],
        claimed_at="2026-01-01T00:00:00+00:00",
    )
    path = export_evidence([ref], tmp_path / "e.json", use_case="test")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert list(document) == [
        "schema",
        "use_case",
        "source",
        "source_version",
        "generated_at",
        "evidence",
    ]
    assert (
        presidio_evidence.load_evidence(path.read_text(encoding="utf-8"))[0].signature
        == (HMAC["signature_hex"])
    )


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


@pytest.mark.parametrize(
    "rel",
    [
        "canonical-json/vectors.json",
        "signing/hmac-sha256-golden.json",
        "signing/ed25519-golden.json",
    ],
)
def test_pinned_vectors_match_the_installed_library(rel):
    library = Path(presidio_evidence.vectors_dir()) / rel
    pinned = json.loads((VECTORS / rel).read_text(encoding="utf-8"))
    published = json.loads(library.read_text(encoding="utf-8"))
    pinned.pop("description", None)
    published.pop("description", None)
    assert pinned == published
