from __future__ import annotations

import json
from dataclasses import fields

from presidio_ai.evidence import (
    SUPPORTED_ITEMS,
    EvidenceRef,
    build_ingest_evidence,
    export_evidence,
    sign_evidence,
    verify_evidence,
)
from presidio_ai.ingest import ingest_records
from presidio_ai.ledger import Ledger

KEY = "k"
SIGNING = "sig-key"

# The EvidenceRef field set is the cross-repo contract with ikigov v0.13.0.
CONTRACT_FIELDS = {
    "item_id",
    "source",
    "source_version",
    "ledger_ref",
    "content_hash",
    "signer",
    "signature",
    "claimed_at",
}


def test_evidence_ref_matches_contract():
    assert {f.name for f in fields(EvidenceRef)} == CONTRACT_FIELDS


def test_sign_verify_roundtrip():
    sig = sign_evidence("deadbeef", SIGNING, "me")
    ref = EvidenceRef("D1", "presidio-hardened-ai", "0.1.0", "r", "deadbeef", "me", sig, "t")
    assert verify_evidence(ref, SIGNING) is True


def test_tampered_content_hash_fails_verify():
    sig = sign_evidence("deadbeef", SIGNING, "me")
    ref = EvidenceRef("D1", "presidio-hardened-ai", "0.1.0", "r", "f00d", "me", sig, "t")
    assert verify_evidence(ref, SIGNING) is False


def test_wrong_key_fails_verify():
    sig = sign_evidence("deadbeef", SIGNING, "me")
    ref = EvidenceRef("D1", "presidio-hardened-ai", "0.1.0", "r", "deadbeef", "me", sig, "t")
    assert verify_evidence(ref, "other") is False


def _result(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", key=KEY)
    result = ingest_records([{"note": "a@b.com"}], source_id="s", ledger=ledger)
    return result, ledger


def test_build_ingest_evidence_items(tmp_path):
    result, ledger = _result(tmp_path)
    refs = build_ingest_evidence(result, ledger=ledger, signing_key=SIGNING, signer="prod")
    items = {r.item_id for r in refs}
    assert items == set(SUPPORTED_ITEMS) == {"D1", "D4", "O5"}
    for ref in refs:
        assert verify_evidence(ref, SIGNING)
        assert ref.source == "presidio-hardened-ai"
        assert ref.ledger_ref.startswith("pai-ledger:")


def test_d1_commits_to_content_hash_o5_to_head(tmp_path):
    result, ledger = _result(tmp_path)
    refs = {
        r.item_id: r
        for r in build_ingest_evidence(result, ledger=ledger, signing_key=SIGNING, signer="prod")
    }
    assert refs["D1"].content_hash == result.content_hash
    assert refs["O5"].content_hash == ledger.head_hash


def test_export_shape(tmp_path):
    result, ledger = _result(tmp_path)
    refs = build_ingest_evidence(result, ledger=ledger, signing_key=SIGNING, signer="prod")
    out = tmp_path / "evidence.json"
    export_evidence(refs, out, use_case="fraud-scoring")
    doc = json.loads(out.read_text())
    assert doc["schema"] == "presidio-hardened/evidence-ref@1"
    assert doc["use_case"] == "fraud-scoring"
    assert len(doc["evidence"]) == 3
    assert set(doc["evidence"][0]) == CONTRACT_FIELDS
