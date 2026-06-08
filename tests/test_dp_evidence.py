from __future__ import annotations

import json

from presidio_ai.dp.budget import EpsilonBudget
from presidio_ai.evidence import (
    SUPPORTED_DP_ITEMS,
    build_dp_evidence,
    export_evidence,
    verify_evidence,
)
from presidio_ai.hashing import sha256_hex
from presidio_ai.ledger import Ledger

KEY = "k"
SIGNING = "sig"


def _charge(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", key=KEY)
    budget = EpsilonBudget(10.0, 1e-5, ledger)
    return budget.charge_dpsgd(job_id="ft", noise_multiplier=1.1, sample_rate=0.01, steps=500)


def test_build_dp_evidence_d4(tmp_path):
    charge = _charge(tmp_path)
    refs = build_dp_evidence(
        charge.result,
        signing_key=SIGNING,
        signer="prod",
        charge_seq=charge.ledger_seq,
        algorithm="hmac-sha256",
    )
    assert [r.item_id for r in refs] == list(SUPPORTED_DP_ITEMS) == ["D4"]
    ref = refs[0]
    assert verify_evidence(ref, SIGNING)
    assert ref.content_hash == sha256_hex(charge.result.as_dict())
    assert ref.ledger_ref == f"pai-ledger:seq/{charge.ledger_seq}"
    assert ref.source == "presidio-hardened-ai"


def test_dp_evidence_export_shape(tmp_path):
    charge = _charge(tmp_path)
    refs = build_dp_evidence(
        charge.result,
        signing_key=SIGNING,
        signer="prod",
        charge_seq=charge.ledger_seq,
        algorithm="hmac-sha256",
    )
    out = tmp_path / "dp-evidence.json"
    export_evidence(refs, out, use_case="fraud-scoring")
    doc = json.loads(out.read_text())
    assert doc["use_case"] == "fraud-scoring"
    assert len(doc["evidence"]) == 1
    assert doc["evidence"][0]["item_id"] == "D4"


def test_dp_evidence_tamper_fails(tmp_path):
    charge = _charge(tmp_path)
    ref = build_dp_evidence(
        charge.result,
        signing_key=SIGNING,
        signer="prod",
        charge_seq=charge.ledger_seq,
        algorithm="hmac-sha256",
    )[0]
    from dataclasses import replace

    forged = replace(ref, content_hash="0" * 64)
    assert verify_evidence(forged, SIGNING) is False
