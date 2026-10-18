"""Pre-0.31 ledgers and approvals still verify after the strict-canonicaliser switch.

``tests/fixtures/legacy-v0.30/`` was produced by the released 0.30.0 code (float
payloads, frozen legacy encoder): ``ledger.jsonl`` holds an ingest, an MPA-authorized
charge, a plain charge and a consortium round; ``approvals.json`` holds n-of-m
approvals for a job that was approved but not yet charged at upgrade time. The files
are never rewritten, by these tests or by the code.
"""

from __future__ import annotations

import dataclasses
import json
import math
import shutil
from pathlib import Path

import pytest

from presidio_ai.dp import DPResult, EpsilonBudget, MPAPolicy
from presidio_ai.dp.authorization import (
    MPADenied,
    _legacy_request_v0,
    authorize_request,
    build_request,
    request_hash,
    sign_approval,
)
from presidio_ai.dp.budget import AUTHORIZED_EVENT, CHARGE_EVENT
from presidio_ai.hashing import CANON_STRICT, CanonicalError, canonical_json
from presidio_ai.ledger import Ledger, LedgerError, verify_chain

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-v0.30"
APPROVALS = json.loads((FIXTURES / "approvals.json").read_text(encoding="utf-8"))
KEY = APPROVALS["ledger_key"]
APPROVER_KEYS = APPROVALS["approver_keys"]


@pytest.fixture
def legacy_ledger(tmp_path) -> Path:
    path = tmp_path / "ledger.jsonl"
    shutil.copyfile(FIXTURES / "ledger.jsonl", path)
    return path


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_legacy_fixture_verifies_unchanged(legacy_ledger):
    before = legacy_ledger.read_bytes()
    entries = verify_chain(legacy_ledger, key=KEY)
    assert len(entries) == 5
    assert all(e.canon is None for e in entries)
    assert legacy_ledger.read_bytes() == before
    # The fixture really needs the legacy encoder: its payloads hold floats.
    with pytest.raises(CanonicalError):
        canonical_json(entries[2].signed_view())


def test_appending_to_a_legacy_ledger_tags_only_new_entries(legacy_ledger):
    before = legacy_ledger.read_bytes()
    ledger = Ledger(legacy_ledger, key=KEY)
    ledger.append("note", {"k": "v"})
    assert legacy_ledger.read_bytes().startswith(before)  # stored bytes never rewritten
    entries = verify_chain(legacy_ledger, key=KEY)
    assert [e.canon for e in entries] == [None] * 5 + [CANON_STRICT]
    stored = _lines(legacy_ledger)
    assert "canon" not in stored[0] and stored[-1]["canon"] == 1


def test_budget_sums_legacy_floats_and_new_decimal_strings(legacy_ledger):
    ledger = Ledger(legacy_ledger, key=KEY)
    budget = EpsilonBudget(10.0, 1e-5, ledger)
    legacy_spent = budget.spent()
    assert legacy_spent == pytest.approx(1.6609311216485523 + 0.04464643887287744, abs=1e-15)
    charge = budget.charge_dpsgd(job_id="new", noise_multiplier=2.0, sample_rate=0.01, steps=10)
    payload = verify_chain(legacy_ledger, key=KEY)[-1].payload
    assert isinstance(payload["epsilon"], str)
    assert budget.spent() == pytest.approx(legacy_spent + charge.result.epsilon, abs=1e-12)


def test_tampered_legacy_entry_is_detected(legacy_ledger):
    rows = _lines(legacy_ledger)
    rows[2]["payload"]["epsilon"] = 0.001  # understate a legacy charge
    legacy_ledger.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    with pytest.raises(LedgerError, match="MAC mismatch"):
        verify_chain(legacy_ledger, key=KEY)


def test_stripping_the_canon_tag_is_detected(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    ledger.append("e", {"a": "1"})
    rows = _lines(ledger.path)
    del rows[0]["canon"]
    ledger.path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="MAC mismatch"):
        verify_chain(ledger.path, key=KEY)


def test_untagged_entry_after_a_tagged_one_is_rejected(legacy_ledger):
    Ledger(legacy_ledger, key=KEY).append("e", {"a": "1"})
    rows = _lines(legacy_ledger)
    # Splice a copy of a legacy (untagged) row after the tagged one.
    downgrade = dict(rows[0], seq=6, prev_hash=rows[-1]["entry_hash"])
    with legacy_ledger.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(downgrade) + "\n")
    with pytest.raises(LedgerError, match="after a canon-tagged entry"):
        verify_chain(legacy_ledger, key=KEY)


def test_unknown_canon_tag_is_rejected(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    ledger.append("e", {"a": "1"})
    rows = _lines(ledger.path)
    rows[0]["canon"] = 2
    ledger.path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="unsupported canon"):
        verify_chain(ledger.path, key=KEY)


def test_new_ledger_entries_reject_floats(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    with pytest.raises(LedgerError, match="not canonical"):
        ledger.append("e", {"epsilon": 1.5})
    assert not ledger.path.exists()


def _pending():
    # The result the approvers countersigned, bit for bit. Recomputing it with
    # dpsgd_epsilon reproduces epsilon only on the platform that generated the
    # fixture: the last float digits differ between macOS and Linux runners.
    request = dict(APPROVALS["pending_request"])
    job_id = request.pop("job_id")
    return job_id, DPResult(**request)


def test_legacy_approvals_fail_closed_when_epsilon_differs_in_the_last_bit():
    """A legacy request binds the float itself; any drift denies rather than authorizes."""
    job_id, result = _pending()
    drifted = dataclasses.replace(result, epsilon=math.nextafter(result.epsilon, math.inf))
    policy = MPAPolicy(threshold=2, min_epsilon=0.5, approvers=tuple(sorted(APPROVER_KEYS)))
    with pytest.raises(MPADenied):
        authorize_request(
            drifted,
            job_id=job_id,
            policy=policy,
            approvals=APPROVALS["pending_approvals"],
            approver_keys=APPROVER_KEYS,
        )


def test_legacy_request_hash_is_reproduced():
    job_id, result = _pending()
    legacy = _legacy_request_v0(result, job_id=job_id)
    assert legacy == APPROVALS["pending_request"]
    assert request_hash(legacy) == APPROVALS["pending_request_hash"]


def test_new_requests_are_tagged_and_float_free():
    job_id, result = _pending()
    request = build_request(result, job_id=job_id)
    assert request["canon"] == CANON_STRICT
    assert not any(isinstance(v, float) for v in request.values())
    assert request_hash(request) != APPROVALS["pending_request_hash"]
    with pytest.raises(ValueError, match="unsupported request canon"):
        request_hash({**request, "canon": 2})


def test_pre_upgrade_approvals_still_authorize_and_are_recorded(tmp_path):
    job_id, result = _pending()
    policy = MPAPolicy(threshold=2, min_epsilon=0.5, approvers=tuple(sorted(APPROVER_KEYS)))
    req_hash, approvers, canon = authorize_request(
        result,
        job_id=job_id,
        policy=policy,
        approvals=APPROVALS["pending_approvals"],
        approver_keys=APPROVER_KEYS,
    )
    assert (req_hash, list(approvers), canon) == (
        APPROVALS["pending_request_hash"],
        ["alice", "carol"],
        0,
    )
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    EpsilonBudget(10.0, 1e-5, ledger).charge(
        result,
        job_id=job_id,
        policy=policy,
        approvals=APPROVALS["pending_approvals"],
        approver_keys=APPROVER_KEYS,
    )
    auth = [e for e in verify_chain(ledger.path, key=KEY) if e.event == AUTHORIZED_EVENT][0]
    assert auth.payload["request_canon"] == 0
    assert auth.payload["request_hash"] == APPROVALS["pending_request_hash"]
    assert isinstance(auth.payload["epsilon"], str)


def test_new_approvals_use_the_tagged_request(tmp_path):
    job_id, result = _pending()
    policy = MPAPolicy(threshold=2, min_epsilon=0.5, approvers=tuple(sorted(APPROVER_KEYS)))
    new_hash = request_hash(build_request(result, job_id=job_id))
    approvals = {
        a: sign_approval(new_hash, approver_id=a, approver_key=APPROVER_KEYS[a])
        for a in ("alice", "bob")
    }
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    EpsilonBudget(10.0, 1e-5, ledger).charge(
        result, job_id=job_id, policy=policy, approvals=approvals, approver_keys=APPROVER_KEYS
    )
    entries = verify_chain(ledger.path, key=KEY)
    auth = [e for e in entries if e.event == AUTHORIZED_EVENT][0]
    assert auth.payload["request_canon"] == 1 and auth.payload["request_hash"] == new_hash
    charge = [e for e in entries if e.event == CHARGE_EVENT][0]
    assert charge.payload["epsilon"] == result.signed_dict()["epsilon"]


def test_legacy_and_new_approvals_are_never_mixed():
    job_id, result = _pending()
    policy = MPAPolicy(threshold=2, min_epsilon=0.5, approvers=tuple(sorted(APPROVER_KEYS)))
    new_hash = request_hash(build_request(result, job_id=job_id))
    mixed = {
        "alice": APPROVALS["pending_approvals"]["alice"],  # over the legacy request
        "bob": sign_approval(new_hash, approver_id="bob", approver_key=APPROVER_KEYS["bob"]),
    }
    with pytest.raises(MPADenied):
        authorize_request(
            result, job_id=job_id, policy=policy, approvals=mixed, approver_keys=APPROVER_KEYS
        )
