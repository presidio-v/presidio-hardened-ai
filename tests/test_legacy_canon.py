"""Pre-0.31 ledgers and approvals fail closed since 0.32 (issue #74).

``tests/fixtures/legacy-v0.30/`` was produced by the released 0.30.0 code (float
payloads, the float-tolerant encoder removed in 0.32): ``ledger.jsonl`` holds an
ingest, an MPA-authorized charge, a plain charge and a consortium round;
``approvals.json`` holds n-of-m approvals over an untagged request. Neither verifies
any more: the ledger is rejected outright and the approvals do not authorize. The
files are never rewritten, by these tests or by the code.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from presidio_ai.dp import DPResult, EpsilonBudget, MPAPolicy
from presidio_ai.dp.authorization import (
    MPADenied,
    authorize_request,
    build_request,
    request_hash,
    sign_approval,
)
from presidio_ai.dp.budget import AUTHORIZED_EVENT, CHARGE_EVENT, _as_decimal
from presidio_ai.hashing import CANON_STRICT, CanonicalError, canonical_for
from presidio_ai.ledger import Ledger, LedgerError, verify_chain

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-v0.30"
APPROVALS = json.loads((FIXTURES / "approvals.json").read_text(encoding="utf-8"))
KEY = APPROVALS["ledger_key"]
APPROVER_KEYS = APPROVALS["approver_keys"]
POLICY = MPAPolicy(threshold=2, min_epsilon=0.5, approvers=tuple(sorted(APPROVER_KEYS)))


@pytest.fixture
def legacy_ledger(tmp_path) -> Path:
    path = tmp_path / "ledger.jsonl"
    shutil.copyfile(FIXTURES / "ledger.jsonl", path)
    return path


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _pending():
    # The result the approvers countersigned before 0.31.
    request = dict(APPROVALS["pending_request"])
    job_id = request.pop("job_id")
    return job_id, DPResult(**request)


def test_legacy_ledger_fails_closed_and_is_not_rewritten(legacy_ledger):
    before = legacy_ledger.read_bytes()
    with pytest.raises(LedgerError, match="untagged pre-0.31 entry at seq 0"):
        verify_chain(legacy_ledger, key=KEY)
    assert legacy_ledger.read_bytes() == before


def test_budget_on_a_legacy_ledger_fails_closed(legacy_ledger):
    budget = EpsilonBudget(10.0, 1e-5, Ledger(legacy_ledger, key=KEY))
    with pytest.raises(LedgerError, match="untagged pre-0.31"):
        budget.spent()


def test_stripping_the_canon_tag_is_rejected(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    ledger.append("e", {"a": "1"})
    rows = _lines(ledger.path)
    del rows[0]["canon"]
    ledger.path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="untagged pre-0.31"):
        verify_chain(ledger.path, key=KEY)


@pytest.mark.parametrize("tag", [0, 2, True])
def test_other_canon_tags_are_rejected(tmp_path, tag):
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    ledger.append("e", {"a": "1"})
    rows = _lines(ledger.path)
    rows[0]["canon"] = tag
    ledger.path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="unsupported canon"):
        verify_chain(ledger.path, key=KEY)


@pytest.mark.parametrize("tag", [0, 2, True, None])
def test_canonical_for_supports_only_the_strict_tag(tag):
    with pytest.raises(CanonicalError, match="unsupported canon tag"):
        canonical_for(tag)


def test_new_ledger_entries_reject_floats(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    with pytest.raises(LedgerError, match="not canonical"):
        ledger.append("e", {"epsilon": 1.5})
    assert not ledger.path.exists()


@pytest.mark.parametrize("value", [1.5, True, None, [1], "nan", "inf", "x"])
def test_recorded_parameters_must_be_exact(value):
    with pytest.raises(ValueError):
        _as_decimal(value)


def test_untagged_request_is_rejected():
    with pytest.raises(ValueError, match="untagged authorization request"):
        request_hash(APPROVALS["pending_request"])


def test_pre_upgrade_approvals_no_longer_authorize():
    job_id, result = _pending()
    with pytest.raises(MPADenied):
        authorize_request(
            result,
            job_id=job_id,
            policy=POLICY,
            approvals=APPROVALS["pending_approvals"],
            approver_keys=APPROVER_KEYS,
        )


def test_new_requests_are_tagged_and_float_free():
    job_id, result = _pending()
    request = build_request(result, job_id=job_id)
    assert request["canon"] == CANON_STRICT
    assert not any(isinstance(v, float) for v in request.values())
    assert request_hash(request) != APPROVALS["pending_request_hash"]
    with pytest.raises(ValueError, match="unsupported request canon"):
        request_hash({**request, "canon": 2})


def test_re_signed_approvals_authorize_and_are_recorded(tmp_path):
    job_id, result = _pending()
    new_hash = request_hash(build_request(result, job_id=job_id))
    approvals = {
        a: sign_approval(new_hash, approver_id=a, approver_key=APPROVER_KEYS[a])
        for a in ("alice", "bob")
    }
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    EpsilonBudget(10.0, 1e-5, ledger).charge(
        result, job_id=job_id, policy=POLICY, approvals=approvals, approver_keys=APPROVER_KEYS
    )
    entries = verify_chain(ledger.path, key=KEY)
    auth = [e for e in entries if e.event == AUTHORIZED_EVENT][0]
    assert auth.payload["request_canon"] == 1 and auth.payload["request_hash"] == new_hash
    charge = [e for e in entries if e.event == CHARGE_EVENT][0]
    assert charge.payload["epsilon"] == result.signed_dict()["epsilon"]
