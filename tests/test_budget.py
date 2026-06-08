from __future__ import annotations

import pytest

from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.dp.budget import CHARGE_EVENT, BudgetExceeded, EpsilonBudget
from presidio_ai.ledger import Ledger, LedgerError

KEY = "budget-key"


def _ledger(tmp_path, name="ledger.jsonl"):
    return Ledger(tmp_path / name, key=KEY)


def test_charge_records_and_decrements(tmp_path):
    ledger = _ledger(tmp_path)
    budget = EpsilonBudget(total_epsilon=10.0, delta=1e-5, ledger=ledger)
    r = dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.01, steps=500, delta=1e-5)
    charge = budget.charge(r, job_id="ft-1")

    assert charge.spent_epsilon == pytest.approx(r.epsilon)
    assert charge.remaining_epsilon == pytest.approx(10.0 - r.epsilon)
    # Persisted as a ledger entry, re-derivable from a fresh handle.
    reopened = EpsilonBudget(10.0, 1e-5, Ledger(tmp_path / "ledger.jsonl", key=KEY))
    assert reopened.spent() == pytest.approx(r.epsilon)


def test_charges_compose_additively(tmp_path):
    budget = EpsilonBudget(100.0, 1e-5, _ledger(tmp_path))
    a = budget.charge_dpsgd(job_id="a", noise_multiplier=1.0, sample_rate=0.01, steps=200)
    b = budget.charge_dpsgd(job_id="b", noise_multiplier=1.0, sample_rate=0.01, steps=200)
    assert budget.spent() == pytest.approx(a.result.epsilon + b.result.epsilon)
    assert b.spent_epsilon == pytest.approx(a.result.epsilon + b.result.epsilon)


def test_budget_exceeded_raises_and_is_not_recorded(tmp_path):
    ledger = _ledger(tmp_path)
    budget = EpsilonBudget(total_epsilon=0.001, delta=1e-5, ledger=ledger)
    with pytest.raises(BudgetExceeded):
        budget.charge_dpsgd(job_id="too-big", noise_multiplier=1.0, sample_rate=0.05, steps=5000)
    # Rejected charge leaves no entry.
    assert budget.spent() == 0.0
    charges = [e for e in ledger.entries() if e.event == CHARGE_EVENT]
    assert charges == []


def test_charge_payload_is_privacy_params_only(tmp_path):
    budget = EpsilonBudget(10.0, 1e-5, _ledger(tmp_path))
    budget.charge_dpsgd(job_id="ft", noise_multiplier=1.1, sample_rate=0.01, steps=100)
    payload = [e.payload for e in budget.ledger.entries() if e.event == CHARGE_EVENT][0]
    assert set(payload) >= {
        "job_id",
        "epsilon",
        "delta",
        "noise_multiplier",
        "sample_rate",
        "steps",
    }


def test_spent_fails_closed_on_tamper(tmp_path):
    ledger = _ledger(tmp_path)
    budget = EpsilonBudget(10.0, 1e-5, ledger)
    budget.charge_dpsgd(job_id="ft", noise_multiplier=1.0, sample_rate=0.01, steps=100)
    path = tmp_path / "ledger.jsonl"
    import json

    rec = json.loads(path.read_text().splitlines()[0])
    rec["payload"]["epsilon"] = 0.0  # try to hide the spend
    path.write_text(json.dumps(rec) + "\n")
    with pytest.raises(LedgerError):
        budget.spent()


def test_invalid_budget_params():
    import pathlib

    lg = Ledger(pathlib.Path("/tmp") / "x.jsonl", key=KEY)  # noqa: S108 - not written in this test
    with pytest.raises(ValueError):
        EpsilonBudget(0.0, 1e-5, lg)
    with pytest.raises(ValueError):
        EpsilonBudget(1.0, 0.0, lg)


def test_charge_requires_job_id(tmp_path):
    budget = EpsilonBudget(10.0, 1e-5, _ledger(tmp_path))
    r = dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.01, steps=10, delta=1e-5)
    with pytest.raises(ValueError):
        budget.charge(r, job_id="")
