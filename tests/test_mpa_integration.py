from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.dp.authorization import (
    MPADenied,
    MPAPolicy,
    build_request,
    request_hash,
    sign_approval,
)
from presidio_ai.dp.budget import AUTHORIZED_EVENT, CHARGE_EVENT, EpsilonBudget
from presidio_ai.ledger import Ledger

KEY = "ledger-key"
APPROVERS = {"alice": "ka", "bob": "kb", "carol": "kc"}
PARAMS = dict(noise_multiplier=1.0, sample_rate=0.05, steps=2000)


def _budget(tmp_path, total=100.0):
    return EpsilonBudget(total, 1e-5, Ledger(tmp_path / "ledger.jsonl", key=KEY))


def _approvals(job_id, who):
    result = dpsgd_epsilon(delta=1e-5, **PARAMS)
    rh = request_hash(build_request(result, job_id=job_id))
    return {a: sign_approval(rh, approver_id=a, approver_key=APPROVERS[a]) for a in who}


def test_high_epsilon_requires_and_records_authorization(tmp_path):
    budget = _budget(tmp_path)
    policy = MPAPolicy(threshold=2, min_epsilon=0.0, approvers=tuple(sorted(APPROVERS)))
    charge = budget.charge_dpsgd(
        job_id="ft",
        **PARAMS,
        policy=policy,
        approvals=_approvals("ft", ["alice", "bob"]),
        approver_keys=APPROVERS,
    )
    assert charge.result.epsilon > 0
    events = [e.event for e in budget.ledger.entries()]
    assert events == [AUTHORIZED_EVENT, CHARGE_EVENT]  # auth recorded before charge
    auth = budget.ledger.entries()[0].payload
    assert auth["approvers"] == ["alice", "bob"] and auth["threshold"] == 2


def test_insufficient_approval_denies_and_records_nothing(tmp_path):
    budget = _budget(tmp_path)
    policy = MPAPolicy(threshold=2, min_epsilon=0.0, approvers=tuple(sorted(APPROVERS)))
    with pytest.raises(MPADenied):
        budget.charge_dpsgd(
            job_id="ft",
            **PARAMS,
            policy=policy,
            approvals=_approvals("ft", ["alice"]),  # only 1 of 2
            approver_keys=APPROVERS,
        )
    assert budget.ledger.entries() == []
    assert budget.spent() == 0.0


def test_below_min_epsilon_skips_authorization(tmp_path):
    budget = _budget(tmp_path)
    policy = MPAPolicy(threshold=2, min_epsilon=1e9, approvers=tuple(sorted(APPROVERS)))
    # No approvals supplied, but epsilon is below the threshold so none are required.
    charge = budget.charge_dpsgd(job_id="ft", **PARAMS, policy=policy, approver_keys=APPROVERS)
    assert charge.result.epsilon > 0
    assert [e.event for e in budget.ledger.entries()] == [CHARGE_EVENT]


# ── CLI ──────────────────────────────────────────────────────────────────────
runner = CliRunner()


def _cli_approval(approver):
    r = runner.invoke(
        app,
        [
            "dp-authorize",
            "--job-id",
            "ft",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.05",
            "--steps",
            "2000",
            "--delta",
            "1e-5",
            "--approver",
            approver,
            "--approver-key",
            APPROVERS[approver],
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    return json.loads(r.stdout)["approval"]


def test_cli_mpa_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    keyfile = tmp_path / "approvers.json"
    keyfile.write_text(json.dumps(APPROVERS))
    ledger = tmp_path / "ledger.jsonl"

    approvals = [_cli_approval("alice"), _cli_approval("bob")]
    r = runner.invoke(
        app,
        [
            "dp-charge",
            "--ledger",
            str(ledger),
            "--total-epsilon",
            "100",
            "--job-id",
            "ft",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.05",
            "--steps",
            "2000",
            "--mpa-threshold",
            "2",
            "--mpa-min-epsilon",
            "0",
            "--approver-keys",
            str(keyfile),
            "--approval",
            approvals[0],
            "--approval",
            approvals[1],
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    assert json.loads(r.stdout)["epsilon"] > 0


def test_cli_mpa_denied_exit_3(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    keyfile = tmp_path / "approvers.json"
    keyfile.write_text(json.dumps(APPROVERS))
    r = runner.invoke(
        app,
        [
            "dp-charge",
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--total-epsilon",
            "100",
            "--job-id",
            "ft",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.05",
            "--steps",
            "2000",
            "--mpa-threshold",
            "2",
            "--mpa-min-epsilon",
            "0",
            "--approver-keys",
            str(keyfile),
            "--approval",
            _cli_approval("alice"),
        ],  # only 1 of 2
    )
    assert r.exit_code == 3
