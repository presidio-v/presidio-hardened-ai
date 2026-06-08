from __future__ import annotations

import json

from typer.testing import CliRunner

from presidio_ai.cli import app

runner = CliRunner()
KEY = "cli-dp-key"


def test_dp_account_quiet():
    r = runner.invoke(
        app,
        [
            "dp-account",
            "--noise-multiplier",
            "1.1",
            "--sample-rate",
            "0.01",
            "--steps",
            "1000",
            "--delta",
            "1e-5",
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    out = json.loads(r.stdout)
    assert out["epsilon"] > 0
    assert out["accountant"] == "rdp-subsampled-gaussian"


def test_dp_account_invalid_exits_1():
    r = runner.invoke(
        app,
        ["dp-account", "--noise-multiplier", "0", "--sample-rate", "0.1", "--steps", "10"],
    )
    assert r.exit_code == 1


def test_dp_charge_and_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    ledger = tmp_path / "ledger.jsonl"
    evidence = tmp_path / "dp-evidence.json"

    charge = runner.invoke(
        app,
        [
            "dp-charge",
            "--ledger",
            str(ledger),
            "--total-epsilon",
            "10",
            "--job-id",
            "ft-1",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.01",
            "--steps",
            "500",
            "--delta",
            "1e-5",
            "--evidence-out",
            str(evidence),
            "--algorithm",
            "hmac-sha256",
            "--quiet",
        ],
    )
    assert charge.exit_code == 0, charge.stdout
    summary = json.loads(charge.stdout)
    assert summary["epsilon"] > 0
    assert summary["evidence"][0]["item_id"] == "D4"
    assert json.loads(evidence.read_text())["evidence"][0]["item_id"] == "D4"

    status = runner.invoke(
        app, ["dp-budget", "--ledger", str(ledger), "--total-epsilon", "10", "--quiet"]
    )
    assert status.exit_code == 0
    st = json.loads(status.stdout)
    assert st["spent"] == summary["epsilon"]
    assert st["remaining"] < 10


def test_dp_charge_over_budget_exits_2(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    r = runner.invoke(
        app,
        [
            "dp-charge",
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--total-epsilon",
            "0.001",
            "--job-id",
            "big",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.05",
            "--steps",
            "5000",
        ],
    )
    assert r.exit_code == 2
