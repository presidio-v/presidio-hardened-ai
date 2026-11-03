from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app

runner = CliRunner()
KEY = "cli-key"


def _write_jsonl(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_ingest_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    inp = tmp_path / "in.jsonl"
    _write_jsonl(inp, [{"note": "mail alice@example.com"}, {"note": "ok"}])
    ledger = tmp_path / "ledger.jsonl"
    out = tmp_path / "scrubbed.jsonl"
    evidence = tmp_path / "evidence.json"

    result = runner.invoke(
        app,
        [
            "ingest",
            "--source",
            "crm",
            "--input",
            str(inp),
            "--ledger",
            str(ledger),
            "--out",
            str(out),
            "--evidence-out",
            str(evidence),
            "--use-case",
            "fraud",
            "--algorithm",
            "hmac-sha256",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.stdout
    summary = json.loads(result.stdout)
    assert summary["n_records"] == 2
    assert summary["redaction_counts"]["EMAIL_ADDRESS"] == 1
    assert len(summary["evidence"]) == 3

    assert "alice@example.com" not in out.read_text()
    assert "alice@example.com" not in ledger.read_text()
    doc = json.loads(evidence.read_text())
    assert {e["item_id"] for e in doc["evidence"]} == {"D1", "D4", "O5"}


def test_verify_ok(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    inp = tmp_path / "in.jsonl"
    _write_jsonl(inp, [{"note": "ok"}])
    ledger = tmp_path / "ledger.jsonl"
    runner.invoke(app, ["ingest", "--source", "s", "--input", str(inp), "--ledger", str(ledger)])

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--quiet"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["ok"] is True


def test_verify_detects_tamper(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    inp = tmp_path / "in.jsonl"
    _write_jsonl(inp, [{"note": "ok"}])
    ledger = tmp_path / "ledger.jsonl"
    runner.invoke(app, ["ingest", "--source", "s", "--input", str(inp), "--ledger", str(ledger)])

    rec = json.loads(ledger.read_text().splitlines()[0])
    rec["payload"]["n_records"] = 99
    ledger.write_text(json.dumps(rec) + "\n")

    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--quiet"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["ok"] is False


def test_verify_reports_corrupt_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b"not json\n")
    result = runner.invoke(app, ["verify", "--ledger", str(ledger), "--quiet"])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert json.loads(result.stdout)["ok"] is False


def test_missing_key_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("PRESIDIO_AI_LEDGER_KEY", raising=False)
    result = runner.invoke(app, ["verify", "--ledger", str(tmp_path / "l.jsonl")])
    assert result.exit_code == 1


def test_block_action_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    inp = tmp_path / "in.jsonl"
    _write_jsonl(inp, [{"note": "a@b.com"}])
    result = runner.invoke(
        app,
        [
            "ingest",
            "--source",
            "s",
            "--input",
            str(inp),
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--pii-action",
            "block",
        ],
    )
    assert result.exit_code == 1


def test_consortium_round_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    spec = {
        "round_id": "r1",
        "delta": 1e-5,
        "dim": 3,
        "threshold": 2,
        "updates": {
            "bankA": [0.1, 0.2, 0.3],
            "bankB": [0.0, -0.1, 0.4],
            "bankC": [0.2, 0.2, -0.2],
        },
        "dp": {
            "bankA": {"noise_multiplier": 1.1, "sample_rate": 0.01, "steps": 50},
            "bankB": {"noise_multiplier": 1.1, "sample_rate": 0.01, "steps": 50},
            "bankC": {"noise_multiplier": 1.1, "sample_rate": 0.01, "steps": 50},
        },
    }
    round_file = tmp_path / "round.json"
    round_file.write_text(json.dumps(spec))
    ledger = tmp_path / "round.jsonl"
    evidence = tmp_path / "round.evidence.json"
    result = runner.invoke(
        app,
        [
            "consortium-round",
            "--round-file",
            str(round_file),
            "--ledger",
            str(ledger),
            "--budget-dir",
            str(tmp_path / "budgets"),
            "--evidence-out",
            str(evidence),
            "--algorithm",
            "hmac-sha256",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.stdout
    summary = json.loads(result.stdout)
    assert summary["n_survivors"] == 3
    assert summary["dropped"] == []
    expected = [sum(spec["updates"][p][k] for p in spec["updates"]) for k in range(3)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(summary["aggregate"], expected, strict=True))
    assert evidence.exists()
    assert (tmp_path / "budgets" / "bankA.jsonl").exists()


def _hostile_round(tmp_path, silo):
    dp = {"noise_multiplier": 1.1, "sample_rate": 0.01, "steps": 50}
    spec = {
        "round_id": "r1",
        "delta": 1e-5,
        "dim": 2,
        "threshold": 2,
        "updates": {"bankA": [0.1, 0.2], silo: [0.0, -0.1], "bankC": [0.2, 0.2]},
        "dp": {"bankA": dp, silo: dp, "bankC": dp},
    }
    round_file = tmp_path / "round.json"
    round_file.write_text(json.dumps(spec))
    return round_file


@pytest.mark.parametrize("silo", ["../escaped", "/abs/silo", "x/../bankA", ".hidden", "a\\b", ""])
def test_consortium_round_rejects_path_like_silo_ids(tmp_path, monkeypatch, silo):
    """Audit 2026-11-03: silo ids from the round file name per-silo ledger files."""
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    work = tmp_path / "work"
    work.mkdir()
    budgets = work / "budgets"
    result = runner.invoke(
        app,
        [
            "consortium-round",
            "--round-file",
            str(_hostile_round(work, silo)),
            "--ledger",
            str(work / "round.jsonl"),
            "--budget-dir",
            str(budgets),
            "--algorithm",
            "hmac-sha256",
            "--quiet",
        ],
    )
    assert result.exit_code == 1
    assert "silo id" in result.output
    written = {p for p in tmp_path.rglob("*.jsonl")}
    assert written == set(), written  # nothing written anywhere, inside or outside budgets


def test_consortium_round_rejects_silo_ledger_that_is_the_round_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    result = runner.invoke(
        app,
        [
            "consortium-round",
            "--round-file",
            str(_hostile_round(tmp_path, "round")),
            "--ledger",
            str(tmp_path / "round.jsonl"),
            "--budget-dir",
            str(tmp_path),
            "--algorithm",
            "hmac-sha256",
            "--quiet",
        ],
    )
    assert result.exit_code == 1
    assert "round ledger" in result.output


def test_verify_missing_ledger_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    result = runner.invoke(app, ["verify", "--ledger", str(tmp_path / "nope.jsonl"), "-q"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["ok"] is False


def test_verify_expect_entry_detects_truncation(tmp_path, monkeypatch):
    from presidio_ai.ledger import Ledger

    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    path = tmp_path / "l.jsonl"
    led = Ledger(path, key=KEY)
    for i in range(3):
        led.append("e", {"i": i})
    seq, head = led.anchor
    args = ["verify", "--ledger", str(path), "--expect-entry", f"{seq}:{head}", "-q"]
    assert runner.invoke(app, args).exit_code == 0
    path.write_text("".join(path.read_text().splitlines(keepends=True)[:1]))
    assert runner.invoke(app, ["verify", "--ledger", str(path), "-q"]).exit_code == 0
    assert runner.invoke(app, args).exit_code == 1
    short = ["verify", "--ledger", str(path), "--min-entries", "3", "-q"]
    assert runner.invoke(app, short).exit_code == 1
    bad = ["verify", "--ledger", str(path), "--expect-entry", "x:y", "-q"]
    assert runner.invoke(app, bad).exit_code == 1
