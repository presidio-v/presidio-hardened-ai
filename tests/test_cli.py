from __future__ import annotations

import json

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
