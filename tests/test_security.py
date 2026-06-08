from __future__ import annotations

import json

from presidio_ai import security


def test_log_writes_structural_event(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path))
    security.log_security_event({"event": "pai-ingest-complete", "n_records": 3})
    log = (tmp_path / "security.log").read_text().strip()
    record = json.loads(log)
    assert record["event"] == "pai-ingest-complete"
    assert record["n_records"] == 3
    assert "ts" in record


def test_session_counter(monkeypatch):
    security.reset_session_count()
    assert security.increment_session_count() == 1
    assert security.increment_session_count() == 2
    security.reset_session_count()
    assert security.increment_session_count() == 1


def test_session_limit_env(monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_MAX_OPS", "5")
    assert security.session_limit() == 5
    monkeypatch.setenv("PRESIDIO_AI_MAX_OPS", "not-an-int")
    assert security.session_limit() == 1000


def test_log_is_best_effort_on_bad_home(monkeypatch, tmp_path):
    # Point HOME at a file so mkdir fails; logging must not raise.
    bad = tmp_path / "afile"
    bad.write_text("x")
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(bad / "sub"))
    security.log_security_event({"event": "x"})
