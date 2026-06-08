from __future__ import annotations

import json
import os
import stat

import pytest

from presidio_ai.ledger import GENESIS_HASH, Ledger, LedgerError, verify_chain

KEY = "test-ledger-key"


def test_append_and_verify(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path, key=KEY)
    e0 = ledger.append("data-ingested", {"n_records": 3})
    e1 = ledger.append("data-ingested", {"n_records": 5})

    assert e0.seq == 0 and e1.seq == 1
    assert e0.prev_hash == GENESIS_HASH
    assert e1.prev_hash == e0.entry_hash

    entries = verify_chain(path, key=KEY)
    assert [e.seq for e in entries] == [0, 1]
    assert ledger.head_hash == e1.entry_hash


def test_resume_existing_ledger(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("a", {"x": 1})
    # New handle should continue the chain, not restart it.
    reopened = Ledger(path, key=KEY)
    e1 = reopened.append("b", {"x": 2})
    assert e1.seq == 1
    assert len(verify_chain(path, key=KEY)) == 2


def test_tamper_payload_detected(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path, key=KEY)
    ledger.append("a", {"n_records": 1})
    ledger.append("b", {"n_records": 2})

    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["payload"]["n_records"] = 999  # edit content, keep the old hash
    lines[0] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(LedgerError, match="MAC mismatch"):
        verify_chain(path, key=KEY)


def test_reorder_detected(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path, key=KEY)
    ledger.append("a", {"i": 0})
    ledger.append("b", {"i": 1})
    lines = path.read_text().splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n")
    with pytest.raises(LedgerError):
        verify_chain(path, key=KEY)


def test_wrong_key_fails(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("a", {"i": 0})
    with pytest.raises(LedgerError, match="MAC mismatch"):
        verify_chain(path, key="another-key")


def test_missing_key_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("PRESIDIO_AI_LEDGER_KEY", raising=False)
    with pytest.raises(LedgerError, match="No ledger key"):
        Ledger(tmp_path / "l.jsonl")


def test_key_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    path = tmp_path / "l.jsonl"
    Ledger(path).append("a", {"i": 0})
    assert len(verify_chain(path)) == 1


def test_empty_event_rejected(tmp_path):
    with pytest.raises(LedgerError):
        Ledger(tmp_path / "l.jsonl", key=KEY).append("")


def test_verify_missing_file_is_empty(tmp_path):
    assert verify_chain(tmp_path / "nope.jsonl", key=KEY) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_file_permissions_0600(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("a", {"i": 0})
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
