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


def test_verify_missing_file_raises_unless_missing_ok(tmp_path):
    with pytest.raises(LedgerError, match="missing"):
        verify_chain(tmp_path / "nope.jsonl", key=KEY)
    assert verify_chain(tmp_path / "nope.jsonl", key=KEY, missing_ok=True) == []
    with pytest.raises(LedgerError, match="missing"):
        verify_chain(tmp_path / "nope.jsonl", key=KEY, missing_ok=True, min_entries=1)


# --- truncation / deletion against an anchor (audit 2026-11-03) -------------


def _three(path):
    led = Ledger(path, key=KEY)
    for i in range(3):
        led.append("e", {"i": i})
    return led


def _truncate(path, keep):
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:keep]))


def test_suffix_truncation_verifies_without_anchor_but_not_with_one(tmp_path):
    path = tmp_path / "l.jsonl"
    led = _three(path)
    anchor = led.anchor
    assert anchor == (2, led.head_hash)
    _truncate(path, 1)
    assert len(verify_chain(path, key=KEY)) == 1  # the limitation, stated in the docs
    with pytest.raises(LedgerError, match="truncated"):
        verify_chain(path, key=KEY, anchor=anchor)
    with pytest.raises(LedgerError, match="truncated"):
        verify_chain(path, key=KEY, min_entries=3)


def test_anchor_detects_replaced_tail_and_allows_growth(tmp_path):
    path = tmp_path / "l.jsonl"
    led = _three(path)
    anchor = led.anchor
    led.append("e", {"i": 3})
    assert len(verify_chain(path, key=KEY, anchor=anchor)) == 4  # growth past the anchor is fine
    # Roll back to two entries and append a different third one (keyed writer).
    _truncate(path, 2)
    Ledger(path, key=KEY).append("e", {"i": "other"})
    with pytest.raises(LedgerError, match="anchor"):
        verify_chain(path, key=KEY, anchor=anchor)


def test_anchor_must_be_a_non_negative_int(tmp_path):
    path = tmp_path / "l.jsonl"
    _three(path)
    for bad in (-1, True, "1"):
        with pytest.raises(LedgerError, match="anchor"):
            verify_chain(path, key=KEY, anchor=(bad, "0" * 64))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_file_permissions_0600(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("a", {"i": 0})
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


# --- malformed ledger files fail with LedgerError, not a raw exception -------

_GOOD = {
    "seq": 0,
    "timestamp": "t",
    "event": "e",
    "payload": {},
    "prev_hash": GENESIS_HASH,
    "entry_hash": "00",
    "canon": 1,
}


def _line(**changes):
    rec = {**_GOOD, **changes}
    return json.dumps({k: v for k, v in rec.items() if v is not _DROP}).encode()


_DROP = object()


@pytest.mark.parametrize(
    "data",
    [
        b"not json",
        b"[1, 2]",
        b'"a string"',
        b"\xff\xfe",
        b'{"seq": 0}',
        _line(extra="x"),
        _line(timestamp=_DROP),
        _line(seq="0"),
        _line(seq=True),
        _line(canon="1"),
        _line(canon=False),
        _line(payload=[]),
        _line(event=None),
        _line(entry_hash=5),
        _line(prev_hash=[]),
    ],
    ids=lambda d: d[:24].decode("utf-8", "replace"),
)
def test_malformed_entry_raises_ledger_error(tmp_path, data):
    path = tmp_path / "bad.jsonl"
    path.write_bytes(data + b"\n")
    with pytest.raises(LedgerError):
        verify_chain(path, key=KEY)
    with pytest.raises(LedgerError):
        Ledger(path, key=KEY)


@pytest.mark.parametrize("bad", ["é" * 64, "\ud800" * 64])
def test_non_ascii_entry_hash_is_a_mac_mismatch(tmp_path, bad):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("data-ingested", {"n_records": 1})
    record = json.loads(path.read_text())
    record["entry_hash"] = bad
    path.write_text(json.dumps(record) + "\n")
    with pytest.raises(LedgerError, match="MAC mismatch"):
        verify_chain(path, key=KEY)


def test_non_ascii_anchor_hash_does_not_match(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("data-ingested", {"n_records": 1})
    with pytest.raises(LedgerError, match="anchor"):
        verify_chain(path, key=KEY, anchor=(0, "é" * 64))
