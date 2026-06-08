from __future__ import annotations

import pytest

from presidio_ai.ingest import ingest_records
from presidio_ai.ledger import Ledger, verify_chain

KEY = "k"


def _ledger(tmp_path):
    return Ledger(tmp_path / "ledger.jsonl", key=KEY)


def test_ingest_scrubs_and_records_lineage(tmp_path):
    ledger = _ledger(tmp_path)
    records = [{"id": 1, "note": "call alice@example.com"}, {"id": 2, "note": "clean"}]
    result = ingest_records(records, source_id="crm-export", ledger=ledger)

    assert result.n_records == 2
    assert result.redaction_counts["EMAIL_ADDRESS"] == 1
    assert result.records[0]["note"] == "call <EMAIL_ADDRESS>"
    assert result.records[0]["id"] == 1  # non-string field untouched
    assert result.ledger_seq == 0
    assert len(verify_chain(tmp_path / "ledger.jsonl", key=KEY)) == 1


def test_ledger_holds_no_pii(tmp_path):
    ledger = _ledger(tmp_path)
    ingest_records([{"note": "ssn 123-45-6789 mail x@y.com"}], source_id="s", ledger=ledger)
    raw = (tmp_path / "ledger.jsonl").read_text()
    assert "123-45-6789" not in raw
    assert "x@y.com" not in raw
    assert "redaction_counts" in raw  # commitments/counts are present


def test_content_hash_is_deterministic(tmp_path):
    r1 = ingest_records([{"note": "a@b.com"}], source_id="s", ledger=_ledger(tmp_path))
    r2 = ingest_records([{"note": "a@b.com"}], source_id="s", ledger=_ledger(tmp_path / "x"))
    assert r1.content_hash == r2.content_hash


def test_string_records_become_text_field(tmp_path):
    result = ingest_records(["mail a@b.com"], source_id="s", ledger=_ledger(tmp_path))
    assert result.records[0]["text"] == "mail <EMAIL_ADDRESS>"


def test_fields_restriction(tmp_path):
    records = [{"keep": "a@b.com", "scrub": "c@d.com"}]
    result = ingest_records(records, source_id="s", ledger=_ledger(tmp_path), fields=["scrub"])
    assert result.records[0]["keep"] == "a@b.com"
    assert result.records[0]["scrub"] == "<EMAIL_ADDRESS>"


def test_empty_source_id_rejected(tmp_path):
    with pytest.raises(ValueError):
        ingest_records([], source_id="", ledger=_ledger(tmp_path))


def test_bad_record_type_rejected(tmp_path):
    with pytest.raises(TypeError):
        ingest_records([123], source_id="s", ledger=_ledger(tmp_path))
