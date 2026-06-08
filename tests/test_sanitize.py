from __future__ import annotations

import pytest

from presidio_ai import sanitize as s


def test_validate_identifier_ok():
    assert s.validate_identifier("fraud-scoring") == "fraud-scoring"


@pytest.mark.parametrize("bad", ["", "   ", "x" * 300, "a\x00b", "a\nb"])
def test_validate_identifier_rejects(bad):
    with pytest.raises(s.ValidationError):
        s.validate_identifier(bad)


def test_validate_path_ok():
    assert s.validate_path("data/in.jsonl") == "data/in.jsonl"


@pytest.mark.parametrize("bad", ["", "x\x00y", "p" * 5000])
def test_validate_path_rejects(bad):
    with pytest.raises(s.ValidationError):
        s.validate_path(bad)


def test_pii_action_and_mode():
    assert s.validate_pii_action("redact") == "redact"
    assert s.validate_pii_mode("nlp") == "nlp"
    with pytest.raises(s.ValidationError):
        s.validate_pii_action("delete")
    with pytest.raises(s.ValidationError):
        s.validate_pii_mode("ml")


def test_escape():
    assert s.escape("<b>&'\"") == "&lt;b&gt;&amp;&#x27;&quot;"
