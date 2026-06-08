from __future__ import annotations

import pytest

from presidio_ai.pii import PIIBlockedError, PIIScrubber


def test_redacts_email_and_counts():
    s = PIIScrubber()
    result = s.scrub("Contact alice@example.com please")
    assert "alice@example.com" not in result.text
    assert "<EMAIL_ADDRESS>" in result.text
    assert result.counts["EMAIL_ADDRESS"] == 1
    assert result.total == 1


def test_detects_ssn_and_credit_card():
    s = PIIScrubber()
    r = s.scrub("SSN 123-45-6789 card 4111 1111 1111 1111")
    assert r.counts.get("US_SSN") == 1
    assert r.counts.get("CREDIT_CARD") == 1
    assert "123-45-6789" not in r.text


def test_block_action_raises():
    s = PIIScrubber(action="block")
    with pytest.raises(PIIBlockedError):
        s.scrub("email me at bob@example.org")


def test_warn_action_keeps_text_but_counts():
    s = PIIScrubber(action="warn")
    r = s.scrub("bob@example.org")
    assert r.text == "bob@example.org"
    assert r.counts["EMAIL_ADDRESS"] == 1


def test_clean_text_passthrough():
    s = PIIScrubber()
    r = s.scrub("nothing sensitive here")
    assert r.text == "nothing sensitive here"
    assert r.total == 0


def test_empty_text():
    assert PIIScrubber().scrub("").total == 0


def test_entity_subset():
    s = PIIScrubber(entities=("EMAIL_ADDRESS",))
    r = s.scrub("a@b.com 123-45-6789")
    assert r.counts.get("EMAIL_ADDRESS") == 1
    assert "US_SSN" not in r.counts  # SSN not in the configured entity set


def test_invalid_action_and_mode():
    with pytest.raises(ValueError):
        PIIScrubber(action="nope")
    with pytest.raises(ValueError):
        PIIScrubber(mode="nope")


def test_nlp_mode_falls_back_to_regex_without_extra():
    # presidio-analyzer is not installed in the base test env.
    s = PIIScrubber(mode="nlp")
    assert s.effective_mode == "regex"
    assert s.scrub("x@y.com").counts["EMAIL_ADDRESS"] == 1
