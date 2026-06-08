"""Tests for the secure-aggregation wire format (P4 / [mpc] lane)."""

from __future__ import annotations

import pytest

from presidio_ai.fl.secure_agg import PRIME
from presidio_ai.fl.transport import (
    TransportError,
    decode_submission,
    encode_submission,
)


def test_submission_roundtrip():
    payload = encode_submission("bankA", "r1", [1, 2, 3])
    sub = decode_submission(payload, expected_dim=3)
    assert sub.party_id == "bankA" and sub.round_id == "r1" and sub.masked == [1, 2, 3]


def test_decode_rejects_wrong_dim():
    payload = encode_submission("a", "r1", [1, 2])
    with pytest.raises(TransportError, match="length 3"):
        decode_submission(payload, expected_dim=3)


def test_decode_rejects_out_of_field_elements():
    bad = {"party_id": "a", "round_id": "r1", "masked": [PRIME]}  # == prime, not < prime
    with pytest.raises(TransportError, match="field integers"):
        decode_submission(bad)
    neg = {"party_id": "a", "round_id": "r1", "masked": [-1]}
    with pytest.raises(TransportError, match="field integers"):
        decode_submission(neg)


def test_decode_rejects_bool_disguised_as_int():
    bad = {"party_id": "a", "round_id": "r1", "masked": [True]}
    with pytest.raises(TransportError, match="field integers"):
        decode_submission(bad)


def test_decode_rejects_malformed_envelope():
    with pytest.raises(TransportError):
        decode_submission("not a dict")
    with pytest.raises(TransportError, match="party_id"):
        decode_submission({"round_id": "r1", "masked": [1]})
    with pytest.raises(TransportError, match="non-empty list"):
        decode_submission({"party_id": "a", "round_id": "r1", "masked": []})
