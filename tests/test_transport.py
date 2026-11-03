"""Tests for the secure-aggregation wire format (P4 / [mpc] lane)."""

from __future__ import annotations

import random

import pytest

from presidio_ai.evidence import generate_ed25519_keypair
from presidio_ai.fl.secure_agg import PRIME, SecureAggregationSession, dequantize
from presidio_ai.fl.transport import (
    RoundCoordinator,
    TransportError,
    decode_submission,
    encode_command,
    encode_submission,
)

_KEYS = {p: generate_ed25519_keypair() for p in ("A", "B", "C", "bankA", "a", "coord")}
PRIV = {p: k[0] for p, k in _KEYS.items()}
TRUST = {p: k[1] for p, k in _KEYS.items()}


def test_submission_roundtrip():
    payload = encode_submission("bankA", "r1", [1, 2, 3], private_key_hex=PRIV["bankA"])
    sub = decode_submission(payload, expected_dim=3)
    assert sub.party_id == "bankA" and sub.round_id == "r1" and sub.masked == [1, 2, 3]


def test_decode_rejects_wrong_dim():
    payload = encode_submission("a", "r1", [1, 2], private_key_hex=PRIV["a"])
    with pytest.raises(TransportError, match="length 3"):
        decode_submission(payload, expected_dim=3)


def test_decode_rejects_out_of_field_elements():
    bad = {"party_id": "a", "round_id": "r1", "masked": [PRIME], "signature": "00"}  # == prime
    with pytest.raises(TransportError, match="field integers"):
        decode_submission(bad)
    neg = {"party_id": "a", "round_id": "r1", "masked": [-1], "signature": "00"}
    with pytest.raises(TransportError, match="field integers"):
        decode_submission(neg)


def test_decode_rejects_bool_disguised_as_int():
    bad = {"party_id": "a", "round_id": "r1", "masked": [True], "signature": "00"}
    with pytest.raises(TransportError, match="field integers"):
        decode_submission(bad)


def test_decode_rejects_malformed_envelope():
    with pytest.raises(TransportError):
        decode_submission("not a dict")
    with pytest.raises(TransportError, match="party_id"):
        decode_submission({"round_id": "r1", "masked": [1]})
    with pytest.raises(TransportError, match="non-empty list"):
        decode_submission({"party_id": "a", "round_id": "r1", "masked": [], "signature": "00"})


def test_decode_requires_a_signature_field():
    with pytest.raises(TransportError, match="signature"):
        decode_submission({"party_id": "a", "round_id": "r1", "masked": [1]})


# --- RoundCoordinator: authenticated, one-shot round (audit 2026-11-03) -------

INPUTS = {"A": [1.0, 2.0], "B": [3.0, 4.0], "C": [0.25, -0.5]}


def _round():
    sess = SecureAggregationSession(["A", "B", "C"], dim=2, threshold=2, rng=random.Random(7))  # noqa: S311
    masked = {p: sess.mask(p, v) for p, v in INPUTS.items()}
    coord = RoundCoordinator(sess, round_id="r1", identity_trust=TRUST, coordinator_id="coord")
    return coord, masked


def _sub(pid, masked, key=None, round_id="r1"):
    return encode_submission(pid, round_id, masked[pid], private_key_hex=PRIV[key or pid])


def _cmd(pid, action, key=None):
    return encode_command(pid, "r1", action, private_key_hex=PRIV[key or pid])


def test_round_closes_once_all_parties_submit_and_serves_one_aggregate():
    coord, masked = _round()
    assert coord.submit(_sub("A", masked))[0] == 200
    assert coord.read(_cmd("A", "read"))[0] == 425  # not closed: no partial aggregate
    assert coord.submit(_sub("B", masked))[0] == 200
    status, body = coord.submit(_sub("C", masked))
    assert status == 200 and body["closed"] is True
    status, body = coord.read(_cmd("B", "read"))
    assert status == 200
    got = [dequantize(v, frac_bits=coord.session.frac_bits) for v in body["aggregate"]]
    assert got == pytest.approx([4.25, 5.5], abs=1e-6)


def test_differencing_attack_is_blocked():
    """The audit's attack: read agg{A,B}, then let C submit, read again, subtract."""
    coord, masked = _round()
    coord.submit(_sub("A", masked))
    coord.submit(_sub("B", masked))
    assert coord.close(_cmd("coord", "close"))[0] == 200
    first = coord.read(_cmd("coord", "read"))[1]["aggregate"]
    assert coord.submit(_sub("C", masked)) == (409, {"error": "round closed"})
    assert coord.read(_cmd("coord", "read"))[1]["aggregate"] == first
    # Even bypassing the coordinator, the session refuses a second, larger set.
    with pytest.raises(ValueError, match="pinned"):
        coord.session.aggregate_field(masked)


def test_overwrite_and_impersonation_are_rejected():
    coord, masked = _round()
    assert coord.submit(_sub("A", masked))[0] == 200
    zeros = encode_submission("A", "r1", [0, 0], private_key_hex=PRIV["A"])
    assert coord.submit(zeros) == (409, {"error": "party already submitted"})
    forged = encode_submission("B", "r1", masked["B"], private_key_hex=PRIV["C"])
    assert coord.submit(forged)[0] == 401
    assert coord.submit(_sub("B", masked, round_id="other"))[0] == 403
    tampered = _sub("B", masked)
    tampered["masked"] = [1, 1]
    assert coord.submit(tampered)[0] == 401
    assert coord.submit({"party_id": "B"})[0] == 400


def test_only_the_coordinator_closes_and_only_parties_read():
    coord, masked = _round()
    coord.submit(_sub("A", masked))
    assert coord.close(_cmd("coord", "close"))[0] == 409  # below threshold
    coord.submit(_sub("B", masked))
    assert coord.close(_cmd("A", "close"))[0] == 403
    assert coord.close(_cmd("coord", "close", key="A"))[0] == 401
    assert coord.close(_cmd("coord", "read"))[0] == 400
    assert coord.close(_cmd("coord", "close"))[0] == 200
    assert coord.read(_cmd("bankA", "read"))[0] == 403
    assert coord.read(_cmd("C", "read"))[0] == 200


def test_coordinator_identity_must_be_trusted():
    sess = SecureAggregationSession(["A", "B"], dim=1, threshold=2, rng=random.Random(1))  # noqa: S311
    with pytest.raises(TransportError, match="coordinator_id"):
        RoundCoordinator(sess, round_id="r1", identity_trust={"A": TRUST["A"]}, coordinator_id="x")
