"""Tests for the secure-aggregation core (P4 v1, ADR-0001).

Deterministic throughout: every session and Shamir call is driven by a seeded
``random.Random`` so the masking, cancellation, and dropout-recovery arithmetic
are reproducible. Float cancellation is exact only up to rounding, so vector
equalities use a tolerance.
"""

from __future__ import annotations

import random

import pytest

from presidio_ai.fl.secure_agg import (
    PRIME,
    SecureAggregationSession,
    shamir_reconstruct,
    shamir_split,
)

TOL = 1e-9


def _close(a, b, tol=TOL):
    return all(abs(x - y) <= tol for x, y in zip(a, b, strict=True))


def _plain_sum(vectors):
    vectors = list(vectors)
    dim = len(vectors[0])
    return [sum(v[k] for v in vectors) for k in range(dim)]


# --- Shamir secret sharing ------------------------------------------------


def test_shamir_roundtrip():
    rng = random.Random(1)  # noqa: S311 - test fixture data, not security-relevant
    secret = 1234567890
    shares = shamir_split(secret, threshold=3, n_shares=5, rng=rng)
    assert len(shares) == 5
    # Any 3 shares reconstruct; so does the full set.
    assert shamir_reconstruct(dict(list(shares.items())[:3])) == secret
    assert shamir_reconstruct(shares) == secret


def test_shamir_below_threshold_does_not_recover():
    rng = random.Random(2)  # noqa: S311 - test fixture data, not security-relevant
    secret = 42
    shares = shamir_split(secret, threshold=3, n_shares=5, rng=rng)
    # 2 shares of a degree-2 polynomial almost never hit the right value.
    assert shamir_reconstruct(dict(list(shares.items())[:2])) != secret


def test_shamir_rejects_bad_params():
    with pytest.raises(ValueError):
        shamir_split(1, threshold=0, n_shares=3)
    with pytest.raises(ValueError):
        shamir_split(1, threshold=4, n_shares=3)
    with pytest.raises(ValueError):
        shamir_split(PRIME, threshold=2, n_shares=3)  # secret out of field
    with pytest.raises(ValueError):
        shamir_reconstruct({})


# --- Masking and aggregation ---------------------------------------------


def _session(n=4, dim=3, threshold=2, seed=7):
    ids = [f"party-{i}" for i in range(n)]
    return ids, SecureAggregationSession(
        ids,
        dim=dim,
        threshold=threshold,
        rng=random.Random(seed),  # noqa: S311 - test fixture data, not security-relevant
    )


def test_aggregate_no_dropout_equals_plain_sum():
    ids, sess = _session()
    rng = random.Random(99)  # noqa: S311 - test fixture data, not security-relevant
    vectors = {p: [rng.uniform(-5, 5) for _ in range(sess.dim)] for p in ids}
    masked = {p: sess.mask(p, vectors[p]) for p in ids}
    recovered = sess.aggregate(masked)
    assert _close(recovered, _plain_sum(vectors.values()))


def test_masked_vector_hides_input():
    ids, sess = _session()
    vec = [1.0, 2.0, 3.0]
    masked = sess.mask(ids[0], vec)
    # The mask is large relative to the input: no component survives unchanged.
    assert all(abs(m - v) > 1e-6 for m, v in zip(masked, vec, strict=True))


def test_aggregate_with_dropout_recovers_survivor_sum():
    ids, sess = _session(n=5, dim=4, threshold=3, seed=11)
    rng = random.Random(123)  # noqa: S311 - test fixture data, not security-relevant
    vectors = {p: [rng.uniform(-3, 3) for _ in range(sess.dim)] for p in ids}
    # Two parties drop: they never submit a masked vector.
    survivors = ids[:3]
    masked = {p: sess.mask(p, vectors[p]) for p in survivors}
    recovered = sess.aggregate(masked)
    expected = _plain_sum(vectors[p] for p in survivors)
    assert _close(recovered, expected)


def test_aggregate_with_explicit_dropped_list_matches_inferred():
    ids, sess = _session(n=5, dim=2, threshold=3, seed=13)
    rng = random.Random(5)  # noqa: S311 - test fixture data, not security-relevant
    vectors = {p: [rng.uniform(-1, 1) for _ in range(sess.dim)] for p in ids}
    survivors = ids[:4]
    masked = {p: sess.mask(p, vectors[p]) for p in survivors}
    inferred = sess.aggregate(masked)
    explicit = sess.aggregate(masked, dropped=[ids[4]])
    assert _close(inferred, explicit)


def test_insufficient_survivors_fails_closed():
    ids, sess = _session(n=4, dim=2, threshold=3, seed=17)
    rng = random.Random(1)  # noqa: S311 - test fixture data, not security-relevant
    vectors = {p: [rng.uniform(-1, 1) for _ in range(sess.dim)] for p in ids}
    masked = {p: sess.mask(p, vectors[p]) for p in ids[:2]}  # only 2 < threshold 3
    with pytest.raises(ValueError, match="survivors to reconstruct"):
        sess.aggregate(masked)


def test_aggregate_rejects_unknown_party():
    ids, sess = _session()
    masked = {p: sess.mask(p, [0.0] * sess.dim) for p in ids}
    masked["ghost"] = [0.0] * sess.dim
    with pytest.raises(KeyError):
        sess.aggregate(masked)


def test_mask_validates_party_and_dim():
    ids, sess = _session()
    with pytest.raises(KeyError):
        sess.mask("nobody", [0.0] * sess.dim)
    with pytest.raises(ValueError):
        sess.mask(ids[0], [0.0] * (sess.dim + 1))


def test_session_rejects_bad_construction():
    with pytest.raises(ValueError):
        SecureAggregationSession(["a"], dim=2, threshold=2)  # < 2 parties
    with pytest.raises(ValueError):
        SecureAggregationSession(["a", "a"], dim=2, threshold=2)  # duplicate ids
    with pytest.raises(ValueError):
        SecureAggregationSession(["a", "b"], dim=2, threshold=3)  # threshold > n
    with pytest.raises(ValueError):
        SecureAggregationSession(["a", "b"], dim=0, threshold=2)  # bad dim
