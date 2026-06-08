"""Tests for the secure-aggregation core (P4, ADR-0001).

Deterministic throughout: every session and Shamir call is driven by a seeded
``random.Random`` so the masking, cancellation, and dropout-recovery arithmetic
are reproducible. Masking is exact in the field, so the field-domain paths use
*exact* integer equality; the real-valued wrapper is checked within the
deterministic quantisation bound only.
"""

from __future__ import annotations

import random

import pytest

from presidio_ai.fl.secure_agg import (
    PRIME,
    SecureAggregationSession,
    dequantize,
    quantize,
    shamir_reconstruct,
    shamir_split,
)


def _close(a, b, tol):
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
    assert shamir_reconstruct(dict(list(shares.items())[:3])) == secret
    assert shamir_reconstruct(shares) == secret


def test_shamir_below_threshold_does_not_recover():
    rng = random.Random(2)  # noqa: S311 - test fixture data, not security-relevant
    secret = 42
    shares = shamir_split(secret, threshold=3, n_shares=5, rng=rng)
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


# --- Fixed-point quantisation ---------------------------------------------


def test_quantize_dequantize_roundtrip_signed():
    for x in (0.0, 1.5, -3.25, 1234.5, -0.0009765625):
        assert dequantize(quantize(x)) == pytest.approx(x, abs=2**-23)


def test_quantize_negative_wraps_into_top_half():
    assert quantize(-1.0) > PRIME // 2  # negatives live in the upper half of the field


# --- Masking and aggregation ---------------------------------------------


def _session(n=4, dim=3, threshold=2, seed=7):
    ids = [f"party-{i}" for i in range(n)]
    return ids, SecureAggregationSession(
        ids,
        dim=dim,
        threshold=threshold,
        rng=random.Random(seed),  # noqa: S311 - test fixture data, not security-relevant
    )


def test_aggregate_field_no_dropout_is_exact():
    ids, sess = _session()
    qvecs = {p: [(i + 1) * 1000 + k for k in range(sess.dim)] for i, p in enumerate(ids)}
    masked = {p: sess.mask_field(p, qvecs[p]) for p in ids}
    recovered = sess.aggregate_field(masked)
    expected = [sum(qvecs[p][k] for p in ids) % PRIME for k in range(sess.dim)]
    assert recovered == expected  # exact integer equality — no float error


def test_aggregate_field_with_dropout_is_exact():
    ids, sess = _session(n=5, dim=4, threshold=3, seed=11)
    qvecs = {p: [(i + 1) * 7 + k for k in range(sess.dim)] for i, p in enumerate(ids)}
    survivors = ids[:3]
    masked = {p: sess.mask_field(p, qvecs[p]) for p in survivors}
    recovered = sess.aggregate_field(masked)
    expected = [sum(qvecs[p][k] for p in survivors) % PRIME for k in range(sess.dim)]
    assert recovered == expected


def test_aggregate_real_no_dropout_within_quantisation_bound():
    ids, sess = _session()
    rng = random.Random(99)  # noqa: S311 - test fixture data, not security-relevant
    vectors = {p: [rng.uniform(-5, 5) for _ in range(sess.dim)] for p in ids}
    masked = {p: sess.mask(p, vectors[p]) for p in ids}
    recovered = sess.aggregate(masked)
    # error <= n_parties * 2**-frac_bits (quantisation only; cancellation is exact)
    bound = len(ids) * 2**-sess.frac_bits
    assert _close(recovered, _plain_sum(vectors.values()), bound)


def test_masked_vector_hides_input():
    ids, sess = _session()
    masked = sess.mask(ids[0], [1.0, 2.0, 3.0])
    raw = [quantize(v) for v in (1.0, 2.0, 3.0)]
    assert all(m != r for m, r in zip(masked, raw, strict=True))


def test_aggregate_with_dropout_recovers_survivor_sum():
    ids, sess = _session(n=5, dim=4, threshold=3, seed=11)
    rng = random.Random(123)  # noqa: S311 - test fixture data, not security-relevant
    vectors = {p: [rng.uniform(-3, 3) for _ in range(sess.dim)] for p in ids}
    survivors = ids[:3]
    masked = {p: sess.mask(p, vectors[p]) for p in survivors}
    recovered = sess.aggregate(masked)
    expected = _plain_sum(vectors[p] for p in survivors)
    assert _close(recovered, expected, len(survivors) * 2**-sess.frac_bits)


def test_explicit_dropped_list_matches_inferred():
    ids, sess = _session(n=5, dim=2, threshold=3, seed=13)
    qvecs = {p: [i + k for k in range(sess.dim)] for i, p in enumerate(ids)}
    survivors = ids[:4]
    masked = {p: sess.mask_field(p, qvecs[p]) for p in survivors}
    assert sess.aggregate_field(masked) == sess.aggregate_field(masked, dropped=[ids[4]])


def test_insufficient_survivors_fails_closed():
    ids, sess = _session(n=4, dim=2, threshold=3, seed=17)
    masked = {p: sess.mask(p, [0.0] * sess.dim) for p in ids[:2]}
    with pytest.raises(ValueError, match="survivors to reconstruct"):
        sess.aggregate(masked)


def test_aggregate_rejects_unknown_party():
    ids, sess = _session()
    masked = {p: sess.mask(p, [0.0] * sess.dim) for p in ids}
    masked["ghost"] = [0] * sess.dim
    with pytest.raises(KeyError):
        sess.aggregate(masked)


def test_mask_validates_party_and_dim():
    ids, sess = _session()
    with pytest.raises(KeyError):
        sess.mask("nobody", [0.0] * sess.dim)
    with pytest.raises(ValueError):
        sess.mask(ids[0], [0.0] * (sess.dim + 1))


def test_set_pairwise_seed_still_cancels():
    ids, sess = _session(n=3, dim=2, threshold=2, seed=21)
    sess.set_pairwise_seed(ids[0], ids[1], 0xDEADBEEF % PRIME)
    qvecs = {p: [10 * (i + 1), 20 * (i + 1)] for i, p in enumerate(ids)}
    masked = {p: sess.mask_field(p, qvecs[p]) for p in ids}
    recovered = sess.aggregate_field(masked)
    expected = [sum(qvecs[p][k] for p in ids) % PRIME for k in range(sess.dim)]
    assert recovered == expected


def test_set_pairwise_seed_rejects_bad_args():
    ids, sess = _session(n=3, dim=2, threshold=2, seed=22)
    with pytest.raises(KeyError):
        sess.set_pairwise_seed(ids[0], ids[0], 1)
    with pytest.raises(ValueError):
        sess.set_pairwise_seed(ids[0], ids[1], PRIME)


def test_session_rejects_bad_construction():
    with pytest.raises(ValueError):
        SecureAggregationSession(["a"], dim=2, threshold=2)
    with pytest.raises(ValueError):
        SecureAggregationSession(["a", "a"], dim=2, threshold=2)
    with pytest.raises(ValueError):
        SecureAggregationSession(["a", "b"], dim=2, threshold=3)
    with pytest.raises(ValueError):
        SecureAggregationSession(["a", "b"], dim=0, threshold=2)
