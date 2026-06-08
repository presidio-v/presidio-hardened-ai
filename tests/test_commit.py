"""Tests for Pedersen commitments + Feldman VSS (P4 malicious-security, ADR-0002)."""

from __future__ import annotations

import random

import pytest

from presidio_ai.fl.commit import (
    MODP2048_GROUP,
    CommitmentError,
    SchnorrGroup,
    feldman_reconstruct,
    feldman_split,
    feldman_verify_share,
    hash_to_subgroup,
    pedersen_add,
    pedersen_commit,
    pedersen_sum,
    pedersen_verify,
)

# Small, verified safe prime (q prime, p = 2q+1 prime) for fast exact-arithmetic tests.
_Q = 30236267232664312970399
_P = 2 * _Q + 1
TEST_GROUP = SchnorrGroup(p=_P, q=_Q, g=4, h=hash_to_subgroup(_P, b"presidio-test-h"))


def _rng(seed=0):
    return random.Random(seed)  # noqa: S311 - test fixture, not security-relevant


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Deterministic-enough Miller-Rabin (fixed witnesses); avoids a sympy dependency."""
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small:
        if n % sp == 0:
            return n == sp
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small[:rounds]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# --- Group / production parameters ---------------------------------------


def test_modp2048_is_a_safe_prime_group():
    # Re-verify the hardcoded RFC 3526 modulus: p and q = (p-1)/2 both prime, and the
    # generators live in the order-q subgroup. (Miller-Rabin via pow is cheap.)
    p, q = MODP2048_GROUP.p, MODP2048_GROUP.q
    assert p.bit_length() == 2048
    assert p == 2 * q + 1
    assert _is_probable_prime(q) and _is_probable_prime(p)
    assert pow(MODP2048_GROUP.g, q, p) == 1
    assert pow(MODP2048_GROUP.h, q, p) == 1


def test_group_rejects_non_safe_prime():
    with pytest.raises(CommitmentError):
        SchnorrGroup(p=100, q=7, g=4, h=9)  # 100 != 2*7+1


def test_group_rejects_generator_outside_subgroup():
    # p-1 == -1 has order 2 (not q), so it is not in the order-q subgroup.
    with pytest.raises(CommitmentError):
        SchnorrGroup(p=_P, q=_Q, g=_P - 1, h=TEST_GROUP.h)


# --- Pedersen commitments ------------------------------------------------


def test_pedersen_verify_roundtrip():
    c = pedersen_commit(12345, 67890, TEST_GROUP)
    assert pedersen_verify(c, 12345, 67890, TEST_GROUP)
    assert not pedersen_verify(c, 12346, 67890, TEST_GROUP)  # wrong value
    assert not pedersen_verify(c, 12345, 67891, TEST_GROUP)  # wrong randomness


def test_pedersen_is_additively_homomorphic():
    m1, r1, m2, r2 = 111, 222, 333, 444
    c1 = pedersen_commit(m1, r1, TEST_GROUP)
    c2 = pedersen_commit(m2, r2, TEST_GROUP)
    combined = pedersen_add(c1, c2, TEST_GROUP)
    assert pedersen_verify(combined, m1 + m2, r1 + r2, TEST_GROUP)


def test_pedersen_sum_commits_to_the_total():
    values = [10, 20, 30, 40]
    rs = [1, 2, 3, 4]
    commits = [pedersen_commit(m, r, TEST_GROUP) for m, r in zip(values, rs, strict=True)]
    total = pedersen_sum(commits, TEST_GROUP)
    assert pedersen_verify(total, sum(values), sum(rs), TEST_GROUP)


def test_pedersen_hiding_same_value_differs_with_randomness():
    assert pedersen_commit(5, 1, TEST_GROUP) != pedersen_commit(5, 2, TEST_GROUP)


# --- Feldman VSS ---------------------------------------------------------


def test_feldman_reconstruct_and_verify_shares():
    secret = 987654321
    sharing = feldman_split(secret, threshold=3, n_shares=5, group=TEST_GROUP, rng=_rng(1))
    # Every share verifies against the public commitments.
    for x, share in sharing.shares.items():
        assert feldman_verify_share(x, share, sharing.commitments, group=TEST_GROUP)
    # Any 3 reconstruct; the commitment to a_0 is g^secret.
    sub = dict(list(sharing.shares.items())[:3])
    assert feldman_reconstruct(sub, group=TEST_GROUP) == secret
    assert sharing.commitments[0] == pow(TEST_GROUP.g, secret, TEST_GROUP.p)


def test_feldman_detects_a_tampered_share():
    sharing = feldman_split(42, threshold=2, n_shares=4, group=TEST_GROUP, rng=_rng(2))
    x, good = next(iter(sharing.shares.items()))
    assert feldman_verify_share(x, good, sharing.commitments, group=TEST_GROUP)
    # A malicious dealer / corrupted transit: share off by one fails verification.
    assert not feldman_verify_share(x, good + 1, sharing.commitments, group=TEST_GROUP)


def test_feldman_below_threshold_does_not_recover():
    secret = 555
    sharing = feldman_split(secret, threshold=3, n_shares=5, group=TEST_GROUP, rng=_rng(3))
    two = dict(list(sharing.shares.items())[:2])
    assert feldman_reconstruct(two, group=TEST_GROUP) != secret


def test_feldman_rejects_bad_params():
    with pytest.raises(CommitmentError):
        feldman_split(1, threshold=0, n_shares=3, group=TEST_GROUP)
    with pytest.raises(CommitmentError):
        feldman_split(1, threshold=4, n_shares=3, group=TEST_GROUP)
    with pytest.raises(CommitmentError):
        feldman_split(TEST_GROUP.q, threshold=2, n_shares=3, group=TEST_GROUP)  # secret >= q
