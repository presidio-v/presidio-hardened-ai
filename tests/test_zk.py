"""Tests for zero-knowledge bounded-norm input validation (P4, ADR-0003).

Uses a small verified safe-prime group for fast exact arithmetic; the construction is
identical on the production MODP-2048 group.
"""

from __future__ import annotations

import random
from dataclasses import replace

import pytest

from presidio_ai.fl.commit import SchnorrGroup, hash_to_subgroup, pedersen_commit
from presidio_ai.fl.zk import (
    ProofError,
    prove_bit,
    prove_bounded,
    prove_range,
    verify_bit,
    verify_bounded,
    verify_range,
)

_Q = 30236267232664312970399
G = SchnorrGroup(p=2 * _Q + 1, q=_Q, g=4, h=hash_to_subgroup(2 * _Q + 1, b"zk-test"))


def _rng(seed=0):
    return random.Random(seed)  # noqa: S311 - test fixture, not security-relevant


# --- bit OR-proof ---------------------------------------------------------


def test_bit_proof_roundtrip():
    rng = _rng(1)
    for bit in (0, 1):
        r = rng.randrange(G.q)
        c = pedersen_commit(bit, r, G)
        pf = prove_bit(c, bit, r, group=G, prefix=7, index=0, rng=rng)
        assert verify_bit(c, pf, group=G, prefix=7, index=0)
        # wrong transcript context (prefix/index) must fail (Fiat-Shamir binding)
        assert not verify_bit(c, pf, group=G, prefix=8, index=0)


def test_bit_proof_rejects_non_bit_commitment():
    rng = _rng(2)
    r = rng.randrange(G.q)
    c2 = pedersen_commit(2, r, G)  # commits to 2, not a bit
    # An honest prover cannot OR-prove a non-bit; a forged proof must not verify.
    pf = prove_bit(pedersen_commit(1, r, G), 1, r, group=G, prefix=1, index=0, rng=rng)
    assert not verify_bit(c2, pf, group=G, prefix=1, index=0)


# --- range proof ----------------------------------------------------------


def test_range_proof_completeness():
    rng = _rng(3)
    for v in (0, 1, 5, 200, 255):
        r = rng.randrange(G.q)
        c = pedersen_commit(v, r, G)
        pf = prove_range(v, r, bits=8, group=G, rng=rng)
        assert verify_range(c, pf, group=G)


def test_range_proof_rejects_wrong_commitment():
    rng = _rng(4)
    v, r = 10, rng.randrange(G.q)
    pf = prove_range(v, r, bits=8, group=G, rng=rng)
    # product check binds bits to the commitment: a commitment to v+1 is rejected.
    assert not verify_range(pedersen_commit(v + 1, r, G), pf, group=G)


def test_range_proof_rejects_tampered_bit_commitment():
    rng = _rng(5)
    v, r = 7, rng.randrange(G.q)
    c = pedersen_commit(v, r, G)
    pf = prove_range(v, r, bits=8, group=G, rng=rng)
    pf.bit_commitments[0] = (pf.bit_commitments[0] * 2) % G.p
    assert not verify_range(c, pf, group=G)


def test_range_proof_rejects_tampered_response():
    rng = _rng(6)
    v, r = 9, rng.randrange(G.q)
    c = pedersen_commit(v, r, G)
    pf = prove_range(v, r, bits=8, group=G, rng=rng)
    bp = pf.bit_proofs[0]
    pf.bit_proofs[0] = replace(bp, z0=(bp.z0 + 1) % G.q)
    assert not verify_range(c, pf, group=G)


def test_range_proof_out_of_range_witness_raises():
    rng = _rng(7)
    with pytest.raises(ProofError):
        prove_range(256, rng.randrange(G.q), bits=8, group=G)
    with pytest.raises(ProofError):
        prove_range(-1, rng.randrange(G.q), bits=8, group=G)


# --- L-infinity bounded-norm vector proof ---------------------------------


def _commit_vec(values, randomness):
    return [pedersen_commit(v % G.q, r, G) for v, r in zip(values, randomness, strict=True)]


def test_bounded_norm_completeness():
    rng = _rng(8)
    bound = 100
    values = [-100, -7, 0, 42, 100]
    randomness = [rng.randrange(G.q) for _ in values]
    commitments = _commit_vec(values, randomness)
    proof = prove_bounded(values, randomness, bound=bound, group=G, rng=rng)
    assert verify_bounded(commitments, proof, group=G)


def test_bounded_norm_rejects_out_of_bound_witness():
    rng = _rng(9)
    with pytest.raises(ProofError, match="outside"):
        prove_bounded([101], [rng.randrange(G.q)], bound=100, group=G)


def test_bounded_norm_rejects_wrong_commitments():
    rng = _rng(10)
    bound = 50
    values = [-10, 25, 50]
    randomness = [rng.randrange(G.q) for _ in values]
    proof = prove_bounded(values, randomness, bound=bound, group=G, rng=rng)
    wrong = _commit_vec([v + 1 for v in values], randomness)
    assert not verify_bounded(wrong, proof, group=G)


def test_bounded_norm_length_mismatch_fails():
    rng = _rng(11)
    values = [1, 2, 3]
    randomness = [rng.randrange(G.q) for _ in values]
    commitments = _commit_vec(values, randomness)
    proof = prove_bounded(values, randomness, bound=10, group=G, rng=rng)
    assert not verify_bounded(commitments[:2], proof, group=G)


# --- L2 bounded-norm: square proof + squared-norm range proof (ADR-0005) ---

from presidio_ai.fl.zk import (  # noqa: E402
    prove_l2_bounded,
    prove_square,
    verify_l2_bounded,
    verify_square,
)


def test_square_proof_completeness_and_soundness():
    rng = _rng(20)
    for x in (0, 1, 7, -5, 123):
        rx, ry = rng.randrange(G.q), rng.randrange(G.q)
        cx = pedersen_commit(x, rx, G)
        cy, sp = prove_square(x, rx, ry, group=G, prefix=1, rng=rng)
        assert verify_square(cx, cy, sp, group=G, prefix=1)
        # a commitment to x²+1 is not the square of cx
        cy_bad = pedersen_commit((x * x) % G.q + 1, ry, G)
        assert not verify_square(cx, cy_bad, sp, group=G, prefix=1)
        # transcript binding: wrong prefix fails
        assert not verify_square(cx, cy, sp, group=G, prefix=2)


def _commit(values, randomness):
    return [pedersen_commit(v, r, G) for v, r in zip(values, randomness, strict=True)]


def test_l2_completeness():
    rng = _rng(21)
    bound = 50
    values = [-30, 10, 20]  # ||.||2^2 = 1400 <= 2500
    randomness = [rng.randrange(G.q) for _ in values]
    proof = prove_l2_bounded(values, randomness, bound=bound, group=G, rng=rng)
    assert verify_l2_bounded(_commit(values, randomness), proof, bound=bound, group=G)


def test_l2_rejects_vector_within_linf_but_over_l2():
    # The whole point of L2: each coordinate is within L∞=50, but the norm is too big.
    rng = _rng(22)
    values = [50, 50, 50]  # ||.||2^2 = 7500 > 2500
    randomness = [rng.randrange(G.q) for _ in values]
    with pytest.raises(ProofError):
        prove_l2_bounded(values, randomness, bound=50, group=G, rng=rng)


def test_l2_bound_binding_and_wrong_commitments():
    rng = _rng(23)
    bound = 40
    values = [-10, 20, 10]
    randomness = [rng.randrange(G.q) for _ in values]
    proof = prove_l2_bounded(values, randomness, bound=bound, group=G, rng=rng)
    commits = _commit(values, randomness)
    assert verify_l2_bounded(commits, proof, bound=bound, group=G)
    # a proof for bound=40 must not satisfy a different requested bound
    assert not verify_l2_bounded(commits, proof, bound=41, group=G)
    # wrong commitments rejected
    wrong = _commit([v + 1 for v in values], randomness)
    assert not verify_l2_bounded(wrong, proof, bound=bound, group=G)


# --- cross-commitment equality (ADR-0006 item 4) --------------------------

from presidio_ai.fl.zk import prove_commitment_equality, verify_commitment_equality  # noqa: E402


def test_commitment_equality_binds_same_value():
    rng = _rng(30)
    s, r = 4242, rng.randrange(G.q)
    c_ped = pedersen_commit(s, r, G)
    c_fel = pow(G.g, s % G.q, G.p)  # Feldman C_0 = g^s
    proof = prove_commitment_equality(c_ped, c_fel, r, group=G, prefix=9, rng=rng)
    assert verify_commitment_equality(c_ped, c_fel, proof, group=G, prefix=9)
    # different committed value -> fails
    c_fel_bad = pow(G.g, (s + 1) % G.q, G.p)
    assert not verify_commitment_equality(c_ped, c_fel_bad, proof, group=G, prefix=9)
    # transcript binding
    assert not verify_commitment_equality(c_ped, c_fel, proof, group=G, prefix=10)
