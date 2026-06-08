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
