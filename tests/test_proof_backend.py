"""Tests for the pluggable proof backend (P4, ADR-0004)."""

from __future__ import annotations

import random

from presidio_ai.fl.commit import SchnorrGroup, hash_to_subgroup
from presidio_ai.fl.proof_backend import (
    ModpBackend,
    ProofBackend,
    backend_name,
    get_backend,
)

_Q = 30236267232664312970399
GROUP = SchnorrGroup(p=2 * _Q + 1, q=_Q, g=4, h=hash_to_subgroup(2 * _Q + 1, b"pb-test"))


def _b():
    return ModpBackend(GROUP)


def test_modp_backend_satisfies_protocol():
    assert isinstance(_b(), ProofBackend)
    assert _b().name == "modp-2048"


def test_default_backend_falls_back_to_modp_without_native():
    # No native [zk] wheel in this environment -> MODP fallback is selected and cached.
    assert backend_name() == "modp-2048"
    assert isinstance(get_backend(), ProofBackend)


def test_commit_is_homomorphic():
    b = _b()
    c1 = b.commit(10, 111)
    c2 = b.commit(32, 222)
    assert b.add(c1, c2) == b.commit(42, 333)
    assert b.sum([c1, c2]) == b.commit(42, 333)


def test_serialize_commitment_is_stable():
    b = _b()
    c = b.commit(7, 9)
    assert b.serialize_commitment(c) == b.serialize_commitment(c)


def test_bounded_norm_roundtrip_and_bound_binding():
    b = _b()
    rng = random.Random(1)  # noqa: S311 - test fixture
    values = [-5, 0, 9]
    blindings = [b.random_blinding() for _ in values]
    commits = [b.commit(v, r) for v, r in zip(values, blindings, strict=True)]
    proof = b.prove_bounded(values, blindings, bound=16, rng=rng)
    assert b.verify_bounded(commits, proof, bound=16)
    # A proof for bound=16 must NOT satisfy a stricter requested bound (bound binding).
    assert not b.verify_bounded(commits, proof, bound=8)
