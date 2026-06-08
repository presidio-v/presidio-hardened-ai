"""Native Ristretto255 + Bulletproofs backend tests (P4, ADR-0004).

Skipped unless the ``presidio_ai_zk`` wheel (built from ``rust/`` via maturin) is installed —
i.e. these run in the dedicated ``ci-zk`` lane, not the dependency-light default gate. They
cross-validate the native backend against the MODP fallback on **decision equivalence**
(accept the in-bound, reject the out-of-bound) — the two are not byte-compatible.
"""

from __future__ import annotations

import random

import pytest

pytest.importorskip("presidio_ai_zk")

from presidio_ai.fl._ristretto_backend import RistrettoBulletproofsBackend  # noqa: E402
from presidio_ai.fl.commit import SchnorrGroup, hash_to_subgroup  # noqa: E402
from presidio_ai.fl.proof_backend import ModpBackend, ProofBackend, get_backend  # noqa: E402

_Q = 30236267232664312970399
_MODP = ModpBackend(SchnorrGroup(p=2 * _Q + 1, q=_Q, g=4, h=hash_to_subgroup(2 * _Q + 1, b"x")))


def test_native_is_selected_when_present():
    assert get_backend().name == "ristretto255-bulletproofs"
    assert isinstance(RistrettoBulletproofsBackend(), ProofBackend)


def test_native_commit_is_homomorphic():
    b = RistrettoBulletproofsBackend()
    c1, c2 = b.commit(10, 111), b.commit(32, 222)
    assert b.add(c1, c2) == b.commit(42, 333)
    assert b.sum([c1, c2]) == b.commit(42, 333)


@pytest.mark.parametrize("backend_factory", [RistrettoBulletproofsBackend, lambda: _MODP])
def test_decision_equivalence_in_bound_accepts(backend_factory):
    b = backend_factory()
    rng = random.Random(1)  # noqa: S311 - test fixture
    values = [-5, 0, 9, 16]
    blindings = [b.random_blinding() for _ in values]
    commits = [b.commit(v, r) for v, r in zip(values, blindings, strict=True)]
    proof = b.prove_bounded(values, blindings, bound=16, rng=rng)
    assert b.verify_bounded(commits, proof, bound=16) is True


@pytest.mark.parametrize("backend_factory", [RistrettoBulletproofsBackend, lambda: _MODP])
def test_decision_equivalence_out_of_bound_rejects(backend_factory):
    b = backend_factory()
    values = [100]  # > bound
    blindings = [b.random_blinding() for _ in values]
    with pytest.raises(Exception):  # noqa: B017 - prover refuses an out-of-bound witness
        b.prove_bounded(values, blindings, bound=16)


@pytest.mark.parametrize("backend_factory", [RistrettoBulletproofsBackend, lambda: _MODP])
def test_decision_equivalence_bound_binding(backend_factory):
    b = backend_factory()
    values = [9]
    blindings = [b.random_blinding() for _ in values]
    commits = [b.commit(v, r) for v, r in zip(values, blindings, strict=True)]
    proof = b.prove_bounded(values, blindings, bound=16)
    assert b.verify_bounded(commits, proof, bound=16) is True
    # a proof for bound=16 must not satisfy a stricter requested bound
    assert b.verify_bounded(commits, proof, bound=8) is False
