"""Adapter exposing the native Ristretto255 + Bulletproofs module as a ``ProofBackend``.

Imported only when the ``presidio_ai_zk`` wheel (built from ``rust/`` via maturin, the
``[zk]`` accelerator) is installed; :func:`presidio_ai.fl.proof_backend.get_backend`
falls back to the pure-Python MODP backend otherwise. Blindings are plain Python ints
(reduced mod the Ristretto group order here); commitments are 32-byte compressed points.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence

import presidio_ai_zk  # the maturin-built native module (only importable with the [zk] wheel)

# Order of the Ristretto255 group (= order of the Ed25519 prime-order subgroup).
_L = 2**252 + 27742317777372353535851937790883648493


def _blinding_bytes(value: int) -> bytes:
    return (value % _L).to_bytes(32, "little")


class RistrettoBulletproofsBackend:
    """Audited, ``O(log n)`` backend over dalek bulletproofs + curve25519-dalek."""

    name = "ristretto255-bulletproofs"

    def random_blinding(self) -> int:
        return secrets.randbelow(_L)

    def commit(self, value: int, blinding: int) -> bytes:
        return presidio_ai_zk.pedersen_commit(int(value), _blinding_bytes(blinding))

    def add(self, c1: bytes, c2: bytes) -> bytes:
        return presidio_ai_zk.pedersen_add(c1, c2)

    def sum(self, commitments: Sequence[bytes]) -> bytes:
        return presidio_ai_zk.pedersen_sum(list(commitments))

    def serialize_commitment(self, commitment: bytes) -> str:
        return commitment.hex()

    def prove_bounded(self, values, blindings, *, bound: int, rng=None) -> bytes:
        # rng is unused: the native prover draws its own randomness (CSPRNG).
        return presidio_ai_zk.prove_bounded(
            [int(v) for v in values], [_blinding_bytes(b) for b in blindings], int(bound)
        )

    def verify_bounded(self, commitments: Sequence[bytes], proof: bytes, *, bound: int) -> bool:
        return bool(presidio_ai_zk.verify_bounded(list(commitments), proof, int(bound)))
