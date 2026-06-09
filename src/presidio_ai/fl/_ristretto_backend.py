"""Adapter exposing the native Ristretto255 + Bulletproofs module as a ``ProofBackend``.

Imported only when the ``presidio_ai_zk`` wheel (built from ``rust/`` via maturin, the
``[zk]`` accelerator) is installed; :func:`presidio_ai.fl.proof_backend.get_backend`
falls back to the pure-Python MODP backend otherwise. Blindings are plain Python ints
(reduced mod the Ristretto group order here); commitments are 32-byte compressed points.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence

import presidio_ai_zk  # the maturin-built native module (only importable with the [zk] wheel)

# Order of the Ristretto255 group (= order of the Ed25519 prime-order subgroup).
_L = 2**252 + 27742317777372353535851937790883648493


def _blinding_bytes(value: int) -> bytes:
    return (value % _L).to_bytes(32, "little")


def _l2_challenge(*points: bytes) -> int:
    """Fiat-Shamir challenge (a scalar) over a domain-separated transcript of points."""
    h = hashlib.sha256(b"presidio-hardened-ai/zk/ristretto/square/v1")
    for pt in points:
        h.update(len(pt).to_bytes(4, "big"))
        h.update(pt)
    return int.from_bytes(h.digest(), "big") % _L


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

    # --- L2 bounded-norm (ADR-0005): square Sigma-protocol over Ristretto points, with the
    # squared-norm range check delegated to the native range proof. Mirrors the verified
    # MODP construction; the protocol logic is here, only generic point ops are native.

    def _commit_scalar(self, value: int, blinding: int) -> bytes:
        return presidio_ai_zk.pedersen_commit_scalar(
            _blinding_bytes(value), _blinding_bytes(blinding)
        )

    def _prove_square(self, x: int, rx: int, ry: int):
        c_x = self.commit(x, rx)
        c_y = self.commit(x * x, ry)
        r_prime = (ry - x * rx) % _L
        k_x, k_rx, k_r = secrets.randbelow(_L), secrets.randbelow(_L), secrets.randbelow(_L)
        t1 = self._commit_scalar(k_x, k_rx)
        t2 = presidio_ai_zk.pedersen_add(
            presidio_ai_zk.point_mul(c_x, _blinding_bytes(k_x)), self._commit_scalar(0, k_r)
        )
        e = _l2_challenge(c_x, c_y, t1, t2)
        z_x = (k_x + e * (x % _L)) % _L
        z_rx = (k_rx + e * rx) % _L
        z_r = (k_r + e * r_prime) % _L
        return c_y, (t1, t2, z_x, z_rx, z_r)

    def _verify_square(self, c_x: bytes, c_y: bytes, sp) -> bool:
        t1, t2, z_x, z_rx, z_r = sp
        e = _l2_challenge(c_x, c_y, t1, t2)
        ok1 = self._commit_scalar(z_x, z_rx) == presidio_ai_zk.pedersen_add(
            t1, presidio_ai_zk.point_mul(c_x, _blinding_bytes(e))
        )
        lhs2 = presidio_ai_zk.pedersen_add(
            presidio_ai_zk.point_mul(c_x, _blinding_bytes(z_x)), self._commit_scalar(0, z_r)
        )
        ok2 = lhs2 == presidio_ai_zk.pedersen_add(
            t2, presidio_ai_zk.point_mul(c_y, _blinding_bytes(e))
        )
        return ok1 and ok2

    def prove_l2_bounded(self, values, blindings, *, bound: int, rng=None):
        m = bound * bound
        sq_commitments, sq_proofs, sq_blindings = [], [], []
        for x, rx in zip(values, blindings, strict=True):
            ry = secrets.randbelow(_L)
            sq_blindings.append(ry)
            c_y, sp = self._prove_square(int(x), int(rx), ry)
            sq_commitments.append(c_y)
            sq_proofs.append(sp)
        s_val = sum(int(x) * int(x) for x in values)
        if s_val > m:
            raise ValueError("squared norm exceeds bound^2 (L2 norm out of bound)")
        s_blind = sum(sq_blindings) % _L
        # S = Σ x_k^2 in [0, m]: the native symmetric range proof on [S] with bound m gives
        # S in [-m, m]; S >= 0 (a real sum of squares) so this enforces S <= m.
        range_proof = self.prove_bounded([s_val], [s_blind], bound=m, rng=rng)
        return (sq_commitments, sq_proofs, range_proof)

    def verify_l2_bounded(self, commitments: Sequence[bytes], proof, *, bound: int) -> bool:
        m = bound * bound
        sq_commitments, sq_proofs, range_proof = proof
        if len(sq_commitments) != len(commitments) or len(sq_proofs) != len(commitments):
            return False
        for c_x, c_y, sp in zip(commitments, sq_commitments, sq_proofs, strict=True):
            if not self._verify_square(c_x, c_y, sp):
                return False
        s_commit = self.sum(sq_commitments)
        return self.verify_bounded([s_commit], range_proof, bound=m)

    # Whole-consortium aggregation: one Bulletproof over the concatenated consortium vector
    # (true O(log) aggregation via the native aggregated range proof).

    def prove_bounded_batch(self, party_values, party_blindings, *, bound: int, rng=None):
        order = sorted(party_values, key=str)
        flat_v = [v for p in order for v in party_values[p]]
        flat_r = [r for p in order for r in party_blindings[p]]
        return ([str(p) for p in order], self.prove_bounded(flat_v, flat_r, bound=bound, rng=rng))

    def verify_bounded_batch(self, party_commitments, proof, *, bound: int) -> bool:
        order, agg = proof
        if [str(p) for p in sorted(party_commitments, key=str)] != list(order):
            return False
        flat_c = [c for p in order for c in party_commitments[p]]
        return self.verify_bounded(flat_c, agg, bound=bound)
