"""Pluggable zero-knowledge proof backend (P4, ADR-0004).

ADR-0003 shipped bounded-norm ZK proofs over the pure-Python MODP-2048 group; ADR-0004
adds an audited, fast Ristretto255 + Bulletproofs backend without changing the guarantee.
This module is the seam: one :class:`ProofBackend` interface, two implementations, and an
auto-dispatch that prefers the native backend when its wheel is installed and otherwise
falls back to pure Python — so ``[zk]`` is an *accelerator*, not a requirement.

A backend owns three things: Pedersen **commitments** (with their homomorphic sum), the
**bounded-norm proof** (prove/verify), and a canonical **serialization** of a commitment
(for the ledger digest). Blindings are plain Python ints; each backend reduces them into
its own scalar field, so callers never touch group-specific arithmetic. A consortium round
selects one backend and uses it end to end — backends are never mixed within a round.

The guarantee is identical on both paths (a transparent ZK range proof enforcing the clip
bound); only proof size and speed differ. The two are **not** byte-compatible — they are
different proof systems over different groups — so CI cross-validates *decision equivalence*
(accept the in-bound, reject the out-of-bound/tampered), never identical bytes.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from presidio_ai.fl.commit import (
    MODP2048_GROUP,
    SchnorrGroup,
    pedersen_add,
    pedersen_commit,
    pedersen_sum,
    random_scalar,
)
from presidio_ai.fl.zk import prove_bounded as _modp_prove_bounded
from presidio_ai.fl.zk import verify_bounded as _modp_verify_bounded


@runtime_checkable
class ProofBackend(Protocol):
    """A commitment + bounded-norm-proof backend (commitments are opaque to callers)."""

    name: str

    def random_blinding(self) -> int: ...
    def commit(self, value: int, blinding: int) -> Any: ...
    def add(self, c1: Any, c2: Any) -> Any: ...
    def sum(self, commitments: Sequence[Any]) -> Any: ...
    def serialize_commitment(self, commitment: Any) -> str: ...
    def prove_bounded(
        self, values: Sequence[int], blindings: Sequence[int], *, bound: int, rng: Any = None
    ) -> Any: ...
    def verify_bounded(self, commitments: Sequence[Any], proof: Any, *, bound: int) -> bool: ...


class ModpBackend:
    """Pure-Python fallback: Pedersen + bit-decomposition range proofs over MODP-2048."""

    name = "modp-2048"

    def __init__(self, group: SchnorrGroup = MODP2048_GROUP) -> None:
        self.group = group

    def random_blinding(self) -> int:
        return random_scalar(self.group)

    def commit(self, value: int, blinding: int) -> int:
        return pedersen_commit(value, blinding, self.group)

    def add(self, c1: int, c2: int) -> int:
        return pedersen_add(c1, c2, self.group)

    def sum(self, commitments: Sequence[int]) -> int:
        return pedersen_sum(commitments, self.group)

    def serialize_commitment(self, commitment: int) -> str:
        return format(commitment % self.group.p, "x")

    def prove_bounded(self, values, blindings, *, bound, rng=None):
        return _modp_prove_bounded(values, blindings, bound=bound, group=self.group, rng=rng)

    def verify_bounded(self, commitments, proof, *, bound) -> bool:
        # Bind the proof to the *requested* bound: a party must not prove a larger bound
        # than the policy demands.
        if getattr(proof, "bound", None) != bound:
            return False
        return _modp_verify_bounded(commitments, proof, group=self.group)


def _load_native() -> ProofBackend | None:
    """Load the Ristretto255 + Bulletproofs backend if its ``[zk]`` wheel is installed."""
    try:
        import presidio_ai_zk  # noqa: F401 - maturin-built native module (the [zk] extra)
    except Exception:
        return None
    try:
        from presidio_ai.fl._ristretto_backend import RistrettoBulletproofsBackend

        return RistrettoBulletproofsBackend()
    except Exception:  # pragma: no cover - native present but wrapper failed; stay safe
        return None


_DEFAULT_BACKEND: ProofBackend | None = None


def get_backend() -> ProofBackend:
    """Return the process default backend: native Ristretto/Bulletproofs if available, else MODP.

    Resolved once and cached. Set an explicit backend on a call site to override.
    """
    global _DEFAULT_BACKEND
    if _DEFAULT_BACKEND is None:
        _DEFAULT_BACKEND = _load_native() or ModpBackend()
    return _DEFAULT_BACKEND


def backend_name() -> str:
    """Name of the active default backend (``ristretto255-bulletproofs`` or ``modp-2048``)."""
    return get_backend().name
