"""Secure aggregation core — additive masking with dropout recovery (P4 v1).

Implements the cryptographic *core* of the consortium protocol decided in
ADR-0001 (Bonawitz et al., 2017, "Practical Secure Aggregation"): several
mutually-distrusting parties compute a **sum** of their vectors so that the
coordinator — and any colluding minority — learns only the aggregate, never an
individual party's vector. This is exactly the operation FedAvg needs.

The construction, all in one process and fully unit-testable:

* **Antisymmetric pairwise masks.** Each unordered pair ``{i, j}`` shares a seed
  ``s_ij``. Party *i* adds ``+PRG(s_ij)`` when ``i < j`` and ``-PRG(s_ij)`` when
  ``i > j``. When both parties' inputs are summed, every pairwise mask cancels.
* **Self-masks.** Each party also adds ``PRG(b_i)`` from a private seed ``b_i``.
  Without it, a coordinator who learned the pairwise seeds of a *dropped* party
  could still strip masks and recover a survivor's input; the self-mask closes
  that window. Survivors' self-masks are removed by reconstructing ``b_i``.
* **Dropout recovery via Shamir.** Every party ``t``-of-``n`` secret-shares both
  its self seed and its pairwise seeds. After collecting inputs the coordinator
  knows the survivor set and, from any ``t`` survivor shares, reconstructs
  (a) each survivor's ``b_i`` to remove its self-mask, and (b) each *dropped*
  party's pairwise seeds to remove the masks that no longer cancel. Fewer than
  ``t`` survivors cannot reconstruct — the protocol fails closed.

Trust boundary (see ADR-0001 / SECURITY.md). This module is the in-process,
deterministic reference: it *takes* seeds and *holds* shares so the masking and
recovery arithmetic can be verified end to end. In a real deployment the seeds
come from pairwise key agreement (Diffie-Hellman) and the shares travel over an
authenticated network — that transport is the deferred ``[mpc]`` lane, not this
file. Seeds must be high-entropy: ``SecureAggregationSession`` draws them from a
CSPRNG (``secrets.SystemRandom``) by default; passing a seeded ``random.Random``
is for tests only.

Note on arithmetic. Masks here are real-valued (the model updates are floats),
so cancellation is exact only up to floating-point rounding; tests assert
equality within tolerance. A production deployment quantises inputs into the
Shamir field and does mask arithmetic mod a prime, which cancels *exactly* and
has no overflow — that hardening rides on the same ``[mpc]`` lane.
"""

from __future__ import annotations

import random
import secrets
from collections.abc import Hashable, Mapping, Sequence

# A 61-bit Mersenne prime: the Shamir field. Field elements (and therefore every
# seed we share) are < 2**61, so products stay well within Python's big ints.
PRIME = (1 << 61) - 1


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Evaluate a polynomial (Horner) at ``x`` over GF(PRIME)."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % PRIME
    return acc


def shamir_split(
    secret: int, threshold: int, n_shares: int, *, rng: random.Random | None = None
) -> dict[int, int]:
    """Split ``secret`` into ``n_shares`` Shamir shares; any ``threshold`` recover it.

    Returns ``{x: P(x)}`` for ``x`` in ``1..n_shares``, where ``P`` is a degree
    ``threshold - 1`` polynomial over GF(PRIME) with ``P(0) == secret``. Random
    coefficients come from ``rng`` (default a CSPRNG); ``secret`` must be in the
    field.
    """
    if not 1 <= threshold <= n_shares:
        raise ValueError("require 1 <= threshold <= n_shares")
    if not 0 <= secret < PRIME:
        raise ValueError("secret must be a field element in [0, PRIME)")
    src = rng or secrets.SystemRandom()
    coeffs = [secret] + [src.randrange(PRIME) for _ in range(threshold - 1)]
    return {x: _eval_poly(coeffs, x) for x in range(1, n_shares + 1)}


def shamir_reconstruct(shares: Mapping[int, int]) -> int:
    """Recover the secret via Lagrange interpolation at 0 over GF(PRIME).

    ``shares`` maps distinct x-coordinates to ``P(x)``. Any set of at least
    ``threshold`` correct shares reconstructs ``P(0)``; supplying more is fine.
    """
    if not shares:
        raise ValueError("need at least one share to reconstruct")
    xs = list(shares)
    secret = 0
    for i, xi in enumerate(xs):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = (num * (-xj)) % PRIME
            den = (den * (xi - xj)) % PRIME
        term = shares[xi] * num * pow(den, PRIME - 2, PRIME)  # den^-1 via Fermat
        secret = (secret + term) % PRIME
    return secret


def _prg(seed: int, dim: int, *, scale: float = 1.0) -> list[float]:
    """Deterministically expand a seed into a length-``dim`` real mask vector.

    Determinism is the contract: two parties holding the same pairwise seed must
    derive byte-identical masks for them to cancel. The seed itself must be
    high-entropy (CSPRNG/DH) — that is the session's responsibility, not this
    expander's.
    """
    gen = random.Random(seed)  # noqa: S311 - deterministic mask expansion, not key material
    return [gen.gauss(0.0, scale) for _ in range(dim)]


class SecureAggregationSession:
    """In-process reference of one secure-aggregation round (ADR-0001).

    Generates the self and pairwise seeds for ``party_ids``, secret-shares each
    so a quorum of survivors can recover them, exposes :meth:`mask` for a party
    to mask its vector, and :meth:`aggregate` for the coordinator to recover the
    sum of the *surviving* parties' vectors — and nothing else.
    """

    def __init__(
        self,
        party_ids: Sequence[Hashable],
        dim: int,
        threshold: int,
        *,
        mask_scale: float = 1.0,
        rng: random.Random | None = None,
    ) -> None:
        ids = list(party_ids)
        if len(set(ids)) != len(ids):
            raise ValueError("party_ids must be unique")
        if len(ids) < 2:
            raise ValueError("secure aggregation needs at least 2 parties")
        if not 2 <= threshold <= len(ids):
            raise ValueError("require 2 <= threshold <= n_parties")
        if dim < 1:
            raise ValueError("dim must be >= 1")
        src = rng or secrets.SystemRandom()
        self.party_ids = ids
        self.dim = dim
        self.threshold = threshold
        self.mask_scale = mask_scale
        # Shamir x-coordinate per party (1-based; 0 is reserved for the secret).
        self._x = {pid: i + 1 for i, pid in enumerate(ids)}
        n = len(ids)
        # Self seed + its sharing among all n parties.
        self._self_seed: dict[Hashable, int] = {}
        self._self_shares: dict[Hashable, dict[int, int]] = {}
        for pid in ids:
            seed = src.randrange(PRIME)
            self._self_seed[pid] = seed
            self._self_shares[pid] = shamir_split(seed, threshold, n, rng=src)
        # Symmetric pairwise seed per unordered pair + its sharing.
        self._pair_seed: dict[frozenset, int] = {}
        self._pair_shares: dict[frozenset, dict[int, int]] = {}
        for a in range(n):
            for b in range(a + 1, n):
                key = frozenset((ids[a], ids[b]))
                seed = src.randrange(PRIME)
                self._pair_seed[key] = seed
                self._pair_shares[key] = shamir_split(seed, threshold, n, rng=src)

    def _pair_sign(self, p: Hashable, q: Hashable) -> int:
        """+1 if p precedes q in party order, else -1 (antisymmetric mask sign)."""
        return 1 if self._x[p] < self._x[q] else -1

    def mask(self, pid: Hashable, vector: Sequence[float]) -> list[float]:
        """Return ``vector`` masked with party ``pid``'s self + pairwise masks."""
        if pid not in self._x:
            raise KeyError(f"unknown party: {pid!r}")
        if len(vector) != self.dim:
            raise ValueError(f"vector must have length {self.dim}")
        out = list(map(float, vector))
        self_mask = _prg(self._self_seed[pid], self.dim, scale=self.mask_scale)
        for k in range(self.dim):
            out[k] += self_mask[k]
        for other in self.party_ids:
            if other == pid:
                continue
            seed = self._pair_seed[frozenset((pid, other))]
            sign = self._pair_sign(pid, other)
            pair_mask = _prg(seed, self.dim, scale=self.mask_scale)
            for k in range(self.dim):
                out[k] += sign * pair_mask[k]
        return out

    def aggregate(
        self,
        masked: Mapping[Hashable, Sequence[float]],
        dropped: Sequence[Hashable] = (),
    ) -> list[float]:
        """Recover the sum of surviving parties' *unmasked* vectors.

        ``masked`` holds one masked vector per surviving party. ``dropped`` lists
        parties that did not submit (defaults to every known party absent from
        ``masked``). Recovery needs at least ``threshold`` survivors; with fewer
        the masks cannot be stripped and the call fails closed.
        """
        survivors = [p for p in self.party_ids if p in masked]
        dropped_set = set(dropped) | (set(self.party_ids) - set(masked))
        if dropped_set & set(survivors):
            raise ValueError("a party cannot be both submitted and dropped")
        unknown = set(masked) - set(self._x)
        if unknown:
            raise KeyError(f"unknown parties in masked inputs: {unknown}")
        if len(survivors) < self.threshold:
            raise ValueError(
                f"need >= {self.threshold} survivors to reconstruct, got {len(survivors)}"
            )
        for p in survivors:
            if len(masked[p]) != self.dim:
                raise ValueError(f"masked vector for {p!r} must have length {self.dim}")

        # Survivor x-coordinates carry the shares used for every reconstruction.
        quorum = [self._x[p] for p in survivors]

        total = [0.0] * self.dim
        for p in survivors:
            vec = masked[p]
            for k in range(self.dim):
                total[k] += vec[k]

        # Remove each survivor's self-mask (pairwise masks among survivors already
        # cancelled in the sum above).
        for p in survivors:
            seed = shamir_reconstruct({x: self._self_shares[p][x] for x in quorum})
            self_mask = _prg(seed, self.dim, scale=self.mask_scale)
            for k in range(self.dim):
                total[k] -= self_mask[k]

        # Remove the pairwise masks that no longer cancel because the partner dropped.
        for d in dropped_set:
            for s in survivors:
                key = frozenset((s, d))
                seed = shamir_reconstruct({x: self._pair_shares[key][x] for x in quorum})
                sign = self._pair_sign(s, d)  # the sign survivor s used for pair {s, d}
                pair_mask = _prg(seed, self.dim, scale=self.mask_scale)
                for k in range(self.dim):
                    total[k] -= sign * pair_mask[k]
        return total
