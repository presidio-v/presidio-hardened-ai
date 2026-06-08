"""Secure aggregation core — additive masking with dropout recovery (P4).

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

**Exact field arithmetic (v0.12.0).** All masking and reconstruction happen in
the prime field GF(``PRIME``), not in floating point. Real-valued model updates
are quantised into the field once at the boundary (fixed-point, ``frac_bits``
fractional bits) and the field aggregate is de-quantised once at the end. Mask
cancellation is therefore **exact** — there is no accumulated floating-point
error, and there is no overflow as long as the true signed sum stays within
``±PRIME/2`` in fixed-point units (a documented, easily-satisfied bound). The
only approximation left is the deterministic per-input quantisation step,
bounded by ``2**-frac_bits`` per component and independent of the party count.

Trust boundary (see ADR-0001 / SECURITY.md). This module is the in-process
reference: it *takes* seeds and *holds* shares so the masking and recovery
arithmetic can be verified end to end. In a real deployment the seeds come from
authenticated pairwise key agreement (see :mod:`presidio_ai.fl.keyagreement`)
and the shares travel over an authenticated network — that transport is the
``[mpc]`` lane. Seeds must be high-entropy: ``SecureAggregationSession`` draws
them from a CSPRNG (``secrets.SystemRandom``) by default; passing a seeded
``random.Random`` is for tests only.
"""

from __future__ import annotations

import hashlib
import random
import secrets
from collections.abc import Hashable, Mapping, Sequence

# A 61-bit Mersenne prime: the Shamir field. Field elements (and therefore every
# seed we share) are < 2**61, so products stay well within Python's big ints.
PRIME = (1 << 61) - 1

# Default fixed-point precision for quantising real updates into the field.
# 2**-24 ~= 6e-8 resolution; with PRIME ~ 2**61 the signed-sum headroom is
# (PRIME/2) / 2**24 ~= 2**36 fixed-point units, ample for normalised updates.
DEFAULT_FRAC_BITS = 24


def _eval_poly(coeffs: Sequence[int], x: int, prime: int) -> int:
    """Evaluate a polynomial (Horner) at ``x`` over GF(prime)."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % prime
    return acc


def shamir_split(
    secret: int,
    threshold: int,
    n_shares: int,
    *,
    prime: int = PRIME,
    rng: random.Random | None = None,
) -> dict[int, int]:
    """Split ``secret`` into ``n_shares`` Shamir shares; any ``threshold`` recover it.

    Returns ``{x: P(x)}`` for ``x`` in ``1..n_shares``, where ``P`` is a degree
    ``threshold - 1`` polynomial over GF(prime) with ``P(0) == secret``. Random
    coefficients come from ``rng`` (default a CSPRNG); ``secret`` must be in the
    field.
    """
    if not 1 <= threshold <= n_shares:
        raise ValueError("require 1 <= threshold <= n_shares")
    if not 0 <= secret < prime:
        raise ValueError("secret must be a field element in [0, prime)")
    src = rng or secrets.SystemRandom()
    coeffs = [secret] + [src.randrange(prime) for _ in range(threshold - 1)]
    return {x: _eval_poly(coeffs, x, prime) for x in range(1, n_shares + 1)}


def shamir_reconstruct(shares: Mapping[int, int], *, prime: int = PRIME) -> int:
    """Recover the secret via Lagrange interpolation at 0 over GF(prime).

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
            num = (num * (-xj)) % prime
            den = (den * (xi - xj)) % prime
        term = shares[xi] * num * pow(den, prime - 2, prime)  # den^-1 via Fermat
        secret = (secret + term) % prime
    return secret


def quantize(x: float, *, frac_bits: int = DEFAULT_FRAC_BITS, prime: int = PRIME) -> int:
    """Map a real value to a field element via signed fixed-point.

    ``round(x * 2**frac_bits)`` taken ``mod prime``; negative values wrap into
    the top half of the field and are recovered by :func:`dequantize`.
    """
    return round(x * (1 << frac_bits)) % prime


def dequantize(v: int, *, frac_bits: int = DEFAULT_FRAC_BITS, prime: int = PRIME) -> float:
    """Inverse of :func:`quantize` for a (possibly summed) field element.

    Field elements above ``prime/2`` are interpreted as negative (centred
    representation). Correct as long as the true signed value is in
    ``(-prime/2, prime/2)`` fixed-point units.
    """
    if v >= prime // 2:
        v -= prime
    return v / (1 << frac_bits)


def _field_prg(seed: int, dim: int, prime: int) -> list[int]:
    """Deterministically expand a seed into ``dim`` uniform field elements.

    SHA-256 in counter mode: block ``k`` is ``sha256(seed8 || k8)``; 128 bits of
    it are reduced mod ``prime`` (modular bias <= 2**-67 against a 61-bit prime,
    cryptographically negligible). Determinism is the contract — two parties
    holding the same pairwise seed derive identical masks, so they cancel.
    """
    seed8 = (seed % prime).to_bytes(8, "big")
    out = []
    for k in range(dim):
        block = hashlib.sha256(seed8 + k.to_bytes(8, "big")).digest()
        out.append(int.from_bytes(block[:16], "big") % prime)
    return out


class SecureAggregationSession:
    """In-process reference of one secure-aggregation round (ADR-0001).

    Generates the self and pairwise seeds for ``party_ids``, secret-shares each
    so a quorum of survivors can recover them, exposes :meth:`mask` for a party
    to mask its (real-valued) vector, and :meth:`aggregate` for the coordinator
    to recover the sum of the *surviving* parties' vectors — and nothing else.
    Masking is exact in GF(``prime``); see the module docstring.
    """

    def __init__(
        self,
        party_ids: Sequence[Hashable],
        dim: int,
        threshold: int,
        *,
        frac_bits: int = DEFAULT_FRAC_BITS,
        prime: int = PRIME,
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
        self.frac_bits = frac_bits
        self.prime = prime
        # Shamir x-coordinate per party (1-based; 0 is reserved for the secret).
        self._x = {pid: i + 1 for i, pid in enumerate(ids)}
        n = len(ids)
        # Self seed + its sharing among all n parties.
        self._self_seed: dict[Hashable, int] = {}
        self._self_shares: dict[Hashable, dict[int, int]] = {}
        for pid in ids:
            seed = src.randrange(prime)
            self._self_seed[pid] = seed
            self._self_shares[pid] = shamir_split(seed, threshold, n, prime=prime, rng=src)
        # Symmetric pairwise seed per unordered pair + its sharing.
        self._pair_seed: dict[frozenset, int] = {}
        self._pair_shares: dict[frozenset, dict[int, int]] = {}
        for a in range(n):
            for b in range(a + 1, n):
                key = frozenset((ids[a], ids[b]))
                seed = src.randrange(prime)
                self._pair_seed[key] = seed
                self._pair_shares[key] = shamir_split(seed, threshold, n, prime=prime, rng=src)

    def _pair_sign(self, p: Hashable, q: Hashable) -> int:
        """+1 if p precedes q in party order, else -1 (antisymmetric mask sign)."""
        return 1 if self._x[p] < self._x[q] else -1

    def set_pairwise_seed(self, a: Hashable, b: Hashable, seed: int) -> None:
        """Override the pairwise seed for ``{a, b}`` (e.g. from real key agreement).

        Re-shares the new seed among all parties. For wiring an authenticated
        key-agreement layer (:mod:`presidio_ai.fl.keyagreement`) on top of the
        in-process session; seeds must be field elements drawn from a CSPRNG/KDF.
        """
        if a == b or a not in self._x or b not in self._x:
            raise KeyError("both parties must be distinct members of the session")
        if not 0 <= seed < self.prime:
            raise ValueError("seed must be a field element in [0, prime)")
        key = frozenset((a, b))
        self._pair_seed[key] = seed
        self._pair_shares[key] = shamir_split(
            seed, self.threshold, len(self.party_ids), prime=self.prime
        )

    def mask_field(self, pid: Hashable, q_vector: Sequence[int]) -> list[int]:
        """Mask an already-quantised (field-element) vector. Exact, no rounding."""
        if pid not in self._x:
            raise KeyError(f"unknown party: {pid!r}")
        if len(q_vector) != self.dim:
            raise ValueError(f"vector must have length {self.dim}")
        out = [v % self.prime for v in q_vector]
        self_mask = _field_prg(self._self_seed[pid], self.dim, self.prime)
        for k in range(self.dim):
            out[k] = (out[k] + self_mask[k]) % self.prime
        for other in self.party_ids:
            if other == pid:
                continue
            seed = self._pair_seed[frozenset((pid, other))]
            sign = self._pair_sign(pid, other)
            pair_mask = _field_prg(seed, self.dim, self.prime)
            for k in range(self.dim):
                out[k] = (out[k] + sign * pair_mask[k]) % self.prime
        return out

    def mask(self, pid: Hashable, vector: Sequence[float]) -> list[int]:
        """Quantise ``vector`` (reals) into the field and mask it. Returns field elements."""
        q = [quantize(v, frac_bits=self.frac_bits, prime=self.prime) for v in vector]
        return self.mask_field(pid, q)

    def _resolve_survivors(
        self, masked: Mapping[Hashable, Sequence[int]], dropped: Sequence[Hashable]
    ) -> tuple[list[Hashable], set]:
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
        return survivors, dropped_set

    def aggregate_field(
        self,
        masked: Mapping[Hashable, Sequence[int]],
        dropped: Sequence[Hashable] = (),
    ) -> list[int]:
        """Recover the exact field sum of surviving parties' quantised vectors.

        Returns field elements; the masks are stripped exactly (no rounding).
        Recovery needs at least ``threshold`` survivors or it fails closed.
        """
        survivors, dropped_set = self._resolve_survivors(masked, dropped)
        quorum = [self._x[p] for p in survivors]
        prime = self.prime

        total = [0] * self.dim
        for p in survivors:
            vec = masked[p]
            for k in range(self.dim):
                total[k] = (total[k] + vec[k]) % prime

        # Remove each survivor's self-mask (pairwise masks among survivors already
        # cancelled in the field sum above).
        for p in survivors:
            seed = shamir_reconstruct({x: self._self_shares[p][x] for x in quorum}, prime=prime)
            self_mask = _field_prg(seed, self.dim, prime)
            for k in range(self.dim):
                total[k] = (total[k] - self_mask[k]) % prime

        # Remove the pairwise masks that no longer cancel because the partner dropped.
        for d in dropped_set:
            for s in survivors:
                key = frozenset((s, d))
                seed = shamir_reconstruct(
                    {x: self._pair_shares[key][x] for x in quorum}, prime=prime
                )
                sign = self._pair_sign(s, d)  # the sign survivor s used for pair {s, d}
                pair_mask = _field_prg(seed, self.dim, prime)
                for k in range(self.dim):
                    total[k] = (total[k] - sign * pair_mask[k]) % prime
        return total

    def aggregate(
        self,
        masked: Mapping[Hashable, Sequence[int]],
        dropped: Sequence[Hashable] = (),
    ) -> list[float]:
        """Recover the sum of surviving parties' *real* vectors (de-quantised)."""
        field_sum = self.aggregate_field(masked, dropped)
        return [dequantize(v, frac_bits=self.frac_bits, prime=self.prime) for v in field_sum]
