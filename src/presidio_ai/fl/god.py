"""Guaranteed-output-delivery aggregation for a sum (P4, ADR-0006, Option A).

Honest-majority robust secret-sharing aggregation: each party **Feldman-VSS-shares** every
coordinate of its (DP-noised, quantised) update to all parties; shares are **added locally**
(the sum of shares at a point is a share of the sum — no multiplication, since the target is a
sum); and the aggregate is recovered by **robust reconstruction** — verify each share against
the homomorphically-combined commitments, discard the invalid ones, and interpolate from a
valid quorum.

Why this delivers the output (GOD) under an honest majority (``n ≥ 2t+1``):

* a **malicious dealer** can only publish commitments for which the *correct* polynomial
  evaluations verify, so an inconsistent share is detected and that dealer is **excluded**
  (its input simply drops out of the sum);
* a **malicious holder** that reports a wrong summed-share is caught by robust reconstruction
  (the summed-share is verified against the product of the dealers' commitments — Feldman
  commitments are homomorphic) and **discarded**;
* there is **no coordinator**: any honest quorum of ``t+1`` valid summed-shares reconstructs
  the sum, so no single party can halt the round.

This reuses the Feldman VSS and robust reconstruction in :mod:`presidio_ai.fl.commit`. It is
the GOD alternative to the masking aggregation of :mod:`presidio_ai.fl.secure_agg`; a round
chooses one. (Per ADR-0006, binding the bounded-norm ZK gate to the *shared* inputs needs a
small cross-commitment equality proof and is the remaining integration item.)
"""

from __future__ import annotations

from collections.abc import Hashable, Mapping, Sequence
from dataclasses import dataclass

from presidio_ai.fl.commit import (
    MODP2048_GROUP,
    CommitmentError,
    SchnorrGroup,
    feldman_split,
    feldman_verify_share,
    robust_reconstruct,
)


class GODError(RuntimeError):
    """Raised when guaranteed-output-delivery aggregation cannot complete (fail-closed)."""


@dataclass(frozen=True)
class DealtInput:
    """One party's VSS-shared input: per-coordinate shares + coefficient commitments."""

    shares: list[dict[int, int]]  # per coordinate: holder x -> share
    commitments: list[list[int]]  # per coordinate: g^{a_l} commitments (a_0 = the value)


def deal_input(
    values: Sequence[int],
    *,
    threshold: int,
    n_holders: int,
    group: SchnorrGroup = MODP2048_GROUP,
    rng=None,
) -> DealtInput:
    """Feldman-VSS-share each coordinate of ``values`` among ``n_holders`` parties."""
    shares: list[dict[int, int]] = []
    commitments: list[list[int]] = []
    for v in values:
        sharing = feldman_split(v % group.q, threshold, n_holders, group=group, rng=rng)
        shares.append(sharing.shares)
        commitments.append(sharing.commitments)
    return DealtInput(shares=shares, commitments=commitments)


@dataclass(frozen=True)
class GODResult:
    aggregate_field: list[int]  # Σ over included dealers of each coordinate (field elements)
    included: list[Hashable]
    excluded: list[Hashable]


def _is_group_element(c: object, group: SchnorrGroup) -> bool:
    return (
        isinstance(c, int)
        and not isinstance(c, bool)
        and 1 <= c < group.p
        and pow(c, group.q, group.p) == 1
    )


def _is_share(y: object, group: SchnorrGroup) -> bool:
    return isinstance(y, int) and not isinstance(y, bool) and 0 <= y < group.q


def _consistent_dealer(
    dealt: object, *, n_holders: int, threshold: int, dim: int, group: SchnorrGroup
) -> bool:
    """A dealer is included only if its input is well formed for the round and Feldman-consistent.

    Well formed: ``dim`` coordinates, each with exactly ``threshold`` coefficient
    commitments (degree ``threshold - 1``) that are subgroup elements, and a share for every
    holder ``1..n_holders``. Anything else returns ``False`` (excluded), never raises, so a
    malformed dealer cannot halt the round or change the shape of the aggregate.
    """
    shares = getattr(dealt, "shares", None)
    commitments = getattr(dealt, "commitments", None)
    if not isinstance(shares, list) or not isinstance(commitments, list):
        return False
    if len(shares) != dim or len(commitments) != dim:
        return False
    for coord_shares, coord_commits in zip(shares, commitments, strict=True):
        if not isinstance(coord_shares, Mapping) or not isinstance(coord_commits, list):
            return False
        if len(coord_commits) != threshold:
            return False
        if not all(_is_group_element(c, group) for c in coord_commits):
            return False
        for x in range(1, n_holders + 1):
            y = coord_shares.get(x)
            if not _is_share(y, group):
                return False
            if not feldman_verify_share(x, y, coord_commits, group=group):
                return False
    return True


def _round_dimension(dealt: Mapping[Hashable, DealtInput]) -> int:
    """The dimension a strict majority of dealers declare (honest-majority model)."""
    counts: dict[int, int] = {}
    for d in dealt.values():
        shares = getattr(d, "shares", None)
        if isinstance(shares, list):
            counts[len(shares)] = counts.get(len(shares), 0) + 1
    for k, c in counts.items():
        if 2 * c > len(dealt):
            return k
    raise GODError("no dimension is declared by a majority of dealers; pass dim explicitly")


def god_aggregate(
    dealt: Mapping[Hashable, DealtInput],
    *,
    threshold: int,
    n_holders: int,
    dim: int | None = None,
    group: SchnorrGroup = MODP2048_GROUP,
    holder_overrides: Mapping[Hashable, Mapping[int, int]] | None = None,
) -> GODResult:
    """Robustly reconstruct the sum of the dealers' inputs (GOD under honest majority).

    ``dim`` is the round's vector dimension, an agreed round parameter; when omitted it is
    the dimension a strict majority of dealers declare. Dealers whose input is malformed for
    the round (wrong dimension or degree, missing holders, non-group commitments) or
    Feldman-inconsistent are excluded. A malicious holder may corrupt its summed-share via
    ``holder_overrides`` (``{coordinate_index: {x: bad_share}}``) and is discarded by robust
    reconstruction. Fails closed if a coordinate cannot reach a ``threshold``-sized valid quorum.
    """
    if threshold < 1 or n_holders < threshold:
        raise GODError("need 1 <= threshold <= n_holders")
    if not dealt:
        raise GODError("no dealers to aggregate")
    dim = _round_dimension(dealt) if dim is None else dim
    if dim < 1:
        raise GODError("dim must be >= 1")
    included = [
        p
        for p, d in dealt.items()
        if _consistent_dealer(d, n_holders=n_holders, threshold=threshold, dim=dim, group=group)
    ]
    excluded = [p for p in dealt if p not in included]
    if not included:
        raise GODError("no consistent dealers to aggregate")
    overrides = holder_overrides or {}

    aggregate: list[int] = []
    for k in range(dim):
        # Homomorphically combine the dealers' commitments for coordinate k.
        agg_commitments = [1] * threshold  # every included dealer has exactly `threshold`
        for p in included:
            for c_idx, c in enumerate(dealt[p].commitments[k]):
                agg_commitments[c_idx] = (agg_commitments[c_idx] * c) % group.p
        # Each holder sums the shares it received from the included dealers.
        summed: dict[int, int] = {}
        for x in range(1, n_holders + 1):
            summed[x] = sum(dealt[p].shares[k][x] for p in included) % group.q
        # A malicious holder may report a wrong summed-share for this coordinate.
        for x, bad in overrides.get(k, {}).items():
            summed[x] = bad % group.q
        try:
            aggregate.append(
                robust_reconstruct(summed, agg_commitments, threshold=threshold, group=group)
            )
        except CommitmentError as exc:
            raise GODError(f"coordinate {k}: {exc}") from exc
    return GODResult(aggregate_field=aggregate, included=included, excluded=excluded)
