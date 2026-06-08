"""Update aggregation for federated learning.

``FedAvgAggregator`` is the standard sample-weighted mean of client updates. The
server sees each client's update in the clear.

``SecureSumAggregator`` produces the **same** result but via additive masking: each
client's sample-weighted contribution is perturbed by a per-client mask, and the masks
are constructed to cancel to zero across clients. The server can therefore recover the
sum (hence the average) without learning any individual contribution — the secure-
aggregation property, here as a single-process reference (a real deployment exchanges
pairwise mask seeds between clients).
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from typing import Protocol

# A client update: (weights, bias, n_samples).
Update = tuple[Sequence[float], float, int]


class Aggregator(Protocol):
    def aggregate(self, updates: Sequence[Update]) -> tuple[list[float], float]: ...


def _check(updates: Sequence[Update]) -> tuple[int, int]:
    if not updates:
        raise ValueError("no client updates to aggregate")
    d = len(updates[0][0])
    if any(len(w) != d for w, _, _ in updates):
        raise ValueError("all client weight vectors must have the same length")
    total_n = sum(n for _, _, n in updates)
    if total_n <= 0:
        raise ValueError("total sample count must be > 0")
    return d, total_n


class FedAvgAggregator:
    """Sample-weighted mean of client updates (McMahan et al., 2017)."""

    def aggregate(self, updates: Sequence[Update]) -> tuple[list[float], float]:
        d, total_n = _check(updates)
        w = [0.0] * d
        b = 0.0
        for weights, bias, n in updates:
            for j in range(d):
                w[j] += weights[j] * n
            b += bias * n
        return [v / total_n for v in w], b / total_n


class SecureSumAggregator:
    """FedAvg via zero-sum additive masking — server recovers only the aggregate.

    Equivalent in output to :class:`FedAvgAggregator`; the masking models that the
    coordinator never observes an unmasked individual contribution. Deterministic for
    a fixed ``seed`` so the reference is testable.
    """

    def __init__(self, seed: int = 0) -> None:
        self.seed = seed

    def masked_contributions(self, updates: Sequence[Update]) -> list[list[float]]:
        """Return per-client masked, sample-weighted contributions (len d+1 each).

        The element-wise sum equals the unmasked weighted sum (masks cancel), but no
        single masked vector reveals its client's contribution.
        """
        d, _ = _check(updates)
        rng = random.Random(self.seed)  # noqa: S311 - reference masking, not production crypto
        contributions = [
            [weights[j] * n for j in range(d)] + [bias * n] for weights, bias, n in updates
        ]
        k = len(updates)
        masks = [[rng.gauss(0.0, 1.0) for _ in range(d + 1)] for _ in range(k - 1)]
        # Final mask cancels the rest so the column sums are unchanged.
        last = [-sum(masks[i][c] for i in range(k - 1)) for c in range(d + 1)]
        masks.append(last)
        return [[contributions[i][c] + masks[i][c] for c in range(d + 1)] for i in range(k)]

    def aggregate(self, updates: Sequence[Update]) -> tuple[list[float], float]:
        d, total_n = _check(updates)
        masked = self.masked_contributions(updates)
        summed = [sum(masked[i][c] for i in range(len(masked))) for c in range(d + 1)]
        return [summed[j] / total_n for j in range(d)], summed[d] / total_n
