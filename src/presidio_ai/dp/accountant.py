"""Rényi-DP accountant for the (subsampled) Gaussian mechanism — pure stdlib.

The DP-SGD privacy bound is computed by:

1. RDP of one subsampled-Gaussian step at each Rényi order ``alpha``
   (Mironov, Talwar & Zhang, *Rényi Differential Privacy of the Sampled Gaussian
   Mechanism*, 2019 — integer-order bound), composed additively over ``steps``;
2. conversion of the composed RDP curve to an ``(epsilon, delta)`` guarantee,
   minimised over the candidate orders (Mironov 2017).

epsilon/delta semantics: ``delta`` is the failure probability of the
``(epsilon, delta)``-DP guarantee for the whole training run (all ``steps``
composed), assuming Poisson subsampling at rate ``sample_rate`` and per-step L2
clipping to sensitivity 1 with Gaussian noise of standard deviation
``noise_multiplier``. Integer orders only — sound (an upper bound on the tight
RDP), slightly looser than a fractional-order accountant.

Validation oracles (see tests): the subsampled bound collapses to the exact
Gaussian RDP ``alpha / (2 sigma^2)`` at ``q = 1`` and to ``0`` at ``q = 0``, is
monotone increasing in ``q`` and in ``steps``, and the stable log-sum-exp matches
a direct high-precision summation.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

# Candidate integer Rényi orders. A wide range lets the RDP->epsilon conversion
# pick the tightest order across noise/rate/steps regimes; cost is negligible.
DEFAULT_ORDERS: tuple[int, ...] = tuple(range(2, 257))


class AccountantError(ValueError):
    """Raised on out-of-domain DP parameters."""


@dataclass(frozen=True)
class DPResult:
    epsilon: float
    delta: float
    optimal_order: int
    noise_multiplier: float
    sample_rate: float
    steps: int
    accountant: str = "rdp-subsampled-gaussian"

    def as_dict(self) -> dict[str, float | int | str]:
        return {
            "epsilon": self.epsilon,
            "delta": self.delta,
            "optimal_order": self.optimal_order,
            "noise_multiplier": self.noise_multiplier,
            "sample_rate": self.sample_rate,
            "steps": self.steps,
            "accountant": self.accountant,
        }


def _check(noise_multiplier: float, sample_rate: float, steps: int, delta: float) -> None:
    if noise_multiplier <= 0:
        raise AccountantError("noise_multiplier must be > 0")
    if not 0.0 <= sample_rate <= 1.0:
        raise AccountantError("sample_rate must be in [0, 1]")
    if steps < 0:
        raise AccountantError("steps must be >= 0")
    if not 0.0 < delta < 1.0:
        raise AccountantError("delta must be in (0, 1)")


def _logsumexp(values: Sequence[float]) -> float:
    finite = [v for v in values if v != -math.inf]
    if not finite:
        return -math.inf
    m = max(finite)
    return m + math.log(sum(math.exp(v - m) for v in finite))


def _log_binom(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def rdp_gaussian(alpha: float, noise_multiplier: float) -> float:
    """RDP of the (unsubsampled) Gaussian mechanism at order ``alpha`` (sensitivity 1)."""
    if noise_multiplier <= 0:
        raise AccountantError("noise_multiplier must be > 0")
    return alpha / (2.0 * noise_multiplier * noise_multiplier)


def rdp_subsampled_gaussian(alpha: int, sample_rate: float, noise_multiplier: float) -> float:
    """RDP at integer order ``alpha`` >= 2 of one Poisson-subsampled Gaussian step.

    Closed-form integer-order bound:
        RDP(alpha) = 1/(alpha-1) * log( sum_{k=0}^{alpha}
            C(alpha,k) (1-q)^{alpha-k} q^k exp( k(k-1) / (2 sigma^2) ) )
    computed via a numerically stable log-sum-exp.
    """
    if int(alpha) != alpha or alpha < 2:
        raise AccountantError("alpha must be an integer >= 2")
    if noise_multiplier <= 0:
        raise AccountantError("noise_multiplier must be > 0")
    if not 0.0 <= sample_rate <= 1.0:
        raise AccountantError("sample_rate must be in [0, 1]")
    q = sample_rate
    if q == 0.0:
        return 0.0
    if q == 1.0:
        return rdp_gaussian(alpha, noise_multiplier)

    sigma2 = noise_multiplier * noise_multiplier
    log_q = math.log(q)
    log_1mq = math.log1p(-q)
    log_terms = [
        _log_binom(alpha, k) + (alpha - k) * log_1mq + k * log_q + (k * (k - 1)) / (2.0 * sigma2)
        for k in range(alpha + 1)
    ]
    return _logsumexp(log_terms) / (alpha - 1)


def rdp_to_epsilon(orders: Sequence[int], rdps: Sequence[float], delta: float) -> tuple[float, int]:
    """Convert a composed RDP curve to (epsilon, optimal_order) for a target delta.

    epsilon(delta) = min_alpha [ rdp(alpha) + log(1/delta) / (alpha - 1) ]
    """
    if not 0.0 < delta < 1.0:
        raise AccountantError("delta must be in (0, 1)")
    if len(orders) != len(rdps) or not orders:
        raise AccountantError("orders and rdps must be non-empty and equal length")
    log_inv_delta = math.log(1.0 / delta)
    best_eps = math.inf
    best_order = orders[0]
    for alpha, rdp in zip(orders, rdps, strict=True):
        eps = rdp + log_inv_delta / (alpha - 1)
        if eps < best_eps:
            best_eps, best_order = eps, alpha
    return max(best_eps, 0.0), best_order


def dpsgd_epsilon(
    *,
    noise_multiplier: float,
    sample_rate: float,
    steps: int,
    delta: float,
    orders: Sequence[int] = DEFAULT_ORDERS,
) -> DPResult:
    """Compute the (epsilon, delta) guarantee of a DP-SGD run via RDP composition."""
    _check(noise_multiplier, sample_rate, steps, delta)
    if steps == 0:
        return DPResult(0.0, delta, orders[0], noise_multiplier, sample_rate, 0)
    composed = [
        steps * rdp_subsampled_gaussian(alpha, sample_rate, noise_multiplier) for alpha in orders
    ]
    epsilon, optimal_order = rdp_to_epsilon(orders, composed, delta)
    return DPResult(epsilon, delta, optimal_order, noise_multiplier, sample_rate, steps)
