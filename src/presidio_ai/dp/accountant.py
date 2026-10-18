"""Rényi-DP accountant for the (subsampled) Gaussian mechanism — pure stdlib.

The DP-SGD privacy bound is computed by:

1. RDP of one subsampled-Gaussian step at each Rényi order ``alpha``
   (Mironov, Talwar & Zhang, *Rényi Differential Privacy of the Sampled Gaussian
   Mechanism*, 2019), composed additively over ``steps``. Integer orders use the
   closed-form binomial bound; fractional orders use the TF-Privacy/Opacus series
   (``_compute_log_a_frac``), so the default grid mixes both;
2. conversion of the composed RDP curve to an ``(epsilon, delta)`` guarantee,
   minimised over the candidate orders (Canonne-Kamath-Steinke 2020 — tight; the
   same conversion Opacus uses).

epsilon/delta semantics: ``delta`` is the failure probability of the
``(epsilon, delta)``-DP guarantee for the whole training run (all ``steps``
composed), assuming Poisson subsampling at rate ``sample_rate`` and per-step L2
clipping to sensitivity 1 with Gaussian noise of standard deviation
``noise_multiplier``. The default grid (``FRACTIONAL_ORDERS``) includes fractional
Rényi orders, which can only lower the RDP->epsilon minimum, so the reported epsilon
is <= the integer-only result (``DEFAULT_ORDERS``); both are sound upper bounds.

Validation oracles (see tests): the subsampled bound collapses to the exact
Gaussian RDP ``alpha / (2 sigma^2)`` at ``q = 1`` and to ``0`` at ``q = 0``, is
monotone increasing in ``q`` and in ``steps``, and the stable log-sum-exp matches
a direct high-precision summation.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from presidio_ai.numeric import encode_field

# Candidate integer Rényi orders. A wide range lets the RDP->epsilon conversion
# pick the tightest order across noise/rate/steps regimes; cost is negligible.
DEFAULT_ORDERS: tuple[int, ...] = tuple(range(2, 257))

# Candidate orders for the fractional-order accountant: a fine fractional grid at
# low orders (where the subsampled bound is most sensitive) plus integers up to 256.
# Including non-integer orders can only lower the RDP->epsilon minimum, so the
# reported epsilon is <= the integer-only result (verified in tests).
FRACTIONAL_ORDERS: tuple[float, ...] = tuple(
    sorted(
        {
            *(1.0 + x / 4.0 for x in range(1, 4)),  # 1.25, 1.50, 1.75
            *(2.0 + x / 4.0 for x in range(0, 8)),  # 2.00, 2.25, ... 3.75
            *range(4, 65),  # 4 .. 64
            128.0,
            256.0,
        }
    )
)


class AccountantError(ValueError):
    """Raised on out-of-domain DP parameters."""


@dataclass(frozen=True)
class DPResult:
    epsilon: float
    delta: float
    optimal_order: float
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

    def signed_dict(self) -> dict[str, int | str]:
        """The float-free form for signed payloads (schema ``dp-result@1``).

        Non-integer parameters become decimal strings at their declared precision
        (:data:`presidio_ai.numeric.PRECISION`); ``steps`` stays a JSON integer. Use
        :meth:`as_dict` for display only: its floats are rejected by the canonicaliser.
        """
        return {
            "epsilon": encode_field("epsilon", self.epsilon),
            "delta": encode_field("delta", self.delta),
            "optimal_order": encode_field("optimal_order", self.optimal_order),
            "noise_multiplier": encode_field("noise_multiplier", self.noise_multiplier),
            "sample_rate": encode_field("sample_rate", self.sample_rate),
            "steps": int(self.steps),
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


def _log_add(log_x: float, log_y: float) -> float:
    """Stable log(exp(log_x) + exp(log_y))."""
    a, b = min(log_x, log_y), max(log_x, log_y)
    if a == -math.inf:
        return b
    return math.log1p(math.exp(a - b)) + b


def _log_sub(log_x: float, log_y: float) -> float:
    """Stable log(exp(log_x) - exp(log_y)); requires log_x >= log_y."""
    if log_x < log_y:
        raise AccountantError("log-subtraction would be negative (numerical instability)")
    if log_y == -math.inf:
        return log_x
    if log_x == log_y:
        return -math.inf
    try:
        return math.log(math.expm1(log_x - log_y)) + log_y
    except OverflowError:
        # exp(log_x) dominates exp(log_y); the difference is ~exp(log_x).
        return log_x


def _log_erfc(x: float) -> float:
    """Numerically stable log(erfc(x)), pure stdlib (no scipy).

    Below x=20, ``math.erfc`` is accurate and well above underflow. For large x the
    error function underflows, so use the asymptotic expansion
    ``erfc(x) ~ exp(-x^2)/(x*sqrt(pi)) * sum_n (-1)^n (2n-1)!! / (2x^2)^n``.
    """
    if x < 20.0:
        return math.log(math.erfc(x))
    inv = 1.0 / (2.0 * x * x)
    series = 1.0
    term = 1.0
    for n in range(1, 8):
        term *= -(2 * n - 1) * inv
        series += term
    return -x * x - math.log(x) - 0.5 * math.log(math.pi) + math.log(series)


def _gen_binom(alpha: float, i: int) -> float:
    """Generalised binomial coefficient C(alpha, i) for real alpha, integer i >= 0."""
    result = 1.0
    for m in range(i):
        result *= (alpha - m) / (m + 1)
    return result


def _compute_log_a_frac(q: float, sigma: float, alpha: float, *, max_terms: int = 10000) -> float:
    """log(A_alpha) for one subsampled-Gaussian step at fractional ``alpha`` > 1.

    Port of the canonical TF-Privacy / Opacus fractional-order series (two infinite
    sums over the privacy-loss tails, truncated once both terms fall below e^-30).
    """
    log_a0, log_a1 = -math.inf, -math.inf
    sigma2 = sigma * sigma
    z0 = sigma2 * math.log(1.0 / q - 1.0) + 0.5
    log_q = math.log(q)
    log_1mq = math.log1p(-q)
    root2sigma = math.sqrt(2.0) * sigma
    # Generalised binomial C(alpha, i) updated in O(1) per term:
    #   C(alpha, 0) = 1,  C(alpha, i) = C(alpha, i-1) * (alpha - i + 1) / i.
    # (Computing it from scratch each iteration would make the loop O(n^2).)
    coef = 1.0
    for i in range(max_terms):
        if i > 0:
            coef *= (alpha - i + 1) / i
        log_coef = math.log(abs(coef))
        j = alpha - i
        log_t0 = log_coef + i * log_q + j * log_1mq
        log_t1 = log_coef + j * log_q + i * log_1mq
        log_e0 = math.log(0.5) + _log_erfc((i - z0) / root2sigma)
        log_e1 = math.log(0.5) + _log_erfc((z0 - j) / root2sigma)
        log_s0 = log_t0 + (i * i - i) / (2.0 * sigma2) + log_e0
        log_s1 = log_t1 + (j * j - j) / (2.0 * sigma2) + log_e1
        if coef > 0:
            log_a0, log_a1 = _log_add(log_a0, log_s0), _log_add(log_a1, log_s1)
        else:
            log_a0, log_a1 = _log_sub(log_a0, log_s0), _log_sub(log_a1, log_s1)
        if max(log_s0, log_s1) < -30.0:
            return _log_add(log_a0, log_a1)
    raise AccountantError("fractional RDP series did not converge")


def rdp_subsampled_gaussian_real(
    alpha: float, sample_rate: float, noise_multiplier: float
) -> float:
    """RDP at any real order ``alpha`` > 1 of one Poisson-subsampled Gaussian step.

    Dispatches to the exact integer-order binomial bound when ``alpha`` is integral
    (the verified reference) and to the fractional-order series otherwise. The two
    agree in the limit as ``alpha`` approaches an integer (verified in tests).
    """
    if alpha <= 1.0:
        raise AccountantError("alpha must be > 1")
    if noise_multiplier <= 0:
        raise AccountantError("noise_multiplier must be > 0")
    if not 0.0 <= sample_rate <= 1.0:
        raise AccountantError("sample_rate must be in [0, 1]")
    q = sample_rate
    if q == 0.0:
        return 0.0
    if q == 1.0:
        return rdp_gaussian(alpha, noise_multiplier)
    if float(alpha).is_integer():
        return rdp_subsampled_gaussian(int(alpha), sample_rate, noise_multiplier)
    return _compute_log_a_frac(q, noise_multiplier, float(alpha)) / (alpha - 1.0)


def rdp_to_epsilon(
    orders: Sequence[float], rdps: Sequence[float], delta: float
) -> tuple[float, float]:
    """Convert a composed RDP curve to (epsilon, optimal_order) for a target delta.

    Uses the tight Canonne-Kamath-Steinke (2020) conversion (also used by Opacus), per
    order alpha > 1:

        epsilon(alpha) = rdp(alpha) + log1p(-1/alpha) - (log(delta) + log(alpha))/(alpha-1)

    minimised over the candidate orders. This is a sound upper bound and is never looser
    than the classic Mironov (2017) bound ``rdp(alpha) + log(1/delta)/(alpha-1)`` — the
    two extra terms are non-positive for alpha > 1 — so it tightens the reported epsilon.
    """
    if not 0.0 < delta < 1.0:
        raise AccountantError("delta must be in (0, 1)")
    if len(orders) != len(rdps) or not orders:
        raise AccountantError("orders and rdps must be non-empty and equal length")
    log_delta = math.log(delta)
    best_eps = math.inf
    best_order = orders[0]
    for alpha, rdp in zip(orders, rdps, strict=True):
        if alpha <= 1:
            continue
        eps = rdp + math.log1p(-1.0 / alpha) - (log_delta + math.log(alpha)) / (alpha - 1)
        if eps < best_eps:
            best_eps, best_order = eps, alpha
    return max(best_eps, 0.0), best_order


def dpsgd_epsilon(
    *,
    noise_multiplier: float,
    sample_rate: float,
    steps: int,
    delta: float,
    orders: Sequence[float] = FRACTIONAL_ORDERS,
) -> DPResult:
    """Compute the (epsilon, delta) guarantee of a DP-SGD run via RDP composition."""
    _check(noise_multiplier, sample_rate, steps, delta)
    if steps == 0:
        return DPResult(0.0, delta, orders[0], noise_multiplier, sample_rate, 0)
    used_orders: list[float] = []
    composed: list[float] = []
    for alpha in orders:
        try:
            rdp = rdp_subsampled_gaussian_real(alpha, sample_rate, noise_multiplier)
        except AccountantError:
            # A fractional-order series that does not converge for these parameters is
            # simply not a usable order; integer orders always succeed via the closed
            # form, so the minimisation below is still well-defined. Skip it.
            continue
        used_orders.append(alpha)
        composed.append(steps * rdp)
    epsilon, optimal_order = rdp_to_epsilon(used_orders, composed, delta)
    return DPResult(epsilon, delta, optimal_order, noise_multiplier, sample_rate, steps)
