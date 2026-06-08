from __future__ import annotations

import math

import pytest

from presidio_ai.dp.accountant import (
    DEFAULT_ORDERS,
    AccountantError,
    dpsgd_epsilon,
    rdp_gaussian,
    rdp_subsampled_gaussian,
    rdp_to_epsilon,
)


def _direct_subsampled_rdp(alpha: int, q: float, sigma: float) -> float:
    """Independent (non-log-space) recomputation of the integer-order bound."""
    terms = [
        math.comb(alpha, k)
        * ((1 - q) ** (alpha - k))
        * (q**k)
        * math.exp(k * (k - 1) / (2 * sigma * sigma))
        for k in range(alpha + 1)
    ]
    return math.log(math.fsum(terms)) / (alpha - 1)


def test_rdp_gaussian_closed_form():
    assert rdp_gaussian(2, 1.0) == pytest.approx(1.0)
    assert rdp_gaussian(10, 2.0) == pytest.approx(10 / (2 * 4))


@pytest.mark.parametrize("alpha", [2, 5, 10, 32])
def test_q1_equals_gaussian(alpha):
    # Oracle: at q=1 the subsampled bound collapses to the exact Gaussian RDP.
    assert rdp_subsampled_gaussian(alpha, 1.0, 1.3) == pytest.approx(rdp_gaussian(alpha, 1.3))


@pytest.mark.parametrize("alpha", [2, 7, 16])
def test_q0_is_zero(alpha):
    assert rdp_subsampled_gaussian(alpha, 0.0, 1.0) == 0.0


@pytest.mark.parametrize("alpha", [2, 5, 10, 20])
def test_logsumexp_matches_direct_sum(alpha):
    # Oracle: stable log-sum-exp == direct high-precision summation.
    got = rdp_subsampled_gaussian(alpha, 0.1, 2.0)
    assert got == pytest.approx(_direct_subsampled_rdp(alpha, 0.1, 2.0), rel=1e-9)


def test_monotone_increasing_in_q():
    prev = -1.0
    for q in (0.0, 0.01, 0.05, 0.2, 0.5, 1.0):
        cur = rdp_subsampled_gaussian(8, q, 1.5)
        assert cur >= prev
        prev = cur


def test_epsilon_monotonicity():
    base = dict(sample_rate=0.01, delta=1e-5)
    eps_few = dpsgd_epsilon(noise_multiplier=1.0, steps=100, **base).epsilon
    eps_many = dpsgd_epsilon(noise_multiplier=1.0, steps=2000, **base).epsilon
    assert eps_many > eps_few  # more steps spend more privacy

    eps_noisy = dpsgd_epsilon(noise_multiplier=4.0, steps=1000, **base).epsilon
    eps_sharp = dpsgd_epsilon(noise_multiplier=1.0, steps=1000, **base).epsilon
    assert eps_noisy < eps_sharp  # more noise -> less privacy spent

    eps_lowq = dpsgd_epsilon(
        noise_multiplier=1.0, sample_rate=0.001, steps=1000, delta=1e-5
    ).epsilon
    eps_highq = dpsgd_epsilon(
        noise_multiplier=1.0, sample_rate=0.05, steps=1000, delta=1e-5
    ).epsilon
    assert eps_highq > eps_lowq  # more sampling -> more privacy spent


def test_dpsgd_result_fields():
    r = dpsgd_epsilon(noise_multiplier=1.1, sample_rate=0.01, steps=1000, delta=1e-5)
    assert r.epsilon > 0 and math.isfinite(r.epsilon)
    assert r.optimal_order in DEFAULT_ORDERS
    assert r.accountant == "rdp-subsampled-gaussian"
    assert r.as_dict()["steps"] == 1000


def test_zero_steps_is_zero_epsilon():
    assert dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.1, steps=0, delta=1e-5).epsilon == 0.0


def test_conversion_smaller_delta_costs_more():
    orders = list(DEFAULT_ORDERS)
    rdps = [10 * rdp_subsampled_gaussian(a, 0.01, 1.0) for a in orders]
    eps_loose, _ = rdp_to_epsilon(orders, rdps, 1e-3)
    eps_tight, _ = rdp_to_epsilon(orders, rdps, 1e-7)
    assert eps_tight > eps_loose


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(noise_multiplier=0.0, sample_rate=0.1, steps=10, delta=1e-5),
        dict(noise_multiplier=1.0, sample_rate=1.5, steps=10, delta=1e-5),
        dict(noise_multiplier=1.0, sample_rate=0.1, steps=-1, delta=1e-5),
        dict(noise_multiplier=1.0, sample_rate=0.1, steps=10, delta=0.0),
        dict(noise_multiplier=1.0, sample_rate=0.1, steps=10, delta=1.0),
    ],
)
def test_invalid_params_raise(kwargs):
    with pytest.raises(AccountantError):
        dpsgd_epsilon(**kwargs)


def test_bad_order_raises():
    with pytest.raises(AccountantError):
        rdp_subsampled_gaussian(1, 0.1, 1.0)
