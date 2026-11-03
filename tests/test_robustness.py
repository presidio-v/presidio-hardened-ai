"""Tests for the Byzantine-ML robustness gate (P4, ADR-0007 Option C)."""

from __future__ import annotations

import math
import random

import pytest

from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.fl.commit import SchnorrGroup, hash_to_subgroup
from presidio_ai.fl.consortium import run_god_consortium_round
from presidio_ai.fl.robustness import RobustnessMetrics, RobustnessPolicy, evaluate
from presidio_ai.ledger import Ledger, verify_chain

_Q = 30236267232664312970399
G = SchnorrGroup(p=2 * _Q + 1, q=_Q, g=4, h=hash_to_subgroup(2 * _Q + 1, b"rob"))
KEY = "0" * 64
DELTA = 1e-5


def _rng(seed=0):
    return random.Random(seed)  # noqa: S311 - test fixture


# --- evaluate() ------------------------------------------------------------


def test_evaluate_accepts_good_candidate():
    pol = RobustnessPolicy(
        validate=lambda c: RobustnessMetrics(score=0.95, canary_pass=True), min_score=0.8
    )
    v = evaluate([0.0, 0.0], pol)
    assert v.accepted and v.reason == "accepted"


def test_evaluate_rejects_failed_canary():
    pol = RobustnessPolicy(validate=lambda c: RobustnessMetrics(score=0.99, canary_pass=False))
    v = evaluate([0.0], pol)
    assert not v.accepted and "canary" in v.reason


def test_evaluate_rejects_low_score_and_regression():
    pol = RobustnessPolicy(
        validate=lambda c: RobustnessMetrics(score=0.5, canary_pass=True),
        min_score=0.8,
        max_regression=0.1,
    )
    assert not evaluate([0.0], pol).accepted  # below min_score
    pol2 = RobustnessPolicy(
        validate=lambda c: RobustnessMetrics(score=0.7, canary_pass=True), max_regression=0.1
    )
    assert not evaluate([0.0], pol2, previous_score=0.95).accepted  # regressed 0.25 > 0.1


# --- round integration: accept, reject+rollback ---------------------------


def _dp(parties):
    return {
        p: dpsgd_epsilon(noise_multiplier=1.1, sample_rate=0.01, steps=50, delta=DELTA)
        for p in parties
    }


def _updates(parties, dim, seed=5):
    rng = _rng(seed)
    return {p: [rng.uniform(0, 1) for _ in range(dim)] for p in parties}


def test_god_round_accepts_when_validation_passes(tmp_path):
    parties = [f"b{i}" for i in range(5)]
    pol = RobustnessPolicy(
        validate=lambda c: RobustnessMetrics(score=0.97, canary_pass=True), min_score=0.8
    )
    res = run_god_consortium_round(
        round_id="rob-ok",
        updates=_updates(parties, 3),
        dp_results=_dp(parties),
        threshold=3,
        ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
        group=G,
        robustness=pol,
        rng=_rng(1),
    )
    assert res.applied is True and res.robustness.accepted


def test_god_round_rejects_and_rolls_back_on_canary_fail(tmp_path):
    parties = [f"b{i}" for i in range(5)]
    # a triggered backdoor -> canary fails -> the round is rolled back.
    pol = RobustnessPolicy(validate=lambda c: RobustnessMetrics(score=0.99, canary_pass=False))
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    res = run_god_consortium_round(
        round_id="rob-bad",
        updates=_updates(parties, 3),
        dp_results=_dp(parties),
        threshold=3,
        ledger=ledger,
        group=G,
        robustness=pol,
        rng=_rng(2),
    )
    assert res.applied is False and not res.robustness.accepted
    assert res.per_silo_charge == {} and res.approvers == []  # no charge on a rolled-back round
    entries = verify_chain(ledger.path, key=KEY)
    rejected = [e for e in entries if e.event == "consortium-round-rejected"]
    assert len(rejected) == 1 and rejected[0].payload["mode"] == "god"
    # no consortium-round (accepted) entry was written
    assert not [e for e in entries if e.event == "consortium-round"]


# --- non-finite scores and non-bool canaries (audit 2026-11-03) ---------------


@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf"), True, "0.99", None])
def test_evaluate_rejects_non_finite_or_non_numeric_score(score):
    for pol, prev in (
        (RobustnessPolicy(validate=lambda c: RobustnessMetrics(score, True), min_score=0.5), None),
        (
            RobustnessPolicy(
                validate=lambda c: RobustnessMetrics(score, True), max_regression=0.01
            ),
            0.95,
        ),
        (RobustnessPolicy(validate=lambda c: RobustnessMetrics(score, True)), None),  # defaults
    ):
        verdict = evaluate([0.0], pol, previous_score=prev)
        assert verdict.accepted is False
        assert "finite" in verdict.reason


@pytest.mark.parametrize("canary", ["no", 1, None, "False"])
def test_evaluate_requires_canary_pass_to_be_true(canary):
    pol = RobustnessPolicy(validate=lambda c: RobustnessMetrics(0.99, canary))
    assert evaluate([0.0], pol).accepted is False


def test_god_round_rolls_back_cleanly_on_nan_score(tmp_path):
    parties = [f"b{i}" for i in range(5)]
    pol = RobustnessPolicy(
        validate=lambda c: RobustnessMetrics(score=math.nan, canary_pass=True), min_score=0.5
    )
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    res = run_god_consortium_round(
        round_id="rob-nan",
        updates=_updates(parties, 3),
        dp_results=_dp(parties),
        threshold=3,
        ledger=ledger,
        group=G,
        robustness=pol,
        rng=_rng(3),
    )
    assert res.applied is False and res.per_silo_charge == {}
    entries = verify_chain(ledger.path, key=KEY)
    rejected = [e for e in entries if e.event == "consortium-round-rejected"]
    assert len(rejected) == 1
    assert rejected[0].payload["score"] is None and rejected[0].payload["score_non_finite"] is True
    assert not [e for e in entries if e.event == "consortium-round"]
