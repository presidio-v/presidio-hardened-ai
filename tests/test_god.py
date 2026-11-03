"""Tests for guaranteed-output-delivery aggregation + round (P4, ADR-0006)."""

from __future__ import annotations

import copy
import random

import pytest

from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.dp.budget import EpsilonBudget
from presidio_ai.fl.commit import SchnorrGroup, feldman_split, hash_to_subgroup
from presidio_ai.fl.consortium import GODConsortiumResult, run_god_consortium_round
from presidio_ai.fl.god import DealtInput, GODError, deal_input, god_aggregate
from presidio_ai.ledger import Ledger, verify_chain

_Q = 30236267232664312970399
G = SchnorrGroup(p=2 * _Q + 1, q=_Q, g=4, h=hash_to_subgroup(2 * _Q + 1, b"god-test"))
KEY = "0" * 64
DELTA = 1e-5


def _rng(seed=0):
    return random.Random(seed)  # noqa: S311 - test fixture


# --- aggregation core -----------------------------------------------------


def _deal(parties, vals, t, n):
    return {
        p: deal_input(vals[p], threshold=t, n_holders=n, group=G, rng=_rng(i))
        for i, p in enumerate(parties)
    }


def test_god_aggregate_all_honest_exact():
    parties = [f"p{i}" for i in range(5)]
    vals = {p: [(i + 1) * 10 + k for k in range(3)] for i, p in enumerate(parties)}
    res = god_aggregate(_deal(parties, vals, 3, 5), threshold=3, n_holders=5, group=G)
    assert res.aggregate_field == [sum(vals[p][k] for p in parties) % G.q for k in range(3)]
    assert res.excluded == []


def test_god_tolerates_malicious_holder():
    parties = [f"p{i}" for i in range(5)]
    vals = {p: [(i + 1) * 7 + k for k in range(2)] for i, p in enumerate(parties)}
    dealt = _deal(parties, vals, 3, 5)
    expected = [sum(vals[p][k] for p in parties) % G.q for k in range(2)]
    # holder x=1 reports a wrong summed share for coordinate 0 -> discarded by robust recon.
    bad = (dealt["p0"].shares[0][1] + 9999) % G.q
    res = god_aggregate(dealt, threshold=3, n_holders=5, group=G, holder_overrides={0: {1: bad}})
    assert res.aggregate_field == expected


def test_god_excludes_malicious_dealer():
    parties = [f"p{i}" for i in range(5)]
    vals = {p: [(i + 1) * 5 + k for k in range(2)] for i, p in enumerate(parties)}
    dealt = _deal(parties, vals, 3, 5)
    bad = copy.deepcopy(dealt)
    bad["p2"].shares[0][1] = (bad["p2"].shares[0][1] + 1) % G.q  # inconsistent share
    res = god_aggregate(bad, threshold=3, n_holders=5, group=G)
    assert res.excluded == ["p2"]
    assert res.aggregate_field == [
        sum(vals[p][k] for p in parties if p != "p2") % G.q for k in range(2)
    ]


def test_god_fails_closed_when_too_many_bad_holders():
    parties = [f"p{i}" for i in range(5)]
    vals = {p: [1 for _ in range(1)] for p in parties}
    dealt = _deal(parties, vals, 3, 5)
    # corrupt 3 of 5 holders -> only 2 valid < threshold 3.
    ov = {0: {x: (dealt["p0"].shares[0][x] + 3) % G.q for x in (1, 2, 3)}}
    with pytest.raises(GODError, match="cannot reconstruct"):
        god_aggregate(dealt, threshold=3, n_holders=5, group=G, holder_overrides=ov)


# --- malformed dealers (audit 2026-11-03) ----------------------------------

_HONEST = {"A": [10, 1], "B": [20, 2], "C": [30, 3], "D": [40, 4]}
_HONEST_SUM = [100, 10]


def _honest_dealt():
    return _deal(list(_HONEST), _HONEST, 3, 5)


def _high_degree(values):
    """A dealer that shares with a degree-`threshold` polynomial (one coefficient too many)."""
    shares, commits = [], []
    for v in values:
        sh = feldman_split(v % G.q, 4, 5, group=G, rng=_rng(77))
        shares.append(sh.shares)
        commits.append(sh.commitments)
    return DealtInput(shares=shares, commitments=commits)


def _malformed_cases():
    good = deal_input([5, 5], threshold=3, n_holders=5, group=G, rng=_rng(9))
    return {
        "wrong-dimension": deal_input([5], threshold=3, n_holders=5, group=G, rng=_rng(9)),
        "length-mismatch": DealtInput(shares=good.shares[:1], commitments=good.commitments),
        "high-degree": _high_degree([5, 5]),
        "missing-holder": DealtInput(
            shares=[{k: v for k, v in sh.items() if k != 5} for sh in good.shares],
            commitments=good.commitments,
        ),
        "non-group-commitment": DealtInput(
            shares=good.shares, commitments=[[0, *c[1:]] for c in good.commitments]
        ),
        "not-a-dealt-input": object(),
    }


@pytest.mark.parametrize("case", sorted(_malformed_cases()))
@pytest.mark.parametrize("first", [True, False], ids=["first", "last"])
def test_god_excludes_malformed_dealer_and_still_delivers(case, first):
    bad = _malformed_cases()[case]
    honest = _honest_dealt()
    dealt = {"E": bad, **honest} if first else {**honest, "E": bad}
    res = god_aggregate(dealt, threshold=3, n_holders=5, group=G)
    assert res.excluded == ["E"]
    assert res.aggregate_field == _HONEST_SUM
    explicit = god_aggregate(dealt, threshold=3, n_holders=5, dim=2, group=G)
    assert explicit.aggregate_field == _HONEST_SUM


def test_god_requires_majority_dimension_when_dim_omitted():
    dealt = {
        "A": deal_input([1], threshold=2, n_holders=3, group=G, rng=_rng(1)),
        "B": deal_input([1, 2], threshold=2, n_holders=3, group=G, rng=_rng(2)),
    }
    with pytest.raises(GODError, match="majority"):
        god_aggregate(dealt, threshold=2, n_holders=3, group=G)
    assert god_aggregate(dealt, threshold=2, n_holders=3, dim=2, group=G).included == ["B"]


# --- full GOD round -------------------------------------------------------


def _dp(parties):
    return {
        p: dpsgd_epsilon(noise_multiplier=1.1, sample_rate=0.01, steps=50, delta=DELTA)
        for p in parties
    }


def _updates(parties, dim, seed=5):
    rng = _rng(seed)
    return {p: [rng.uniform(-1, 1) for _ in range(dim)] for p in parties}


def test_god_round_delivers_and_records(tmp_path):
    parties = [f"bank{i}" for i in range(5)]
    dim = 3
    updates = _updates(parties, dim)
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    budgets = {
        p: EpsilonBudget(10.0, DELTA, Ledger(tmp_path / f"{p}.jsonl", key=KEY)) for p in parties
    }
    res = run_god_consortium_round(
        round_id="god-1",
        updates=updates,
        dp_results=_dp(parties),
        threshold=3,
        ledger=ledger,
        group=G,
        budgets=budgets,
        rng=_rng(1),
    )
    assert isinstance(res, GODConsortiumResult)
    expected = [sum(updates[p][k] for p in parties) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(res.aggregate, expected, strict=True))
    assert res.excluded == []
    rnd = [e for e in verify_chain(ledger.path, key=KEY) if e.payload.get("mode") == "god"][0]
    assert rnd.payload["honest_majority_threshold"] == 3 and rnd.payload["n_included"] == 5


def test_god_round_delivers_despite_malicious_holder(tmp_path):
    # A malicious holder cannot halt the round: the output is still delivered correctly.
    parties = [f"bank{i}" for i in range(5)]
    dim = 2
    updates = _updates(parties, dim)
    # Reconstruct what the honest summed share at x=1 would be is hard to predict here, so we
    # just assert the round completes and is correct with an override on coordinate 0.
    res = run_god_consortium_round(
        round_id="god-2",
        updates=updates,
        dp_results=_dp(parties),
        threshold=3,
        ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
        group=G,
        holder_overrides={0: {1: 12345}},
        rng=_rng(2),
    )
    expected = [sum(updates[p][k] for p in parties) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(res.aggregate, expected, strict=True))


# --- bounded-norm gate on the GOD path (ADR-0006 item 4, v0.28.0) ----------


def test_god_round_with_l2_gate_delivers(tmp_path):
    parties = [f"bank{i}" for i in range(5)]
    dim = 3
    updates = _updates(parties, dim)  # small -> within L2 bound
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    res = run_god_consortium_round(
        round_id="god-l2",
        updates=updates,
        dp_results=_dp(parties),
        threshold=3,
        ledger=ledger,
        group=G,
        l2_bound=4.0,
        rng=_rng(1),
    )
    expected = [sum(updates[p][k] for p in parties) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(res.aggregate, expected, strict=True))
    rnd = [e for e in verify_chain(ledger.path, key=KEY) if e.payload.get("mode") == "god"][0]
    assert rnd.payload["proven_norm"] == "l2" and rnd.payload["norm_excluded"] == []


def test_god_round_excludes_poisoning_party_and_still_delivers(tmp_path):
    # A party over the norm bound is excluded by the gate; GOD still delivers over the rest.
    parties = [f"bank{i}" for i in range(5)]
    dim = 2
    updates = _updates(parties, dim)
    updates["bank2"] = [9.0, 9.0]  # ||.||2 way over the bound
    res = run_god_consortium_round(
        round_id="god-poison",
        updates=updates,
        dp_results=_dp(parties),
        threshold=3,
        ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
        group=G,
        l2_bound=2.0,
        rng=_rng(2),
    )
    assert "bank2" in res.excluded and "bank2" not in res.included
    honest = [p for p in parties if p != "bank2"]
    expected = [sum(updates[p][k] for p in honest) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(res.aggregate, expected, strict=True))
