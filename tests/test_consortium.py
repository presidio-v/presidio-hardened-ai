"""Tests for governed consortium rounds (P4 / v0.13.0)."""

from __future__ import annotations

import json
import random

import pytest

from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.dp.authorization import (
    MPADenied,
    MPAPolicy,
    build_request,
    request_hash,
    sign_approval,
)
from presidio_ai.dp.budget import AUTHORIZED_EVENT, EpsilonBudget
from presidio_ai.evidence import consortium_commitment, sign_evidence
from presidio_ai.fl.consortium import CONSORTIUM_EVENT, ConsortiumError, run_consortium_round
from presidio_ai.fl.secure_agg import SecureAggregationSession
from presidio_ai.ledger import Ledger, verify_chain

KEY = "0" * 64
DELTA = 1e-5


def _session(parties, dim, threshold=2, seed=3):
    return SecureAggregationSession(
        parties,
        dim=dim,
        threshold=threshold,
        rng=random.Random(seed),  # noqa: S311 - test fixture
    )


def _dp(parties, steps=50):
    return {
        p: dpsgd_epsilon(noise_multiplier=1.1, sample_rate=0.01, steps=steps, delta=DELTA)
        for p in parties
    }


def _updates(parties, dim, seed=5):
    rng = random.Random(seed)  # noqa: S311 - test fixture
    return {p: [rng.uniform(-2, 2) for _ in range(dim)] for p in parties}


def test_round_aggregates_and_commits(tmp_path):
    parties = ["bankA", "bankB", "bankC"]
    dim = 4
    updates = _updates(parties, dim)
    sess = _session(parties, dim)
    ledger = Ledger(tmp_path / "round.jsonl", key=KEY)
    budgets = {
        p: EpsilonBudget(10.0, DELTA, Ledger(tmp_path / f"{p}.jsonl", key=KEY)) for p in parties
    }
    res = run_consortium_round(
        round_id="r1",
        updates=updates,
        dp_results=_dp(parties),
        session=sess,
        ledger=ledger,
        budgets=budgets,
    )
    # Aggregate matches the plain sum within the quantisation bound.
    expected = [sum(updates[p][k] for p in parties) for k in range(dim)]
    assert all(
        abs(a - e) <= len(parties) * 2**-sess.frac_bits
        for a, e in zip(res.aggregate, expected, strict=True)
    )
    assert res.dropped == []
    assert set(res.per_silo_charge) == set(parties)
    # Each silo charged its own budget exactly once.
    for p in parties:
        assert budgets[p].spent() > 0
    # Ledger has exactly one consortium-round entry, and it is commitments only.
    entries = verify_chain(ledger.path, key=KEY)
    rounds = [e for e in entries if e.event == CONSORTIUM_EVENT]
    assert len(rounds) == 1
    payload = rounds[0].payload
    assert set(payload) == {
        "round_id",
        "aggregate_sha256",
        "max_epsilon",
        "delta",
        "n_parties",
        "n_survivors",
        "n_dropped",
        "per_silo_epsilon",
    }
    # No raw update vector anywhere in the payload.
    assert "aggregate" not in payload and "updates" not in payload


def test_round_with_dropout_recovers_survivor_sum(tmp_path):
    parties = ["a", "b", "c", "d", "e"]
    dim = 3
    all_updates = _updates(parties, dim)
    survivors = parties[:3]
    sess = _session(parties, dim, threshold=3, seed=8)
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    res = run_consortium_round(
        round_id="r2",
        updates={p: all_updates[p] for p in survivors},
        dp_results=_dp(survivors),
        session=sess,
        ledger=ledger,
    )
    expected = [sum(all_updates[p][k] for p in survivors) for k in range(dim)]
    assert all(
        abs(a - e) <= len(survivors) * 2**-sess.frac_bits
        for a, e in zip(res.aggregate, expected, strict=True)
    )
    assert set(res.dropped) == {"d", "e"}


def test_round_requires_mpa_above_threshold(tmp_path):
    parties = ["a", "b"]
    dim = 2
    # High epsilon so the policy triggers.
    dp = {
        p: dpsgd_epsilon(noise_multiplier=0.4, sample_rate=0.2, steps=200, delta=DELTA)
        for p in parties
    }
    gating = max(dp.values(), key=lambda r: r.epsilon)
    policy = MPAPolicy(threshold=2, min_epsilon=0.0, approvers=("cro", "dpo"))
    sess = _session(parties, dim)
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)

    # No approvals -> denied, and nothing is aggregated/charged.
    with pytest.raises(MPADenied):
        run_consortium_round(
            round_id="r3",
            updates=_updates(parties, dim),
            dp_results=dp,
            session=sess,
            ledger=ledger,
            policy=policy,
        )

    # Two valid approvals -> authorized.
    req_hash = request_hash(build_request(gating, job_id="consortium/r3"))
    approver_keys = {"cro": "k-cro", "dpo": "k-dpo"}
    approvals = {
        a: sign_approval(req_hash, approver_id=a, approver_key=k) for a, k in approver_keys.items()
    }
    res = run_consortium_round(
        round_id="r3",
        updates=_updates(parties, dim),
        dp_results=dp,
        session=sess,
        ledger=ledger,
        policy=policy,
        approvals=approvals,
        approver_keys=approver_keys,
    )
    assert sorted(res.approvers) == ["cro", "dpo"]
    entries = verify_chain(ledger.path, key=KEY)
    assert any(e.event == AUTHORIZED_EVENT for e in entries)


def test_round_emits_verifiable_evidence(tmp_path):
    parties = ["a", "b", "c"]
    dim = 2
    updates = _updates(parties, dim)
    sess = _session(parties, dim)
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    ev = tmp_path / "round.evidence.json"
    res = run_consortium_round(
        round_id="r4",
        updates=updates,
        dp_results=_dp(parties),
        session=sess,
        ledger=ledger,
        signing_key="seal-key",
        signer="presidio-hardened-ai",
        algorithm="hmac-sha256",
        evidence_path=ev,
    )
    assert res.evidence_path == ev and ev.exists()
    refs = json.loads(ev.read_text())["evidence"]
    assert len(refs) == 1 and refs[0]["item_id"] == "D4"
    # The signed content hash commits to the round's aggregate-only commitment.
    commitment = consortium_commitment(
        round_id="r4",
        aggregate_field=res.aggregate_field,
        max_epsilon=res.max_epsilon,
        delta=res.delta,
        n_parties=3,
        n_survivors=3,
    )
    from presidio_ai.hashing import sha256_hex

    assert refs[0]["content_hash"] == sha256_hex(commitment)
    assert refs[0]["signature"] == sign_evidence(
        refs[0]["content_hash"], "seal-key", "presidio-hardened-ai"
    )


def test_evidence_path_requires_signing_key(tmp_path):
    parties = ["a", "b"]
    sess = _session(parties, 2)
    with pytest.raises(ConsortiumError, match="signing_key"):
        run_consortium_round(
            round_id="r5",
            updates=_updates(parties, 2),
            dp_results=_dp(parties),
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            evidence_path=tmp_path / "x.json",
        )


def test_round_rejects_mismatched_delta(tmp_path):
    parties = ["a", "b"]
    dp = {
        "a": dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.01, steps=10, delta=1e-5),
        "b": dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.01, steps=10, delta=1e-6),
    }
    sess = _session(parties, 2)
    with pytest.raises(ConsortiumError, match="one delta"):
        run_consortium_round(
            round_id="r6",
            updates=_updates(parties, 2),
            dp_results=dp,
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
        )
