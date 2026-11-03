"""Tests for the malicious-secure consortium round (P4, ADR-0002)."""

from __future__ import annotations

import random

import pytest

from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.evidence import generate_ed25519_keypair
from presidio_ai.fl.commit import SchnorrGroup, hash_to_subgroup
from presidio_ai.fl.consortium import (
    SURVIVOR_SET_EVENT,
    ConsortiumError,
    SurvivorSetSigner,
    run_secure_consortium_round,
    sign_survivor_set,
    verify_survivor_set,
)
from presidio_ai.fl.proof_backend import ModpBackend
from presidio_ai.fl.secure_agg import SecureAggregationSession
from presidio_ai.ledger import Ledger, verify_chain

KEY = "0" * 64
DELTA = 1e-5
_Q = 30236267232664312970399
GROUP = SchnorrGroup(p=2 * _Q + 1, q=_Q, g=4, h=hash_to_subgroup(2 * _Q + 1, b"sc-test"))
BACKEND = ModpBackend(GROUP)


def _vsession(parties, dim, threshold=2, seed=3):
    return SecureAggregationSession(
        parties,
        dim=dim,
        threshold=threshold,
        group=GROUP,
        rng=random.Random(seed),  # noqa: S311 - test fixture
    )


def _dp(parties):
    return {
        p: dpsgd_epsilon(noise_multiplier=1.1, sample_rate=0.01, steps=50, delta=DELTA)
        for p in parties
    }


def _updates(parties, dim, seed=5):
    rng = random.Random(seed)  # noqa: S311 - test fixture
    # small non-negative values: aggregate stays in-range for the homomorphic check
    return {p: [rng.uniform(0, 1) for _ in range(dim)] for p in parties}


_KEYPAIRS: dict[str, tuple[str, str]] = {}


def _identities(parties):
    """Ed25519 identity keys per party: (private keys, public trust store)."""
    for p in parties:
        if p not in _KEYPAIRS:
            _KEYPAIRS[p] = generate_ed25519_keypair()
    return (
        {p: _KEYPAIRS[p][0] for p in parties},
        {p: _KEYPAIRS[p][1] for p in parties},
    )


def _signed_alive(parties, round_id, skeys, attempt=1):
    alive = sorted(str(p) for p in parties)
    return {
        p: sign_survivor_set(round_id, alive, party_id=p, private_key_hex=skeys[p], attempt=attempt)
        for p in alive
    }


# --- survivor-set agreement helper ---------------------------------------


def test_survivor_set_agreement_and_equivocation():
    alive = ["a", "b", "c"]
    skeys, strust = _identities(alive)
    sigs = _signed_alive(alive, "r1", skeys)
    assert (
        verify_survivor_set("r1", alive, signatures=sigs, identity_trust=strust, threshold=2)
        == alive
    )
    # Equivocation: the coordinator presents a DIFFERENT alive set than was signed.
    with pytest.raises(ConsortiumError, match="survivor-set agreement failed"):
        verify_survivor_set("r1", ["a", "b"], signatures=sigs, identity_trust=strust, threshold=2)


# --- full secure round ----------------------------------------------------


def test_secure_round_happy_path(tmp_path):
    parties = ["bankA", "bankB", "bankC"]
    dim = 3
    skeys, strust = _identities(parties)
    updates = _updates(parties, dim)
    sess = _vsession(parties, dim)
    ledger = Ledger(tmp_path / "round.jsonl", key=KEY)
    res = run_secure_consortium_round(
        round_id="r1",
        updates=updates,
        dp_results=_dp(parties),
        session=sess,
        ledger=ledger,
        survivor_signatures=_signed_alive(parties, "r1", skeys),
        survivor_trust=strust,
        survivor_threshold=2,
        backend=BACKEND,
        rng=random.Random(11),  # noqa: S311 - test fixture
    )
    expected = [sum(updates[p][k] for p in parties) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(res.aggregate, expected, strict=True))
    assert sorted(res.survivor_signers) == sorted(parties)
    entries = verify_chain(ledger.path, key=KEY)
    assert any(e.event == SURVIVOR_SET_EVENT for e in entries)
    # ledger consortium entry carries only commitment digests, no raw inputs
    from presidio_ai.fl.consortium import CONSORTIUM_EVENT

    rnd = [e for e in entries if e.event == CONSORTIUM_EVENT][0].payload
    assert "input_commitments_sha256" in rnd and "aggregate" not in rnd


def test_secure_round_rejects_survivor_equivocation(tmp_path):
    # Coordinator tries to run with a quorum that did not sign THIS survivor set:
    # only bankA signs, but the round needs 2 -> abort before any aggregation.
    parties = ["bankA", "bankB"]
    skeys, strust = _identities(parties)
    alive = sorted(parties)
    sigs = {
        "bankA": sign_survivor_set("r2", alive, party_id="bankA", private_key_hex=skeys["bankA"])
    }
    sess = _vsession(parties, 2)
    with pytest.raises(ConsortiumError, match="survivor-set agreement failed"):
        run_secure_consortium_round(
            round_id="r2",
            updates=_updates(parties, 2),
            dp_results=_dp(parties),
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            survivor_signatures=sigs,
            survivor_trust=strust,
            survivor_threshold=2,
            backend=BACKEND,
        )


def test_secure_round_detects_false_aggregate(tmp_path, monkeypatch):
    # A coordinator that returns a tampered aggregate must be caught by the homomorphic
    # commitment check and abort.
    parties = ["a", "b", "c"]
    dim = 2
    skeys, strust = _identities(parties)
    sess = _vsession(parties, dim)

    real = sess.aggregate_field

    def tampered(masked, dropped=()):
        out = real(masked, dropped)
        out[0] = (out[0] + 1) % sess.prime  # flip one coordinate
        return out

    monkeypatch.setattr(sess, "aggregate_field", tampered)
    with pytest.raises(ConsortiumError, match="false aggregate"):
        run_secure_consortium_round(
            round_id="r3",
            updates=_updates(parties, dim),
            dp_results=_dp(parties),
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            survivor_signatures=_signed_alive(parties, "r3", skeys),
            survivor_trust=strust,
            survivor_threshold=2,
            backend=BACKEND,
            rng=random.Random(1),  # noqa: S311 - test fixture
        )


def test_secure_round_aborts_on_tampered_vss_share(tmp_path):
    # The third leg: a corrupted seed share is caught during reconstruction.
    parties = ["a", "b", "c"]
    dim = 2
    skeys, strust = _identities(parties)
    sess = _vsession(parties, dim)
    victim = "a"
    x = sess._x["b"]
    sess._self_shares[victim][x] = (sess._self_shares[victim][x] + 1) % GROUP.q
    from presidio_ai.fl.commit import CommitmentError

    with pytest.raises(CommitmentError, match="inconsistent VSS share"):
        run_secure_consortium_round(
            round_id="r4",
            updates=_updates(parties, dim),
            dp_results=_dp(parties),
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            survivor_signatures=_signed_alive(parties, "r4", skeys),
            survivor_trust=strust,
            survivor_threshold=2,
            backend=BACKEND,
            rng=random.Random(1),  # noqa: S311 - test fixture
        )


def test_secure_round_requires_verifiable_session(tmp_path):
    parties = ["a", "b"]
    plain = SecureAggregationSession(parties, dim=2, threshold=2, rng=random.Random(0))  # noqa: S311
    with pytest.raises(ConsortiumError, match="verifiable-mode session"):
        run_secure_consortium_round(
            round_id="r5",
            updates=_updates(parties, 2),
            dp_results=_dp(parties),
            session=plain,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            survivor_signatures={},
            survivor_trust={},
            survivor_threshold=1,
            backend=BACKEND,
        )


# --- bounded-norm input validation gate (ADR-0003, v0.20.0) ---------------


def test_secure_round_with_bounded_norm_gate(tmp_path):
    parties = ["bankA", "bankB", "bankC"]
    dim = 3
    skeys, strust = _identities(parties)
    updates = _updates(parties, dim)  # values in [0, 1)
    sess = _vsession(parties, dim)
    ledger = Ledger(tmp_path / "round.jsonl", key=KEY)
    res = run_secure_consortium_round(
        round_id="rb1",
        updates=updates,
        dp_results=_dp(parties),
        session=sess,
        ledger=ledger,
        survivor_signatures=_signed_alive(parties, "rb1", skeys),
        survivor_trust=strust,
        survivor_threshold=2,
        backend=BACKEND,
        clip_bound=2.0,
        rng=random.Random(7),  # noqa: S311 - test fixture
    )
    expected = [sum(updates[p][k] for p in parties) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(res.aggregate, expected, strict=True))
    from presidio_ai.fl.consortium import CONSORTIUM_EVENT

    rnd = [e for e in verify_chain(ledger.path, key=KEY) if e.event == CONSORTIUM_EVENT][0].payload
    # Audit 2026-11-03: an L-inf bound proves no L2 sensitivity (up to B*sqrt(dim)).
    assert rnd["sensitivity_proven"] is False
    assert rnd["proven_norm"] == "linf" and rnd["clip_bound"] == "2"


def test_consortium_commitment_carries_proven_norm_only_when_gated():
    from presidio_ai.evidence import consortium_commitment

    base = dict(
        round_id="r",
        aggregate_field=[1, 2],
        max_epsilon=1.0,
        delta=1e-5,
        n_parties=3,
        n_survivors=3,
    )
    assert "proven_norm" not in consortium_commitment(**base)
    gated = consortium_commitment(**base, proven_norm="l2", norm_bound=1.5)
    assert gated["proven_norm"] == "l2" and gated["norm_bound"] == "1.5"
    with pytest.raises(ValueError):
        consortium_commitment(**base, proven_norm="l2")
    with pytest.raises(ValueError):
        consortium_commitment(**base, proven_norm="l1", norm_bound=1.0)


def test_secure_round_rejects_poisoning_update(tmp_path):
    # A party whose update exceeds the clip sensitivity is rejected by the ZK gate.
    parties = ["bankA", "bankB", "bankC"]
    dim = 2
    skeys, strust = _identities(parties)
    updates = _updates(parties, dim)
    updates["bankC"] = [50.0, 0.1]  # boosting / poisoning: way over the clip bound
    sess = _vsession(parties, dim)
    with pytest.raises(ConsortiumError, match="bounded-norm"):
        run_secure_consortium_round(
            round_id="rb2",
            updates=updates,
            dp_results=_dp(parties),
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            survivor_signatures=_signed_alive(parties, "rb2", skeys),
            survivor_trust=strust,
            survivor_threshold=2,
            backend=BACKEND,
            clip_bound=2.0,
            rng=random.Random(3),  # noqa: S311 - test fixture
        )


# --- L2 bounded-norm gate (ADR-0005, v0.23.0) -----------------------------


def test_secure_round_with_l2_gate(tmp_path):
    parties = ["bankA", "bankB", "bankC"]
    dim = 3
    skeys, strust = _identities(parties)
    updates = _updates(parties, dim)  # values in [0, 1) -> small L2 norm
    sess = _vsession(parties, dim)
    ledger = Ledger(tmp_path / "round.jsonl", key=KEY)
    res = run_secure_consortium_round(
        round_id="l2-1",
        updates=updates,
        dp_results=_dp(parties),
        session=sess,
        ledger=ledger,
        survivor_signatures=_signed_alive(parties, "l2-1", skeys),
        survivor_trust=strust,
        survivor_threshold=2,
        backend=BACKEND,
        l2_bound=2.0,
        rng=random.Random(7),  # noqa: S311 - test fixture
    )
    expected = [sum(updates[p][k] for p in parties) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(res.aggregate, expected, strict=True))
    from presidio_ai.fl.consortium import CONSORTIUM_EVENT

    rnd = [e for e in verify_chain(ledger.path, key=KEY) if e.event == CONSORTIUM_EVENT][0].payload
    assert (
        rnd["sensitivity_proven"] is True and rnd["proven_norm"] == "l2" and rnd["l2_bound"] == "2"
    )


def test_secure_round_l2_rejects_high_norm_update(tmp_path):
    # An update within a generous L∞ but exceeding the L2 bound is rejected.
    parties = ["bankA", "bankB", "bankC"]
    dim = 3
    skeys, strust = _identities(parties)
    updates = _updates(parties, dim)
    updates["bankC"] = [1.5, 1.5, 1.5]  # L2 norm^2 = 6.75 > 2^2 = 4
    sess = _vsession(parties, dim)
    with pytest.raises(ConsortiumError, match="L2 bound"):
        run_secure_consortium_round(
            round_id="l2-2",
            updates=updates,
            dp_results=_dp(parties),
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            survivor_signatures=_signed_alive(parties, "l2-2", skeys),
            survivor_trust=strust,
            survivor_threshold=2,
            backend=BACKEND,
            l2_bound=2.0,
            rng=random.Random(3),  # noqa: S311 - test fixture
        )


# --- GOD interim: exclude-and-retry (ADR-0006 Option D, v0.25.0) -----------


def test_retry_excludes_cheater_and_completes(tmp_path):
    from presidio_ai.fl.consortium import run_consortium_round_with_retry

    parties = ["bankA", "bankB", "bankC", "bankD"]
    dim = 3
    skeys, strust = _identities(parties)
    updates = _updates(parties, dim)
    updates["bankC"] = [50.0, 0.0, 0.0]  # poisoning: over the L2 clip bound
    sess = _vsession(parties, dim, threshold=2)
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    out = run_consortium_round_with_retry(
        round_id="god-d",
        updates=updates,
        dp_results=_dp(parties),
        session=sess,
        ledger=ledger,
        survivor_signers={p: SurvivorSetSigner(p, skeys[p]) for p in parties},
        survivor_trust=strust,
        survivor_threshold=2,
        backend=BACKEND,
        l2_bound=2.0,
        rng=random.Random(5),  # noqa: S311 - test fixture
    )
    assert out.excluded == ["bankC"]
    assert set(out.result.survivors) == {"bankA", "bankB", "bankD"}
    expected = [sum(updates[p][k] for p in ["bankA", "bankB", "bankD"]) for k in range(dim)]
    assert all(abs(a - e) < 1e-3 for a, e in zip(out.result.aggregate, expected, strict=True))


def test_retry_fails_closed_when_too_few_honest_remain(tmp_path):
    from presidio_ai.fl.consortium import run_consortium_round_with_retry

    parties = ["a", "b", "c"]
    dim = 2
    skeys, strust = _identities(parties)
    updates = _updates(parties, dim)
    updates["b"] = [9.0, 9.0]  # over bound
    updates["c"] = [9.0, 9.0]  # over bound -> after excluding both, < threshold remain
    sess = _vsession(parties, dim, threshold=2)
    with pytest.raises(ConsortiumError, match="honest parties remain"):
        run_consortium_round_with_retry(
            round_id="god-d2",
            updates=updates,
            dp_results=_dp(parties),
            session=sess,
            ledger=Ledger(tmp_path / "r.jsonl", key=KEY),
            survivor_signers={p: SurvivorSetSigner(p, skeys[p]) for p in parties},
            survivor_trust=strust,
            survivor_threshold=2,
            backend=BACKEND,
            l2_bound=2.0,
            rng=random.Random(1),  # noqa: S311 - test fixture
        )


# --- survivor-set signatures are Ed25519 and ledgered (audit 2026-11-03) -----


def test_coordinator_without_private_keys_cannot_forge_survivor_signatures():
    alive = ["a", "b", "c"]
    skeys, strust = _identities(alive)
    # The coordinator holds only the public trust store. Its best attempt: sign with a
    # key of its own under the parties' names.
    rogue, _ = generate_ed25519_keypair()
    forged = {p: sign_survivor_set("r1", alive, party_id=p, private_key_hex=rogue) for p in alive}
    with pytest.raises(ConsortiumError, match="0 valid signature"):
        verify_survivor_set("r1", alive, signatures=forged, identity_trust=strust, threshold=2)


def test_signers_outside_alive_or_session_do_not_count():
    parties = ["a", "b", "c", "z"]
    skeys, strust = _identities(parties)
    alive = ["a", "b"]
    sigs = _signed_alive(alive, "r1", skeys)
    sigs["z"] = sign_survivor_set("r1", alive, party_id="z", private_key_hex=skeys["z"])
    with pytest.raises(ConsortiumError, match="survivor-set agreement failed"):
        verify_survivor_set(
            "r1",
            alive,
            signatures={"a": sigs["a"], "z": sigs["z"]},
            identity_trust=strust,
            threshold=2,
        )
    got = verify_survivor_set(
        "r1", alive, signatures=sigs, identity_trust=strust, threshold=2, eligible=["a", "b", "c"]
    )
    assert got == ["a", "b"]


def test_signature_is_bound_to_the_attempt():
    alive = ["a", "b"]
    skeys, strust = _identities(alive)
    sigs = _signed_alive(alive, "r1", skeys, attempt=1)
    with pytest.raises(ConsortiumError):
        verify_survivor_set(
            "r1", alive, signatures=sigs, identity_trust=strust, threshold=2, attempt=2
        )


def test_survivor_set_signer_refuses_a_second_set_for_the_same_attempt():
    skeys, _ = _identities(["a"])
    signer = SurvivorSetSigner("a", skeys["a"])
    signer("r1", ["a", "b", "c"], attempt=1)
    signer("r1", ["a", "b", "c"], attempt=1)  # same set again is fine
    with pytest.raises(ConsortiumError, match="already signed a different"):
        signer("r1", ["a", "b"], attempt=1)
    signer("r1", ["a", "b"], attempt=2)  # a new attempt is a new statement


def test_ledger_carries_verifiable_signatures_and_rejects_a_second_set(tmp_path):
    from presidio_ai.evidence import verify_ed25519
    from presidio_ai.fl.consortium import survivor_set_hash

    parties = ["bankA", "bankB", "bankC"]
    skeys, strust = _identities(parties)
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    kwargs = dict(
        dp_results=_dp(parties),
        ledger=ledger,
        survivor_trust=strust,
        survivor_threshold=2,
        backend=BACKEND,
    )
    run_secure_consortium_round(
        round_id="r1",
        updates=_updates(parties, 2),
        session=_vsession(parties, 2),
        survivor_signatures=_signed_alive(parties, "r1", skeys),
        rng=random.Random(2),  # noqa: S311 - test fixture
        **kwargs,
    )
    entry = [e for e in verify_chain(ledger.path, key=KEY) if e.event == SURVIVOR_SET_EVENT][0]
    payload = entry.payload
    assert payload["attempt"] == 1 and payload["threshold"] == 2
    digest = survivor_set_hash("r1", payload["alive"], attempt=1)
    assert payload["set_hash"] == digest
    for party, sig in payload["signatures"].items():  # auditable from public keys alone
        assert verify_ed25519(digest, party, sig, strust[party])
    # The same round and attempt cannot be ledgered twice, even with a smaller set.
    with pytest.raises(ConsortiumError, match="already has a survivor set"):
        run_secure_consortium_round(
            round_id="r1",
            updates={p: v for p, v in _updates(parties, 2).items() if p != "bankC"},
            session=_vsession(parties, 2),
            survivor_signatures=_signed_alive(["bankA", "bankB"], "r1", skeys),
            **kwargs,
        )


def test_retry_records_one_survivor_set_per_attempt(tmp_path):
    from presidio_ai.fl.consortium import run_consortium_round_with_retry

    parties = ["bankA", "bankB", "bankC", "bankD"]
    skeys, strust = _identities(parties)
    updates = _updates(parties, 2)
    updates["bankC"] = [50.0, 0.0]
    ledger = Ledger(tmp_path / "r.jsonl", key=KEY)
    run_consortium_round_with_retry(
        round_id="rr",
        updates=updates,
        dp_results=_dp(parties),
        session=_vsession(parties, 2),
        ledger=ledger,
        survivor_signers={p: SurvivorSetSigner(p, skeys[p]) for p in parties},
        survivor_trust=strust,
        survivor_threshold=2,
        backend=BACKEND,
        l2_bound=2.0,
        rng=random.Random(4),  # noqa: S311 - test fixture
    )
    sets = [e.payload for e in verify_chain(ledger.path, key=KEY) if e.event == SURVIVOR_SET_EVENT]
    assert [(s["attempt"], s["alive"]) for s in sets] == [
        (1, ["bankA", "bankB", "bankC", "bankD"]),
        (2, ["bankA", "bankB", "bankD"]),
    ]
