"""Per-round consortium composition (P4 / v0.13.0).

Ties the secure-aggregation core (ADR-0001) to the family's governance primitives
so that one *consortium round* is, end to end, a governed operation:

1. **Authorize the round (n-of-m MPA).** If a policy is set and the round's
   worst-case per-party epsilon meets the threshold, the round runs only after
   ``threshold`` recognised approvers have countersigned it. The authorization is
   recorded to the round ledger before any aggregation.
2. **Aggregate under secure aggregation.** Each surviving silo's (already
   DP-noised) update is masked and combined in the exact field domain; the
   coordinator recovers only the aggregate, never an individual update. Dropouts
   are recovered via Shamir reconstruction, or the round fails closed.
3. **Charge per-silo DP.** Each silo's composed ``(epsilon, delta)`` for the round
   is charged to its *own* tamper-evident ledger budget (distributed DP: privacy
   is accounted per party, the aggregate adds the secure-aggregation guarantee on
   top).
4. **Emit one signed D4 per round.** A single evidence reference commits to the
   *aggregate only* (its field-domain hash) plus the round's worst-case
   ``(epsilon, delta)`` and participation counts — never a member's update — and
   points at the round's ledger entry. Commitments only.

This is the in-process reference: the coordinator masks each update here. In a
deployment each silo masks locally with seeds from authenticated key agreement
(:mod:`presidio_ai.fl.keyagreement`) and the masked vectors arrive over the
``[mpc]`` transport; the governance flow above is identical.
"""

from __future__ import annotations

from collections.abc import Hashable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from presidio_ai.dp.accountant import DPResult
from presidio_ai.dp.authorization import MPAPolicy, authorize, requires_authorization
from presidio_ai.dp.budget import AUTHORIZED_EVENT, ChargeResult, EpsilonBudget
from presidio_ai.evidence import (
    build_consortium_evidence,
    consortium_commitment,
    export_evidence,
)
from presidio_ai.fl.proof_backend import ProofBackend, get_backend
from presidio_ai.fl.secure_agg import PRIME, SecureAggregationSession, dequantize
from presidio_ai.fl.zk import ProofError
from presidio_ai.hashing import constant_time_equals, hmac_hex, sha256_hex
from presidio_ai.ledger import Ledger

CONSORTIUM_EVENT = "consortium-round"
SURVIVOR_SET_EVENT = "consortium-survivor-set"


class ConsortiumError(RuntimeError):
    """Raised on a malformed or unauthorized consortium round."""


class PartyMisbehavior(ConsortiumError):
    """An attributable misbehavior by a specific party (enables exclude-and-retry, ADR-0006)."""

    def __init__(self, party_id, message: str) -> None:
        super().__init__(message)
        self.party_id = party_id


@dataclass(frozen=True)
class ConsortiumRoundResult:
    round_id: str
    aggregate: list[float]  # de-quantised aggregate update
    aggregate_field: list[int]  # exact field-domain aggregate (the committed value)
    survivors: list[Hashable]
    dropped: list[Hashable]
    max_epsilon: float
    delta: float
    per_silo_charge: dict[str, ChargeResult]
    approvers: list[str]  # empty if the round was below the authorization threshold
    ledger_seq: int  # the consortium-round ledger entry
    evidence_path: Path | None


def run_consortium_round(
    *,
    round_id: str,
    updates: Mapping[Hashable, Sequence[float]],
    dp_results: Mapping[Hashable, DPResult],
    session: SecureAggregationSession,
    ledger: Ledger,
    budgets: Mapping[Hashable, EpsilonBudget] | None = None,
    dropped: Sequence[Hashable] = (),
    policy: MPAPolicy | None = None,
    approvals: Mapping[str, str] | None = None,
    approver_keys: Mapping[str, str] | None = None,
    signing_key: bytes | str | None = None,
    signer: str = "presidio-hardened-ai",
    algorithm: str = "ed25519",
    evidence_path: str | Path | None = None,
) -> ConsortiumRoundResult:
    """Run one governed secure-aggregation round. See the module docstring for the flow."""
    if not round_id:
        raise ConsortiumError("round_id must be non-empty")
    survivors = [p for p in session.party_ids if p in updates]
    if not survivors:
        raise ConsortiumError("no surviving updates to aggregate")
    missing_dp = [s for s in survivors if s not in dp_results]
    if missing_dp:
        raise ConsortiumError(f"missing DP results for survivors: {missing_dp}")
    deltas = {dp_results[s].delta for s in survivors}
    if len(deltas) != 1:
        raise ConsortiumError("all surviving silos must share one delta for the round")
    delta = deltas.pop()
    # Worst-case per-party exposure gates the round (the most privacy-costly member).
    gating = max((dp_results[s] for s in survivors), key=lambda r: r.epsilon)
    max_epsilon = gating.epsilon

    # 1. Authorize the round (n-of-m), bound to (round_id, gating privacy params).
    approvers: list[str] = []
    if requires_authorization(policy, max_epsilon):
        _req_hash, approved = authorize(
            gating,
            job_id=f"consortium/{round_id}",
            policy=policy,
            approvals=approvals or {},
            approver_keys=approver_keys or {},
        )
        approvers = list(approved)
        ledger.append(
            AUTHORIZED_EVENT,
            {
                "job_id": f"consortium/{round_id}",
                "epsilon": max_epsilon,
                "threshold": policy.threshold,
                "approvers": approvers,
                "request_hash": _req_hash,
            },
        )

    # 2. Secure aggregation (exact field domain; coordinator sees only the aggregate).
    masked = {s: session.mask(s, updates[s]) for s in survivors}
    agg_field = session.aggregate_field(masked, dropped=dropped)
    aggregate = session.aggregate(masked, dropped=dropped)
    dropped_list = [p for p in session.party_ids if p not in updates]

    # 3. Charge each silo's own budget (the round is already authorized as a whole).
    per_silo_charge: dict[str, ChargeResult] = {}
    if budgets is not None:
        for s in survivors:
            budget = budgets.get(s)
            if budget is None:
                continue
            per_silo_charge[str(s)] = budget.charge(
                dp_results[s], job_id=f"consortium/{round_id}/{s}"
            )

    # 4. One commitment + ledger entry + signed D4 for the round (aggregate only).
    commitment = consortium_commitment(
        round_id=round_id,
        aggregate_field=agg_field,
        max_epsilon=max_epsilon,
        delta=delta,
        n_parties=len(session.party_ids),
        n_survivors=len(survivors),
    )
    entry = ledger.append(
        CONSORTIUM_EVENT,
        {
            "round_id": round_id,
            "aggregate_sha256": commitment["aggregate_sha256"],
            "max_epsilon": max_epsilon,
            "delta": delta,
            "n_parties": len(session.party_ids),
            "n_survivors": len(survivors),
            "n_dropped": len(dropped_list),
            "per_silo_epsilon": {str(s): dp_results[s].epsilon for s in survivors},
        },
    )

    out_path: Path | None = None
    if evidence_path is not None:
        if signing_key is None:
            raise ConsortiumError("evidence_path requires a signing_key")
        refs = build_consortium_evidence(
            commitment,
            signing_key=signing_key,
            signer=signer,
            round_seq=entry.seq,
            algorithm=algorithm,
        )
        out_path = export_evidence(refs, evidence_path, use_case=f"consortium/{round_id}")

    return ConsortiumRoundResult(
        round_id=round_id,
        aggregate=aggregate,
        aggregate_field=agg_field,
        survivors=survivors,
        dropped=dropped_list,
        max_epsilon=max_epsilon,
        delta=delta,
        per_silo_charge=per_silo_charge,
        approvers=approvers,
        ledger_seq=entry.seq,
        evidence_path=out_path,
    )


# ── Malicious-security hardening (ADR-0002) ─────────────────────────────────
# Two checks turn the honest-but-curious round into one that survives a *deviating*
# coordinator or party, with security-with-abort:
#   1. a signed, ledger-anchored agreement on the survivor set (defeats the
#      coordinator-equivocation unmasking attack), and
#   2. a homomorphic check of the returned aggregate against Pedersen-committed inputs
#      (defeats a coordinator that returns a false aggregate).
# Feldman-VSS share verification (the third leg) lives in the verifiable-mode
# SecureAggregationSession and fires during reconstruction.


def survivor_set_message(round_id: str, alive: Sequence[str]) -> dict[str, object]:
    """Canonical message a party signs to attest the round's survivor set."""
    return {"round_id": round_id, "alive": sorted(alive)}


def sign_survivor_set(round_id: str, alive: Sequence[str], *, party_id: str, key: str) -> str:
    """A party's signature over (round_id, sorted survivor set), bound to its id."""
    msg = {**survivor_set_message(round_id, alive), "party": party_id}
    return hmac_hex(key.encode("utf-8"), msg)


def verify_survivor_set(
    round_id: str,
    alive: Sequence[str],
    *,
    signatures: Mapping[str, str],
    keys: Mapping[str, str],
    threshold: int,
) -> list[str]:
    """Return the parties that validly signed *this* survivor set; abort below threshold.

    Each signature binds the exact ``alive`` set, so a coordinator cannot obtain
    ``threshold`` signatures over two *different* sets — presenting a set the parties did
    not sign makes their signatures fail to verify here. Fail-closed.
    """
    good: list[str] = []
    for party_id, sig in signatures.items():
        key = keys.get(party_id)
        if key is None:
            continue
        expected = sign_survivor_set(round_id, alive, party_id=party_id, key=key)
        if constant_time_equals(expected, sig):
            good.append(party_id)
    if len(good) < threshold:
        raise ConsortiumError(
            f"survivor-set agreement failed for round '{round_id}': "
            f"{len(good)} valid signature(s) over the presented set, need {threshold}"
        )
    return sorted(good)


def commit_quantized(
    q_vector: Sequence[int], *, backend: ProofBackend, rng=None
) -> tuple[list, list[int]]:
    """Per-coordinate Pedersen commitments to a vector; return (commits, randomness).

    Commitments are opaque backend objects (int for MODP, point bytes for Ristretto).
    """
    randomness = [backend.random_blinding() for _ in q_vector]
    commits = [backend.commit(v, r) for v, r in zip(q_vector, randomness, strict=True)]
    return commits, randomness


def verify_aggregate_commitment(
    aggregate_field: Sequence[int],
    party_commits: Mapping[Hashable, Sequence[Any]],
    party_randomness: Mapping[Hashable, Sequence[int]],
    *,
    backend: ProofBackend,
    prime: int = PRIME,
) -> bool:
    """Check the aggregate against the homomorphic sum of per-party input commitments.

    Parties commit to *signed* fixed-point values, so per coordinate ``k`` the product
    ``Π_i C[i][k]`` must equal ``pedersen_commit(centered(aggregate[k]), Σ_i r[i][k])``,
    where ``centered`` maps a masking-field element above ``prime/2`` to its negative.
    Holds when the true per-coordinate sum does not wrap the masking field (the same
    no-overflow operating range that correct de-quantisation already requires).
    """
    dim = len(aggregate_field)
    for k in range(dim):
        product = backend.sum([party_commits[p][k] for p in party_commits])
        r_sum = sum(party_randomness[p][k] for p in party_randomness)
        centered = (
            aggregate_field[k] - prime if aggregate_field[k] > prime // 2 else aggregate_field[k]
        )
        if product != backend.commit(centered, r_sum):
            return False
    return True


@dataclass(frozen=True)
class SecureConsortiumResult:
    round_id: str
    aggregate: list[float]
    aggregate_field: list[int]
    survivors: list[Hashable]
    survivor_signers: list[str]
    max_epsilon: float
    delta: float
    per_silo_charge: dict[str, ChargeResult]
    approvers: list[str]
    ledger_seq: int
    evidence_path: Path | None


def run_secure_consortium_round(
    *,
    round_id: str,
    updates: Mapping[Hashable, Sequence[float]],
    dp_results: Mapping[Hashable, DPResult],
    session: SecureAggregationSession,
    ledger: Ledger,
    survivor_signatures: Mapping[str, str],
    survivor_keys: Mapping[str, str],
    survivor_threshold: int,
    backend: ProofBackend | None = None,
    budgets: Mapping[Hashable, EpsilonBudget] | None = None,
    policy: MPAPolicy | None = None,
    approvals: Mapping[str, str] | None = None,
    approver_keys: Mapping[str, str] | None = None,
    signing_key: bytes | str | None = None,
    signer: str = "presidio-hardened-ai",
    algorithm: str = "ed25519",
    evidence_path: str | Path | None = None,
    clip_bound: float | None = None,
    l2_bound: float | None = None,
    rng=None,
) -> SecureConsortiumResult:
    """A consortium round hardened against active deviation (ADR-0002, security-with-abort).

    Order of operations is abort-before-side-effects: (1) the survivor set is agreed by
    ``survivor_threshold`` signatures and anchored to the ledger; (2) inputs are
    Pedersen-committed; (3) the verifiable-mode session aggregates (Feldman-VSS-checked
    reconstruction); (4) the aggregate is checked homomorphically against the commitments —
    only then are (5) MPA authorization, per-silo DP charges, the round ledger entry, and
    the signed ``D4`` evidence performed.

    If ``clip_bound`` is given (ADR-0003), each survivor must also supply a zero-knowledge
    L∞ bounded-norm proof that every committed coordinate lies in ``[-B, B]`` with ``B``
    the clip sensitivity (in fixed-point units); a contribution whose proof fails — or
    whose update is out of bound — is rejected, so the per-client DP sensitivity is
    *proven*, not assumed. The proven outcome is recorded on the ledger.
    """
    if session.group is None:
        raise ConsortiumError("run_secure_consortium_round requires a verifiable-mode session")
    if not round_id:
        raise ConsortiumError("round_id must be non-empty")
    backend = backend if backend is not None else get_backend()
    survivors = [p for p in session.party_ids if p in updates]
    if not survivors:
        raise ConsortiumError("no surviving updates to aggregate")
    missing_dp = [s for s in survivors if s not in dp_results]
    if missing_dp:
        raise ConsortiumError(f"missing DP results for survivors: {missing_dp}")
    deltas = {dp_results[s].delta for s in survivors}
    if len(deltas) != 1:
        raise ConsortiumError("all surviving silos must share one delta for the round")
    delta = deltas.pop()

    # 1. Survivor-set agreement (defeats coordinator equivocation), anchored to the ledger.
    alive = [str(s) for s in survivors]
    signers = verify_survivor_set(
        round_id,
        alive,
        signatures=survivor_signatures,
        keys=survivor_keys,
        threshold=survivor_threshold,
    )
    ledger.append(
        SURVIVOR_SET_EVENT,
        {
            "round_id": round_id,
            "alive": sorted(alive),
            "signers": signers,
            "set_hash": sha256_hex(survivor_set_message(round_id, alive)),
        },
    )

    # 2. Commit each survivor's *signed* fixed-point input (Pedersen, additively homomorphic;
    # signed so the same commitment is range-provable and the homomorphic check composes).
    scale = 1 << session.frac_bits
    s_updates = {s: [round(v * scale) for v in updates[s]] for s in survivors}
    party_commits: dict[Hashable, list[Any]] = {}
    party_randomness: dict[Hashable, list[int]] = {}
    for s in survivors:
        party_commits[s], party_randomness[s] = commit_quantized(
            s_updates[s], backend=backend, rng=rng
        )

    # 2b. Bounded-norm gate (ADR-0003): each input is ZK-proven within the clip sensitivity,
    # against the *same* commitments, so a poisoning (out-of-norm) contribution is rejected.
    sensitivity_proven = False
    if clip_bound is not None:
        if clip_bound <= 0:
            raise ConsortiumError("clip_bound must be > 0")
        bound_fp = round(clip_bound * scale)
        for sid in survivors:
            try:
                norm_proof = backend.prove_bounded(
                    s_updates[sid], party_randomness[sid], bound=bound_fp, rng=rng
                )
            except ProofError as exc:
                raise PartyMisbehavior(
                    sid, f"input failed bounded-norm for '{sid}' (norm > clip sensitivity): {exc}"
                ) from exc
            if not backend.verify_bounded(party_commits[sid], norm_proof, bound=bound_fp):
                raise PartyMisbehavior(sid, f"bounded-norm proof did not verify for '{sid}'")
        sensitivity_proven = True

    proven_norm = "linf" if sensitivity_proven else None
    if l2_bound is not None:
        if l2_bound <= 0:
            raise ConsortiumError("l2_bound must be > 0")
        l2_fp = round(l2_bound * scale)
        for sid in survivors:
            try:
                l2_proof = backend.prove_l2_bounded(
                    s_updates[sid], party_randomness[sid], bound=l2_fp, rng=rng
                )
            except ProofError as exc:
                raise PartyMisbehavior(
                    sid, f"input failed L2 bound for '{sid}' (||x||2 > clip sensitivity): {exc}"
                ) from exc
            if not backend.verify_l2_bounded(party_commits[sid], l2_proof, bound=l2_fp):
                raise PartyMisbehavior(sid, f"L2 bounded-norm proof did not verify for '{sid}'")
        sensitivity_proven = True
        proven_norm = "l2"

    # 3. Secure aggregation (verifiable session: VSS-checked reconstruction).
    masked = {s: session.mask_field(s, s_updates[s]) for s in survivors}
    agg_field = session.aggregate_field(masked)

    # 4. Homomorphic aggregate check (defeats a false aggregate). Abort before side effects.
    if not verify_aggregate_commitment(
        agg_field, party_commits, party_randomness, backend=backend, prime=session.prime
    ):
        raise ConsortiumError(
            f"aggregate does not match committed inputs for round '{round_id}' (false aggregate)"
        )
    aggregate = [dequantize(v, frac_bits=session.frac_bits, prime=session.prime) for v in agg_field]

    # 5. Governance: worst-case ε gates MPA; per-silo charge; one signed D4; commitments-only entry.
    gating = max((dp_results[s] for s in survivors), key=lambda r: r.epsilon)
    max_epsilon = gating.epsilon
    approvers: list[str] = []
    if requires_authorization(policy, max_epsilon):
        _req_hash, approved = authorize(
            gating,
            job_id=f"consortium/{round_id}",
            policy=policy,
            approvals=approvals or {},
            approver_keys=approver_keys or {},
        )
        approvers = list(approved)
        ledger.append(
            AUTHORIZED_EVENT,
            {
                "job_id": f"consortium/{round_id}",
                "epsilon": max_epsilon,
                "threshold": policy.threshold,
                "approvers": approvers,
                "request_hash": _req_hash,
            },
        )

    per_silo_charge: dict[str, ChargeResult] = {}
    if budgets is not None:
        for s in survivors:
            budget = budgets.get(s)
            if budget is not None:
                per_silo_charge[str(s)] = budget.charge(
                    dp_results[s], job_id=f"consortium/{round_id}/{s}"
                )

    commitment = consortium_commitment(
        round_id=round_id,
        aggregate_field=agg_field,
        max_epsilon=max_epsilon,
        delta=delta,
        n_parties=len(session.party_ids),
        n_survivors=len(survivors),
    )
    commit_digest = sha256_hex(
        {
            "backend": backend.name,
            "commits": {
                str(s): [backend.serialize_commitment(c) for c in party_commits[s]]
                for s in survivors
            },
        }
    )
    entry = ledger.append(
        CONSORTIUM_EVENT,
        {
            "round_id": round_id,
            "aggregate_sha256": commitment["aggregate_sha256"],
            "input_commitments_sha256": commit_digest,
            "max_epsilon": max_epsilon,
            "delta": delta,
            "n_parties": len(session.party_ids),
            "n_survivors": len(survivors),
            "survivor_signers": signers,
            "sensitivity_proven": sensitivity_proven,
            "proven_norm": proven_norm,
            "clip_bound": clip_bound,
            "l2_bound": l2_bound,
            "per_silo_epsilon": {str(s): dp_results[s].epsilon for s in survivors},
        },
    )

    out_path: Path | None = None
    if evidence_path is not None:
        if signing_key is None:
            raise ConsortiumError("evidence_path requires a signing_key")
        refs = build_consortium_evidence(
            commitment,
            signing_key=signing_key,
            signer=signer,
            round_seq=entry.seq,
            algorithm=algorithm,
        )
        out_path = export_evidence(refs, evidence_path, use_case=f"consortium/{round_id}")

    return SecureConsortiumResult(
        round_id=round_id,
        aggregate=aggregate,
        aggregate_field=agg_field,
        survivors=survivors,
        survivor_signers=signers,
        max_epsilon=max_epsilon,
        delta=delta,
        per_silo_charge=per_silo_charge,
        approvers=approvers,
        ledger_seq=entry.seq,
        evidence_path=out_path,
    )


# ── Guaranteed-output-delivery interim: exclude-and-retry (ADR-0006, Option D) ──
# Liveness under a bounded number of *attributable* cheaters, with no new crypto: run the
# ADR-0002 security-with-abort round; on a PartyMisbehavior, drop that party (it becomes a
# dropout the round already tolerates) and re-run among the rest. Honest parties re-sign the
# (now smaller) survivor set each attempt. This handles malicious *parties*; a malicious
# coordinator is the case the full GOD aggregation (run_god_consortium_round) removes.


@dataclass(frozen=True)
class RetryRoundResult:
    result: SecureConsortiumResult
    excluded: list[Hashable]
    attempts: int


def run_consortium_round_with_retry(
    *,
    round_id: str,
    updates: Mapping[Hashable, Sequence[float]],
    dp_results: Mapping[Hashable, DPResult],
    session: SecureAggregationSession,
    ledger: Ledger,
    survivor_keys: Mapping[str, str],
    survivor_threshold: int,
    max_retries: int | None = None,
    **round_kwargs: Any,
) -> RetryRoundResult:
    """Run the secure round, excluding attributable cheaters and retrying until it completes.

    On a :class:`PartyMisbehavior`, the offending party is dropped and the round re-runs among
    the remainder (honest parties re-sign the smaller survivor set). Bounded by ``max_retries``
    (default: the party count). Fails closed if fewer than ``survivor_threshold`` honest parties
    remain or the retry budget is exhausted.
    """
    remaining = dict(updates)
    excluded: list[Hashable] = []
    budget = max_retries if max_retries is not None else len(remaining)
    for attempt in range(1, budget + 2):
        alive = sorted(str(p) for p in remaining)
        if len(alive) < survivor_threshold:
            raise ConsortiumError(
                f"only {len(alive)} honest parties remain (< threshold {survivor_threshold})"
            )
        signatures = {
            p: sign_survivor_set(round_id, alive, party_id=p, key=survivor_keys[p]) for p in alive
        }
        try:
            result = run_secure_consortium_round(
                round_id=round_id,
                updates=remaining,
                dp_results=dp_results,
                session=session,
                ledger=ledger,
                survivor_signatures=signatures,
                survivor_keys=survivor_keys,
                survivor_threshold=survivor_threshold,
                **round_kwargs,
            )
        except PartyMisbehavior as exc:
            culprit = exc.party_id
            excluded.append(culprit)
            remaining = {p: v for p, v in remaining.items() if str(p) != str(culprit)}
            continue
        return RetryRoundResult(result=result, excluded=excluded, attempts=attempt)
    raise ConsortiumError(f"retry budget exhausted after excluding {excluded}")
