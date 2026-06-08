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

from presidio_ai.dp.accountant import DPResult
from presidio_ai.dp.authorization import MPAPolicy, authorize, requires_authorization
from presidio_ai.dp.budget import AUTHORIZED_EVENT, ChargeResult, EpsilonBudget
from presidio_ai.evidence import (
    build_consortium_evidence,
    consortium_commitment,
    export_evidence,
)
from presidio_ai.fl.secure_agg import SecureAggregationSession
from presidio_ai.ledger import Ledger

CONSORTIUM_EVENT = "consortium-round"


class ConsortiumError(RuntimeError):
    """Raised on a malformed or unauthorized consortium round."""


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
