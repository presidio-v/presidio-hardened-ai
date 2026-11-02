"""Org-wide epsilon budget governed by the tamper-evident ledger.

The ledger is the single source of truth for spend: ``spent()`` re-derives the
consumed budget by verifying the chain and summing the recorded charges, so the
budget cannot be understated without breaking the MAC chain. Composition across
jobs uses basic (sequential) composition — epsilons add, deltas add — which is
always sound and matches the product framing of a finite budget spent down. A
tighter RDP-level cross-job composition is a later refinement.

Recorded charge payloads carry **privacy parameters only** (epsilon, delta, noise
multiplier, sampling rate, steps) — these are accounting facts, not PII, and must
be recorded to make the guarantee auditable.

Since 0.31 those parameters are recorded as decimal strings (schema ``dp-result@1``,
``docs/schemas/signed-payloads.md``); pre-0.31 entries hold floats. :meth:`spent`
sums both forms exactly with :class:`~decimal.Decimal`. Half-even rounding at 12
fractional digits can understate a recorded epsilon by at most 5e-13 per charge,
which the 1e-12 admission tolerance already absorbs for any realistic charge count.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal

from presidio_ai.dp.accountant import DPResult, dpsgd_epsilon
from presidio_ai.dp.authorization import MPAPolicy, authorize_request, requires_authorization
from presidio_ai.ledger import Ledger, verify_chain
from presidio_ai.numeric import encode_field
from presidio_ai.provenance import with_parents

CHARGE_EVENT = "dp-budget-charge"
AUTHORIZED_EVENT = "mpa-authorized"


def _as_decimal(value: object) -> Decimal:
    """Exact value of a recorded epsilon/delta (a decimal string; 0 when absent).

    Verified entries are strict-canonical, so a float cannot appear here.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"malformed recorded privacy parameter: {value!r}")
    try:
        out = Decimal(value)
    except ArithmeticError as exc:
        raise ValueError(f"malformed recorded privacy parameter: {value!r}") from exc
    if not out.is_finite():
        raise ValueError(f"non-finite recorded privacy parameter: {value!r}")
    return out


def authorization_payload(
    *,
    job_id: str,
    epsilon: float,
    threshold: int,
    approvers: Sequence[str],
    request_hash: str,
    request_canon: int,
) -> dict[str, object]:
    """Ledger payload of an ``mpa-authorized`` entry (float-free)."""
    return {
        "job_id": job_id,
        "epsilon": encode_field("epsilon", epsilon),
        "threshold": threshold,
        "approvers": list(approvers),
        "request_hash": request_hash,
        "request_canon": request_canon,
    }


class BudgetExceeded(RuntimeError):
    """Raised when a charge would exceed the configured epsilon budget."""


@dataclass(frozen=True)
class ChargeResult:
    job_id: str
    result: DPResult
    spent_epsilon: float
    remaining_epsilon: float
    ledger_seq: int


class EpsilonBudget:
    def __init__(self, total_epsilon: float, delta: float, ledger: Ledger) -> None:
        if total_epsilon <= 0:
            raise ValueError("total_epsilon must be > 0")
        if not 0.0 < delta < 1.0:
            raise ValueError("delta must be in (0, 1)")
        self.total_epsilon = float(total_epsilon)
        self.delta = float(delta)
        self.ledger = ledger

    def _charges(self) -> list[dict]:
        # Verify the chain first: a tampered ledger must not yield a spend figure.
        entries = verify_chain(self.ledger.path, key=self.ledger._key)
        return [e.payload for e in entries if e.event == CHARGE_EVENT]

    def spent(self) -> float:
        return float(sum((_as_decimal(p.get("epsilon", 0)) for p in self._charges()), Decimal(0)))

    def spent_delta(self) -> float:
        return float(sum((_as_decimal(p.get("delta", 0)) for p in self._charges()), Decimal(0)))

    def remaining(self) -> float:
        return max(self.total_epsilon - self.spent(), 0.0)

    def charge(
        self,
        result: DPResult,
        *,
        job_id: str,
        policy: MPAPolicy | None = None,
        approvals: Mapping[str, str] | None = None,
        approver_keys: Mapping[str, str] | None = None,
        parents: Iterable[str] | None = None,
    ) -> ChargeResult:
        """Charge a pre-computed DP result to the budget, recording it to the ledger.

        If ``policy`` is set and the charge's epsilon meets the policy threshold, the
        charge requires n-of-m approval (``approvals`` countersignatures verified
        against ``approver_keys``) and is rejected with :class:`MPADenied` otherwise.
        A successful authorization is recorded to the ledger before the charge.
        ``parents`` (ADR-0002 content hashes, e.g. the identity of the gate certificate
        that authorised the run, verified by :mod:`presidio_ai.gate_certificate`) are
        recorded in the charge entry, omitted when empty.
        """
        if not job_id or not isinstance(job_id, str):
            raise ValueError("job_id must be a non-empty string")
        prospective = self.spent() + result.epsilon
        if prospective > self.total_epsilon + 1e-12:
            raise BudgetExceeded(
                f"job '{job_id}' needs epsilon={result.epsilon:.4f}; "
                f"only {self.remaining():.4f} of {self.total_epsilon:.4f} remains"
            )
        if requires_authorization(policy, result.epsilon):
            req_hash, approvers, req_canon = authorize_request(
                result,
                job_id=job_id,
                policy=policy,
                approvals=approvals or {},
                approver_keys=approver_keys or {},
            )
            self.ledger.append(
                AUTHORIZED_EVENT,
                authorization_payload(
                    job_id=job_id,
                    epsilon=result.epsilon,
                    threshold=policy.threshold,
                    approvers=approvers,
                    request_hash=req_hash,
                    request_canon=req_canon,
                ),
            )
        payload = with_parents({"job_id": job_id, **result.signed_dict()}, parents)
        entry = self.ledger.append(CHARGE_EVENT, payload)
        return ChargeResult(
            job_id=job_id,
            result=result,
            spent_epsilon=prospective,
            remaining_epsilon=max(self.total_epsilon - prospective, 0.0),
            ledger_seq=entry.seq,
        )

    def charge_dpsgd(
        self,
        *,
        job_id: str,
        noise_multiplier: float,
        sample_rate: float,
        steps: int,
        policy: MPAPolicy | None = None,
        approvals: Mapping[str, str] | None = None,
        approver_keys: Mapping[str, str] | None = None,
        parents: Iterable[str] | None = None,
    ) -> ChargeResult:
        """Account a DP-SGD run at the budget's delta, then charge it (with optional MPA)."""
        result = dpsgd_epsilon(
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate,
            steps=steps,
            delta=self.delta,
        )
        return self.charge(
            result,
            job_id=job_id,
            policy=policy,
            approvals=approvals,
            approver_keys=approver_keys,
            parents=parents,
        )
