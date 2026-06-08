"""n-of-m authorization for high-epsilon training jobs (multi-party approval).

Mirrors the ``presidio-hardened-x402`` multi-party-authorization design — n-of-m
HMAC-SHA256 countersignatures — but gates a *privacy-budget charge* instead of a
payment. A job whose accounted epsilon meets or exceeds ``min_epsilon`` may only be
charged once ``threshold`` distinct recognised approvers have countersigned its
authorization request. This is the CRO control surface from the plan: high
privacy-risk runs require human/system sign-off, recorded immutably in the ledger.

Approval is over a canonical *authorization request* derived from the job's privacy
parameters, so an approval cannot be replayed onto a different job or different
(epsilon, delta) without invalidating the signature.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from presidio_ai.dp.accountant import DPResult
from presidio_ai.hashing import constant_time_equals, hmac_hex, sha256_hex


class MPADenied(RuntimeError):
    """Raised when an epsilon charge lacks the required n-of-m authorization."""


@dataclass(frozen=True)
class MPAPolicy:
    threshold: int  # required number of distinct valid approvals
    min_epsilon: float  # authorization required only at/above this epsilon
    approvers: tuple[str, ...]  # recognised approver ids

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("threshold must be >= 1")
        if self.min_epsilon < 0:
            raise ValueError("min_epsilon must be >= 0")
        if len(set(self.approvers)) != len(self.approvers):
            raise ValueError("approver ids must be unique")
        if self.threshold > len(self.approvers):
            raise ValueError("threshold cannot exceed the number of approvers")


def build_request(result: DPResult, *, job_id: str) -> dict[str, object]:
    """Canonical authorization request bound to the job's privacy parameters."""
    return {"job_id": job_id, **result.as_dict()}


def request_hash(request: Mapping[str, object]) -> str:
    return sha256_hex(dict(request))


def sign_approval(req_hash: str, *, approver_id: str, approver_key: bytes | str) -> str:
    """Approver-side countersignature over the request hash, bound to the approver id."""
    key = approver_key.encode("utf-8") if isinstance(approver_key, str) else approver_key
    return hmac_hex(key, {"request_hash": req_hash, "approver": approver_id})


def verify_approval(
    req_hash: str, *, approver_id: str, signature: str, approver_key: bytes | str
) -> bool:
    expected = sign_approval(req_hash, approver_id=approver_id, approver_key=approver_key)
    return constant_time_equals(expected, signature)


def requires_authorization(policy: MPAPolicy | None, epsilon: float) -> bool:
    return policy is not None and epsilon >= policy.min_epsilon


def valid_approvers(
    req_hash: str,
    *,
    approvals: Mapping[str, str],
    approver_keys: Mapping[str, str],
    policy: MPAPolicy,
) -> list[str]:
    """Return the sorted list of distinct, recognised, correctly-signed approvers."""
    good: set[str] = set()
    for approver_id, signature in approvals.items():
        if approver_id not in policy.approvers:
            continue
        key = approver_keys.get(approver_id)
        if key is None:
            continue
        if verify_approval(
            req_hash, approver_id=approver_id, signature=signature, approver_key=key
        ):
            good.add(approver_id)
    return sorted(good)


def authorize(
    result: DPResult,
    *,
    job_id: str,
    policy: MPAPolicy,
    approvals: Mapping[str, str],
    approver_keys: Mapping[str, str],
) -> tuple[str, Sequence[str]]:
    """Verify n-of-m approval for a charge. Returns (request_hash, approver_ids).

    Raises :class:`MPADenied` if fewer than ``threshold`` valid distinct approvals.
    """
    request = build_request(result, job_id=job_id)
    req_hash = request_hash(request)
    approved = valid_approvers(
        req_hash, approvals=approvals, approver_keys=approver_keys, policy=policy
    )
    if len(approved) < policy.threshold:
        raise MPADenied(
            f"job '{job_id}' needs {policy.threshold} approval(s) for epsilon="
            f"{result.epsilon:.4f}; got {len(approved)} valid ({', '.join(approved) or 'none'})"
        )
    return req_hash, approved
