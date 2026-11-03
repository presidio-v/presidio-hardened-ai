from __future__ import annotations

import pytest

from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.dp.authorization import (
    MPADenied,
    MPAPolicy,
    authorize,
    build_request,
    request_hash,
    requires_authorization,
    sign_approval,
    valid_approvers,
    verify_approval,
)

R = dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.05, steps=2000, delta=1e-5)
KEYS = {"alice": "ka", "bob": "kb", "carol": "kc"}


def _rh(job_id="job-1", result=R):
    return request_hash(build_request(result, job_id=job_id))


def _approval(approver, job_id="job-1", result=R):
    return sign_approval(_rh(job_id, result), approver_id=approver, approver_key=KEYS[approver])


def test_sign_verify_roundtrip():
    rh = _rh()
    sig = sign_approval(rh, approver_id="alice", approver_key="ka")
    assert verify_approval(rh, approver_id="alice", signature=sig, approver_key="ka")


def test_signature_bound_to_approver():
    rh = _rh()
    sig = sign_approval(rh, approver_id="alice", approver_key="ka")
    # Same key, different claimed approver id -> invalid.
    assert not verify_approval(rh, approver_id="bob", signature=sig, approver_key="ka")


def test_wrong_key_fails():
    rh = _rh()
    sig = sign_approval(rh, approver_id="alice", approver_key="ka")
    assert not verify_approval(rh, approver_id="alice", signature=sig, approver_key="wrong")


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(threshold=0, min_epsilon=0.0, approvers=("a",)),
        dict(threshold=2, min_epsilon=0.0, approvers=("a",)),
        dict(threshold=1, min_epsilon=0.0, approvers=("a", "a")),
        dict(threshold=1, min_epsilon=-1.0, approvers=("a",)),
    ],
)
def test_policy_validation(kwargs):
    with pytest.raises(ValueError):
        MPAPolicy(**kwargs)


def test_requires_authorization():
    policy = MPAPolicy(threshold=2, min_epsilon=1.0, approvers=tuple(KEYS))
    assert requires_authorization(policy, 2.0)
    assert not requires_authorization(policy, 0.5)
    assert not requires_authorization(None, 99.0)


def test_authorize_succeeds_at_threshold():
    policy = MPAPolicy(threshold=2, min_epsilon=0.0, approvers=tuple(KEYS))
    approvals = {"alice": _approval("alice"), "bob": _approval("bob")}
    rh, approved = authorize(
        R, job_id="job-1", policy=policy, approvals=approvals, approver_keys=KEYS
    )
    assert approved == ["alice", "bob"]
    assert rh == _rh()


def test_authorize_denied_insufficient():
    policy = MPAPolicy(threshold=2, min_epsilon=0.0, approvers=tuple(KEYS))
    approvals = {"alice": _approval("alice")}
    with pytest.raises(MPADenied):
        authorize(R, job_id="job-1", policy=policy, approvals=approvals, approver_keys=KEYS)


def test_valid_approvers_filters_unknown_and_bad():
    policy = MPAPolicy(threshold=1, min_epsilon=0.0, approvers=("alice", "bob"))
    approvals = {
        "alice": _approval("alice"),  # valid
        "bob": "deadbeef",  # bad signature
        "mallory": _approval("alice"),  # not a recognised approver
    }
    assert valid_approvers(_rh(), approvals=approvals, approver_keys=KEYS, policy=policy) == [
        "alice"
    ]


def test_replay_to_other_job_fails():
    policy = MPAPolicy(threshold=1, min_epsilon=0.0, approvers=tuple(KEYS))
    # Approval signed for job-1, presented for job-2.
    approvals = {"alice": _approval("alice", job_id="job-1")}
    with pytest.raises(MPADenied):
        authorize(R, job_id="job-2", policy=policy, approvals=approvals, approver_keys=KEYS)


@pytest.mark.parametrize("bad", ["é" * 64, "\ud800" * 64])
def test_non_ascii_approval_signature_fails_closed(bad):
    assert not verify_approval(_rh(), approver_id="alice", signature=bad, approver_key="ka")
