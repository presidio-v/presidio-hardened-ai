"""Privacy-preserving Byzantine-ML robustness posture (P4, ADR-0007, Option C).

The crypto stack bounds each contribution's *magnitude* (L∞/L2) and guarantees protocol
honesty and delivery, but a well-formed, in-norm update can still be a **backdoor** or
targeted poison. Classical Byzantine-robust rules inspect *individual* updates — which
secure aggregation exists to hide — so this module does **not** attempt to detect a stealthy
backdoor on a hidden update. It provides the **containment** layer that operates only on the
*aggregate* (the candidate global the coordinator is already allowed to see):

* a user-supplied **validation** callback scores the candidate against a clean held-out set;
* a **canary / trigger** check tests known backdoor triggers on the candidate;
* thresholds reject a round whose score is too low, regresses too far from the previous
  round, or fails a canary — and the round is **rolled back** (its aggregate is not applied,
  no DP budget is charged, no evidence is emitted) with a flag recorded on the ledger.

This is one layer of the ADR-0007 posture; the others are *influence-bounding by construction*
(the proven L2 norm + per-client DP, which already bound any single client's effect on the
model) and *accountability* (known participants, MPA, signed/ledgered contributions). The
suite ships no data: the consortium supplies the ``validate`` callback (its clean set and
canaries). The residual — a stealthy, validation-passing backdoor — is documented in
SECURITY.md, not claimed away.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RobustnessMetrics:
    """Result of validating a candidate aggregate against the clean set + canaries."""

    score: float  # e.g. accuracy / utility on the clean validation set (higher is better)
    canary_pass: bool  # every known-trigger canary behaved correctly (no backdoor fired)
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RobustnessPolicy:
    """Acceptance policy for a round's candidate aggregate (operates on the aggregate only).

    ``validate`` is supplied by the consortium and owns the clean validation set and the
    canary/trigger suite; it must not depend on any individual party's update.
    """

    validate: Callable[[Sequence[float]], RobustnessMetrics]
    min_score: float = 0.0  # reject below this absolute score
    max_regression: float = float("inf")  # reject if score drops more than this vs previous
    require_canary: bool = True  # reject if any canary/trigger fails


@dataclass(frozen=True)
class RobustnessVerdict:
    accepted: bool
    metrics: RobustnessMetrics
    reason: str


def evaluate(
    candidate: Sequence[float],
    policy: RobustnessPolicy,
    *,
    previous_score: float | None = None,
) -> RobustnessVerdict:
    """Score a candidate aggregate and decide accept/reject (fail-closed on a failed canary)."""
    metrics = policy.validate(candidate)
    if policy.require_canary and not metrics.canary_pass:
        return RobustnessVerdict(False, metrics, "canary/trigger test failed (possible backdoor)")
    if metrics.score < policy.min_score:
        return RobustnessVerdict(
            False, metrics, f"validation score {metrics.score:.4f} below min {policy.min_score:.4f}"
        )
    if previous_score is not None and (previous_score - metrics.score) > policy.max_regression:
        return RobustnessVerdict(
            False,
            metrics,
            f"validation regressed by {previous_score - metrics.score:.4f} "
            f"(> {policy.max_regression:.4f})",
        )
    return RobustnessVerdict(True, metrics, "accepted")
