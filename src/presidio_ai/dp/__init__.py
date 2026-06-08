"""Differential-privacy accounting and budget governance (P2 / v0.2.0).

The privacy *guarantee* of DP-SGD is its (epsilon, delta) bound; this subpackage
computes it (``accountant``), spends it against a tamper-evident org budget
(``budget``), and turns it into a planning surface (``trainer``). The numerics are
pure-stdlib and rigorously tested; the actual gradient work (Opacus/torch) is an
optional adapter behind the ``[torch]`` extra so the governance core carries no
heavy dependency and is fully verifiable.
"""

from __future__ import annotations

from presidio_ai.dp.accountant import (
    DEFAULT_ORDERS,
    DPResult,
    dpsgd_epsilon,
    rdp_gaussian,
    rdp_subsampled_gaussian,
    rdp_to_epsilon,
)
from presidio_ai.dp.authorization import (
    MPADenied,
    MPAPolicy,
    build_request,
    request_hash,
    sign_approval,
)
from presidio_ai.dp.budget import BudgetExceeded, EpsilonBudget
from presidio_ai.dp.trainer import (
    DPSGDConfig,
    DPTrainer,
    ReferenceDPSGDTrainer,
    TrainedModel,
    make_trainer,
    plan_privacy,
)

__all__ = [
    "DEFAULT_ORDERS",
    "DPResult",
    "dpsgd_epsilon",
    "rdp_gaussian",
    "rdp_subsampled_gaussian",
    "rdp_to_epsilon",
    "EpsilonBudget",
    "BudgetExceeded",
    "MPAPolicy",
    "MPADenied",
    "build_request",
    "request_hash",
    "sign_approval",
    "DPSGDConfig",
    "DPTrainer",
    "ReferenceDPSGDTrainer",
    "TrainedModel",
    "make_trainer",
    "plan_privacy",
]
