"""Federated learning (P3 / v0.5.0): train across silos without centralising data.

Each silo trains locally with the DP-SGD reference trainer starting from the broadcast
global model; a coordinator combines the updates by FedAvg. Raw data never leaves the
silo — the coordinator sees only model updates — and per-client differential privacy
composes across rounds. A ``SecureSumAggregator`` demonstrates secure aggregation: the
server recovers only the *combined* update, not any individual silo's.
"""

from __future__ import annotations

from presidio_ai.fl.aggregation import Aggregator, FedAvgAggregator, SecureSumAggregator
from presidio_ai.fl.coordinator import (
    FederatedClient,
    FederatedResult,
    federated_train,
)

__all__ = [
    "Aggregator",
    "FedAvgAggregator",
    "SecureSumAggregator",
    "FederatedClient",
    "FederatedResult",
    "federated_train",
]
