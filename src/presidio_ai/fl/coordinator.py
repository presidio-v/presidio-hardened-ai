"""Federated coordinator: rounds of local DP-SGD + aggregation, with per-client DP.

Privacy accounting: each silo runs ``local_config.steps`` DP-SGD steps per round for
``rounds`` rounds. Because RDP composes additively over steps, a silo's total guarantee
over the whole run is exactly ``dpsgd_epsilon(steps = rounds × local_steps)`` at its
sampling rate and noise — computed per client and returned. The coordinator only ever
sees (DP-noised) model updates, never raw silo data.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from presidio_ai.dp.accountant import DPResult, dpsgd_epsilon
from presidio_ai.dp.trainer import DPSGDConfig, ReferenceDPSGDTrainer, sigmoid
from presidio_ai.fl.aggregation import Aggregator, FedAvgAggregator


@dataclass(frozen=True)
class FederatedClient:
    client_id: str
    features: Sequence[Sequence[float]]
    labels: Sequence[int]


@dataclass(frozen=True)
class FederatedResult:
    weights: list[float]
    bias: float
    rounds: int
    per_client_epsilon: dict[str, DPResult]  # each silo's composed guarantee
    n_features: int
    pooled_accuracy: float = field(default=0.0)


def _accuracy(weights: list[float], bias: float, clients: Sequence[FederatedClient]) -> float:
    correct = total = 0
    d = len(weights)
    for client in clients:
        for x, y in zip(client.features, client.labels, strict=True):
            pred = sigmoid(sum(weights[j] * x[j] for j in range(d)) + bias) >= 0.5
            correct += int(pred == bool(y))
            total += 1
    return correct / total if total else 0.0


def federated_train(
    clients: Sequence[FederatedClient],
    *,
    rounds: int,
    local_config: DPSGDConfig,
    seed: int = 0,
    aggregator: Aggregator | None = None,
    secure_rng: bool = False,
) -> FederatedResult:
    """Run ``rounds`` of local DP-SGD + aggregation across ``clients``.

    Each round broadcasts the global model, every silo fine-tunes locally under DP
    starting from it, and the coordinator aggregates the updates (FedAvg by default).
    ``secure_rng`` draws every silo's DP noise from a CSPRNG (production); the default seeded
    PRNG is reproducible and predictable, for tests only.
    """
    if not clients:
        raise ValueError("at least one client is required")
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    aggregator = aggregator or FedAvgAggregator()
    trainer = ReferenceDPSGDTrainer()

    d = len(clients[0].features[0])
    weights = [0.0] * d
    bias = 0.0

    for r in range(rounds):
        updates = []
        for ci, client in enumerate(clients):
            model = trainer.train(
                client.features,
                client.labels,
                local_config,
                seed=seed + r * 100_003 + ci,  # distinct per round/client, deterministic
                init_weights=weights,
                init_bias=bias,
                secure_rng=secure_rng,
            )
            updates.append((model.weights, model.bias, len(client.features)))
        weights, bias = aggregator.aggregate(updates)

    per_client = {
        client.client_id: dpsgd_epsilon(
            noise_multiplier=local_config.noise_multiplier,
            sample_rate=local_config.sample_rate,
            steps=rounds * local_config.steps,
            delta=local_config.delta,
        )
        for client in clients
    }
    return FederatedResult(
        weights=weights,
        bias=bias,
        rounds=rounds,
        per_client_epsilon=per_client,
        n_features=d,
        pooled_accuracy=_accuracy(weights, bias, clients),
    )
