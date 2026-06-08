"""DP-SGD harness: privacy planning + a verifiable reference trainer.

The harness expresses the plan's utility-preserving pattern (public-base /
private-delta) and makes the privacy accounting *real*: it runs a genuine DP-SGD
loop — per-example gradient clipping to L2 sensitivity ``clip_norm`` plus Gaussian
noise of scale ``noise_multiplier × clip_norm`` (Abadi et al., 2016) — and charges
the resulting (epsilon, delta) computed by :mod:`presidio_ai.dp.accountant`.

Two backends behind one ``DPTrainer`` interface:

* ``ReferenceDPSGDTrainer`` — pure-stdlib logistic-regression DP-SGD. Dependency-free
  and fully tested, so the *mechanism* (clipping, noise, sampling, accounting) is
  verifiable in CI. The default.
* Opacus (``backend="opacus"``) — production DP-SGD on real models behind the
  ``[torch]`` extra. Not shipped unverified: ``make_trainer`` raises a clear error
  until the adapter lands and can be cross-validated against this accountant in a
  torch-enabled CI lane.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from presidio_ai.dp.accountant import DPResult, dpsgd_epsilon


@dataclass(frozen=True)
class DPSGDConfig:
    """Privacy- and training-relevant DP-SGD hyperparameters."""

    noise_multiplier: float  # sigma: Gaussian noise scale as a multiple of clip_norm
    sample_rate: float  # expected lot size / dataset size (Poisson subsampling)
    steps: int
    delta: float
    private_only: bool = True  # public-base / private-delta: DP charged on the delta only
    clip_norm: float = 1.0  # per-example L2 gradient clip (the sensitivity)
    learning_rate: float = 0.1

    @classmethod
    def from_sizes(
        cls,
        *,
        noise_multiplier: float,
        batch_size: int,
        dataset_size: int,
        epochs: float,
        delta: float,
        private_only: bool = True,
        clip_norm: float = 1.0,
        learning_rate: float = 0.1,
    ) -> DPSGDConfig:
        """Build a config from batch/dataset sizes and epochs."""
        if dataset_size <= 0 or batch_size <= 0:
            raise ValueError("batch_size and dataset_size must be > 0")
        sample_rate = min(batch_size / dataset_size, 1.0)
        steps = int(round(epochs * dataset_size / batch_size))
        return cls(
            noise_multiplier, sample_rate, steps, delta, private_only, clip_norm, learning_rate
        )


def plan_privacy(config: DPSGDConfig) -> DPResult:
    """Account the (epsilon, delta) cost of a planned DP-SGD run."""
    return dpsgd_epsilon(
        noise_multiplier=config.noise_multiplier,
        sample_rate=config.sample_rate,
        steps=config.steps,
        delta=config.delta,
    )


@dataclass(frozen=True)
class TrainedModel:
    weights: list[float]
    bias: float
    result: DPResult  # the privacy guarantee this run carries
    accuracy: float  # on the training set (toy reference metric)
    n_features: int


class DPTrainer(Protocol):
    def train(
        self,
        features: Sequence[Sequence[float]],
        labels: Sequence[int],
        config: DPSGDConfig,
        *,
        seed: int = 0,
    ) -> TrainedModel: ...


# ── helpers (kept module-level for direct unit testing) ──────────────────────


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


def l2_norm(vec: Sequence[float]) -> float:
    return math.sqrt(sum(v * v for v in vec))


def clip(vec: list[float], max_norm: float) -> list[float]:
    """Scale ``vec`` down so its L2 norm is at most ``max_norm`` (DP-SGD clipping)."""
    norm = l2_norm(vec)
    if norm <= max_norm or norm == 0.0:
        return vec
    factor = max_norm / norm
    return [v * factor for v in vec]


class ReferenceDPSGDTrainer:
    """Pure-stdlib DP-SGD for L2-regularisation-free logistic regression.

    Faithful to Abadi et al.: per-example gradients are clipped to ``clip_norm``,
    summed over a Poisson-sampled lot, perturbed with Gaussian noise of std
    ``noise_multiplier × clip_norm`` per coordinate, averaged over the *expected*
    lot size, and applied as a gradient step. Deterministic for a fixed ``seed``.
    """

    def train(
        self,
        features: Sequence[Sequence[float]],
        labels: Sequence[int],
        config: DPSGDConfig,
        *,
        seed: int = 0,
    ) -> TrainedModel:
        n = len(features)
        if n == 0 or len(labels) != n:
            raise ValueError("features and labels must be non-empty and equal length")
        d = len(features[0])
        if any(len(x) != d for x in features):
            raise ValueError("all feature vectors must have the same length")

        # Seedable PRNG for reproducible reference runs. NOTE: DP's guarantee
        # assumes good randomness — a production noise source must be a CSPRNG
        # (e.g. numpy Generator / os.urandom); the Opacus backend uses torch's.
        rng = random.Random(seed)  # noqa: S311 - reference trainer; see note
        w = [0.0] * d
        b = 0.0
        sigma, C, lr, q = (
            config.noise_multiplier,
            config.clip_norm,
            config.learning_rate,
            config.sample_rate,
        )
        expected_lot = max(q * n, 1e-12)

        for _ in range(config.steps):
            grad_sum = [0.0] * (d + 1)  # last entry is the bias gradient
            for i in range(n):
                if rng.random() >= q:  # Poisson subsampling
                    continue
                xi, yi = features[i], labels[i]
                err = sigmoid(sum(w[j] * xi[j] for j in range(d)) + b) - yi
                g = [err * xi[j] for j in range(d)] + [err]
                g = clip(g, C)
                for k in range(d + 1):
                    grad_sum[k] += g[k]
            # Gaussian mechanism: noise std = sigma * sensitivity(C) per coordinate.
            for k in range(d + 1):
                grad_sum[k] += rng.gauss(0.0, sigma * C)
                grad_sum[k] /= expected_lot
            for j in range(d):
                w[j] -= lr * grad_sum[j]
            b -= lr * grad_sum[d]

        result = dpsgd_epsilon(
            noise_multiplier=sigma, sample_rate=q, steps=config.steps, delta=config.delta
        )
        correct = sum(
            int((sigmoid(sum(w[j] * x[j] for j in range(d)) + b) >= 0.5) == bool(y))
            for x, y in zip(features, labels, strict=True)
        )
        return TrainedModel(weights=w, bias=b, result=result, accuracy=correct / n, n_features=d)


def make_trainer(backend: str = "reference") -> DPTrainer:
    """Return a DP-SGD trainer. ``reference`` (stdlib) is the verifiable default."""
    if backend == "reference":
        return ReferenceDPSGDTrainer()
    if backend == "opacus":  # pragma: no cover - requires the [torch] extra
        raise NotImplementedError(
            "the Opacus DP-SGD adapter ships in a later v0.4.x behind the [torch] extra; "
            "it will implement DPTrainer and cross-validate its accounting against "
            "presidio_ai.dp.accountant. Use backend='reference' for now."
        )
    raise ValueError(f"unknown trainer backend: {backend!r}")
