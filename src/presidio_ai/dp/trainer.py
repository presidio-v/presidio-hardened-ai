"""DP-SGD harness skeleton — the public/private split and the privacy plan.

The harness expresses the utility-preserving pattern from the plan: start from a
public base and apply DP only to the sensitive fine-tune ("public-base /
private-delta"), so the (epsilon, delta) cost is charged for the private portion
only. ``plan_privacy`` computes that cost up-front (before any GPU time), which is
what the budget gate and evidence export consume.

The actual gradient work plugs in behind the ``[torch]`` extra: an Opacus-backed
``DPTrainer`` would implement ``train`` using these same accounting parameters. The
core ships only the dependency-free planning surface so the privacy guarantee is
verifiable without torch.
"""

from __future__ import annotations

from dataclasses import dataclass

from presidio_ai.dp.accountant import DPResult, dpsgd_epsilon


@dataclass(frozen=True)
class DPSGDConfig:
    """Privacy-relevant DP-SGD hyperparameters (the part that determines epsilon)."""

    noise_multiplier: float
    sample_rate: float  # expected batch size / private-set size (Poisson subsampling)
    steps: int
    delta: float
    private_only: bool = True  # public-base / private-delta: DP charged on the delta only

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
    ) -> DPSGDConfig:
        """Build a config from batch/dataset sizes and epochs."""
        if dataset_size <= 0 or batch_size <= 0:
            raise ValueError("batch_size and dataset_size must be > 0")
        sample_rate = min(batch_size / dataset_size, 1.0)
        steps = int(round(epochs * dataset_size / batch_size))
        return cls(noise_multiplier, sample_rate, steps, delta, private_only)


def plan_privacy(config: DPSGDConfig) -> DPResult:
    """Account the (epsilon, delta) cost of a planned DP-SGD run."""
    return dpsgd_epsilon(
        noise_multiplier=config.noise_multiplier,
        sample_rate=config.sample_rate,
        steps=config.steps,
        delta=config.delta,
    )
