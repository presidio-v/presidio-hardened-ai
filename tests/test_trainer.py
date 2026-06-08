from __future__ import annotations

import pytest

from presidio_ai.dp.trainer import DPSGDConfig, plan_privacy


def test_plan_privacy_matches_accountant():
    cfg = DPSGDConfig(noise_multiplier=1.1, sample_rate=0.01, steps=1000, delta=1e-5)
    result = plan_privacy(cfg)
    assert result.epsilon > 0
    assert result.steps == 1000


def test_from_sizes_derives_rate_and_steps():
    cfg = DPSGDConfig.from_sizes(
        noise_multiplier=1.0, batch_size=256, dataset_size=60000, epochs=3, delta=1e-5
    )
    assert cfg.sample_rate == pytest.approx(256 / 60000)
    assert cfg.steps == round(3 * 60000 / 256)
    assert cfg.private_only is True


def test_from_sizes_rejects_bad_sizes():
    with pytest.raises(ValueError):
        DPSGDConfig.from_sizes(
            noise_multiplier=1.0, batch_size=0, dataset_size=10, epochs=1, delta=1e-5
        )
