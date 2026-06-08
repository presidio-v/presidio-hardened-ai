"""Torch-only tests for the Opacus DP-SGD backend.

These run in the dedicated torch CI lane (``.github/workflows/ci-torch.yml``); they
skip automatically when the ``[torch]`` extra is absent, so the default lane is
unaffected. The key check cross-validates Opacus' own privacy accountant against this
suite's ``dpsgd_epsilon`` — they should agree to the same order of magnitude (ours is a
sound integer-order upper bound).
"""

from __future__ import annotations

import random

import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("opacus")

from presidio_ai.dp.accountant import dpsgd_epsilon  # noqa: E402
from presidio_ai.dp.trainer import DPSGDConfig, OpacusDPSGDTrainer, make_trainer  # noqa: E402


def _separable(n_per_class=40, seed=1):
    rng = random.Random(seed)  # noqa: S311 - test fixture data
    f, y = [], []
    for _ in range(n_per_class):
        f.append([rng.gauss(2, 0.5), rng.gauss(2, 0.5)])
        y.append(1)
        f.append([rng.gauss(-2, 0.5), rng.gauss(-2, 0.5)])
        y.append(0)
    return f, y


def _cfg(**kw):
    base = dict(
        noise_multiplier=1.0,
        sample_rate=0.2,
        steps=60,
        delta=1e-5,
        clip_norm=1.0,
        learning_rate=0.5,
    )
    base.update(kw)
    return DPSGDConfig(**base)


def test_make_trainer_returns_opacus():
    assert isinstance(make_trainer("opacus"), OpacusDPSGDTrainer)


def test_opacus_trains_separable_data():
    f, y = _separable()
    model = make_trainer("opacus").train(f, y, _cfg(), seed=0)
    assert model.n_features == 2
    assert model.result.epsilon > 0
    assert model.accuracy >= 0.8


def test_opacus_epsilon_cross_validates_accountant():
    from opacus import PrivacyEngine
    from torch import nn
    from torch.utils.data import DataLoader, TensorDataset

    f, y = _separable()
    cfg = _cfg(sample_rate=0.2, steps=100)
    n = len(f)
    x = torch.tensor(f, dtype=torch.float32)
    yt = torch.tensor([[float(v)] for v in y], dtype=torch.float32)
    model = nn.Linear(2, 1)
    opt = torch.optim.SGD(model.parameters(), lr=cfg.learning_rate)
    batch = max(1, round(cfg.sample_rate * n))
    loader = DataLoader(TensorDataset(x, yt), batch_size=batch, shuffle=True)
    engine = PrivacyEngine()
    model, opt, loader = engine.make_private(
        module=model,
        optimizer=opt,
        data_loader=loader,
        noise_multiplier=cfg.noise_multiplier,
        max_grad_norm=cfg.clip_norm,
    )
    loss_fn = nn.BCEWithLogitsLoss()
    done = 0
    while done < cfg.steps:
        for xb, yb in loader:
            opt.zero_grad()
            loss_fn(model(xb), yb).backward()
            opt.step()
            done += 1
            if done >= cfg.steps:
                break

    eps_opacus = engine.get_epsilon(cfg.delta)
    eps_ours = dpsgd_epsilon(
        noise_multiplier=cfg.noise_multiplier,
        sample_rate=cfg.sample_rate,
        steps=cfg.steps,
        delta=cfg.delta,
    ).epsilon
    assert eps_opacus > 0 and eps_ours > 0
    # Same order of magnitude; tolerant of accountant differences across opacus versions.
    assert 0.2 < (eps_opacus / eps_ours) < 5.0
