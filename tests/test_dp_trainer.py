from __future__ import annotations

import importlib.util
import json
import random

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.dp.trainer import (
    DPSGDConfig,
    ReferenceDPSGDTrainer,
    clip,
    l2_norm,
    make_trainer,
    sigmoid,
)

runner = CliRunner()
KEY = "train-key"


def _separable(n_per_class=40, seed=1):
    rng = random.Random(seed)  # noqa: S311 - test fixture data, not security-relevant
    features, labels = [], []
    for _ in range(n_per_class):
        features.append([rng.gauss(2, 0.5), rng.gauss(2, 0.5)])
        labels.append(1)
        features.append([rng.gauss(-2, 0.5), rng.gauss(-2, 0.5)])
        labels.append(0)
    return features, labels


def test_sigmoid_bounds():
    assert 0.0 <= sigmoid(-50) < sigmoid(0) < sigmoid(50) <= 1.0
    assert sigmoid(0) == pytest.approx(0.5)


def test_clip_reduces_norm():
    assert l2_norm(clip([3.0, 4.0], 1.0)) == pytest.approx(1.0)  # 3-4-5 -> unit
    assert clip([0.1, 0.1], 1.0) == [0.1, 0.1]  # under the cap, untouched
    assert clip([0.0, 0.0], 1.0) == [0.0, 0.0]  # zero vector safe


def _cfg(**kw):
    base = dict(
        noise_multiplier=1.0,
        sample_rate=0.5,
        steps=200,
        delta=1e-5,
        clip_norm=1.0,
        learning_rate=0.5,
    )
    base.update(kw)
    return DPSGDConfig(**base)


def test_trains_separable_data():
    f, y = _separable()
    model = ReferenceDPSGDTrainer().train(f, y, _cfg(), seed=0)
    assert model.accuracy >= 0.9  # learns the boundary despite DP noise
    assert model.n_features == 2


def test_deterministic_for_seed():
    f, y = _separable()
    a = ReferenceDPSGDTrainer().train(f, y, _cfg(), seed=7)
    b = ReferenceDPSGDTrainer().train(f, y, _cfg(), seed=7)
    assert a.weights == b.weights and a.bias == b.bias


def test_accounting_matches_config():
    f, y = _separable()
    cfg = _cfg(sample_rate=0.05, steps=300)
    model = ReferenceDPSGDTrainer().train(f, y, cfg, seed=0)
    expected = dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.05, steps=300, delta=1e-5)
    assert model.result.epsilon == pytest.approx(expected.epsilon)


@pytest.mark.parametrize(
    "f,y",
    [([], []), ([[1.0]], [0, 1]), ([[1.0, 2.0], [3.0]], [0, 1])],
)
def test_invalid_data_raises(f, y):
    with pytest.raises(ValueError):
        ReferenceDPSGDTrainer().train(f, y, _cfg(), seed=0)


def test_make_trainer():
    assert isinstance(make_trainer("reference"), ReferenceDPSGDTrainer)
    with pytest.raises(ValueError):
        make_trainer("nope")
    if importlib.util.find_spec("torch") is not None:  # pragma: no cover
        from presidio_ai.dp.trainer import OpacusDPSGDTrainer

        assert isinstance(make_trainer("opacus"), OpacusDPSGDTrainer)
    else:
        with pytest.raises(ImportError):
            make_trainer("opacus")


def test_secure_rng_runs_and_is_nondeterministic():
    f, y = _separable()
    a = ReferenceDPSGDTrainer().train(f, y, _cfg(), secure_rng=True)
    b = ReferenceDPSGDTrainer().train(f, y, _cfg(), secure_rng=True)
    assert 0.0 <= a.accuracy <= 1.0
    assert a.weights != b.weights  # CSPRNG noise -> not reproducible


# ── CLI ──────────────────────────────────────────────────────────────────────


def _write_data(tmp_path):
    f, y = _separable(n_per_class=20)
    p = tmp_path / "data.jsonl"
    p.write_text("\n".join(json.dumps({"x": xi, "y": yi}) for xi, yi in zip(f, y, strict=True)))
    return p


def test_cli_dp_train_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    data = _write_data(tmp_path)
    ledger = tmp_path / "ledger.jsonl"
    evidence = tmp_path / "dp-evidence.json"
    r = runner.invoke(
        app,
        [
            "dp-train",
            "--input",
            str(data),
            "--ledger",
            str(ledger),
            "--total-epsilon",
            "1000",
            "--job-id",
            "ft",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--steps",
            "100",
            "--lr",
            "0.5",
            "--evidence-out",
            str(evidence),
            "--algorithm",
            "hmac-sha256",
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    summary = json.loads(r.stdout)
    assert summary["accuracy"] >= 0.8
    assert summary["epsilon"] > 0
    assert summary["evidence"][0]["item_id"] == "D4"
    assert json.loads(evidence.read_text())["evidence"][0]["item_id"] == "D4"


def test_cli_dp_train_over_budget_exits_2(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    data = _write_data(tmp_path)
    r = runner.invoke(
        app,
        [
            "dp-train",
            "--input",
            str(data),
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--total-epsilon",
            "0.0001",
            "--job-id",
            "ft",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--steps",
            "100",
        ],
    )
    assert r.exit_code == 2


def test_cli_dp_train_malformed_input_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"x": [1.0, 2.0]}) + "\n")  # missing y
    r = runner.invoke(
        app,
        [
            "dp-train",
            "--input",
            str(bad),
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--total-epsilon",
            "10",
            "--job-id",
            "ft",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--steps",
            "10",
        ],
    )
    assert r.exit_code == 1
