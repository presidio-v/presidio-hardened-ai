"""The CLI's DP noise is drawn from a CSPRNG unless a test seed is given explicitly."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.dp.trainer import ReferenceDPSGDTrainer

runner = CliRunner()
KEY = "cli-noise-key"


@pytest.fixture
def calls(monkeypatch, tmp_path):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    seen: list[bool] = []
    real = ReferenceDPSGDTrainer.train

    def spy(self, *args, **kwargs):
        seen.append(kwargs.get("secure_rng", False))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(ReferenceDPSGDTrainer, "train", spy)
    return seen


def _data(tmp_path, name="train.jsonl"):
    path = tmp_path / name
    rows = [{"x": [i / 10, 1 - i / 10], "y": i % 2} for i in range(20)]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return str(path)


def _dp_train(tmp_path, *extra):
    return runner.invoke(
        app,
        ["dp-train", "--input", _data(tmp_path), "--ledger", str(tmp_path / "l.jsonl"),
         "--total-epsilon", "10", "--job-id", "j", "--noise-multiplier", "1.0",
         "--sample-rate", "0.05", "--steps", "5", "--quiet", *extra],
    )  # fmt: skip


def _fl_train(tmp_path, *extra):
    return runner.invoke(
        app,
        ["fl-train", "--silo", _data(tmp_path, "a.jsonl"), "--silo", _data(tmp_path, "b.jsonl"),
         "--rounds", "2", "--local-steps", "3", "--noise-multiplier", "1.0",
         "--sample-rate", "0.5", "--quiet", *extra],
    )  # fmt: skip


@pytest.mark.parametrize("run", [_dp_train, _fl_train], ids=["dp-train", "fl-train"])
def test_default_noise_is_csprng(tmp_path, calls, run):
    r = run(tmp_path)
    assert r.exit_code == 0, r.output
    assert calls and all(calls)
    assert "predictable" not in r.output


@pytest.mark.parametrize("run", [_dp_train, _fl_train], ids=["dp-train", "fl-train"])
def test_explicit_seed_is_reproducible_and_warned(tmp_path, calls, run):
    r = run(tmp_path, "--seed", "7")
    assert r.exit_code == 0, r.output
    assert calls and not any(calls)
    assert "predictable" in r.output


def test_fl_train_secure_agg_without_seed_runs(tmp_path, calls):
    r = _fl_train(tmp_path, "--secure-agg")
    assert r.exit_code == 0, r.output
    assert all(calls)
