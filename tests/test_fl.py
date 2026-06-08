from __future__ import annotations

import json
import random

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.dp.trainer import DPSGDConfig
from presidio_ai.fl import (
    FedAvgAggregator,
    FederatedClient,
    SecureSumAggregator,
    federated_train,
)

runner = CliRunner()


def test_fedavg_weighted_mean():
    updates = [([0.0, 0.0], 0.0, 1), ([2.0, 4.0], 6.0, 3)]
    w, b = FedAvgAggregator().aggregate(updates)
    assert w == [pytest.approx(1.5), pytest.approx(3.0)]  # weighted by n=1,3
    assert b == pytest.approx(4.5)


def test_secure_sum_equals_fedavg_but_hides_individuals():
    updates = [([1.0, -2.0], 0.5, 2), ([3.0, 1.0], -1.0, 2), ([0.0, 4.0], 2.0, 1)]
    plain = FedAvgAggregator().aggregate(updates)
    secure = SecureSumAggregator(seed=3)
    assert secure.aggregate(updates) == (
        [pytest.approx(plain[0][0]), pytest.approx(plain[0][1])],
        pytest.approx(plain[1]),
    )
    # Masked contributions sum (per column) to the raw weighted sum, but individuals differ.
    masked = secure.masked_contributions(updates)
    raw = [[w[0] * n, w[1] * n, b * n] for w, b, n in updates]
    for c in range(3):
        assert sum(m[c] for m in masked) == pytest.approx(sum(r[c] for r in raw))
    assert any(masked[i] != raw[i] for i in range(len(updates)))


def test_empty_updates_raise():
    with pytest.raises(ValueError):
        FedAvgAggregator().aggregate([])


def _silo(cid, seed, n=30):
    rng = random.Random(seed)  # noqa: S311 - test fixture data, not security-relevant
    f, y = [], []
    for _ in range(n):
        f.append([rng.gauss(2, 0.5), rng.gauss(2, 0.5)])
        y.append(1)
        f.append([rng.gauss(-2, 0.5), rng.gauss(-2, 0.5)])
        y.append(0)
    return FederatedClient(cid, f, y)


def _cfg(**kw):
    base = dict(
        noise_multiplier=1.0,
        sample_rate=0.5,
        steps=30,
        delta=1e-5,
        clip_norm=1.0,
        learning_rate=0.5,
    )
    base.update(kw)
    return DPSGDConfig(**base)


def test_federated_train_learns_and_accounts():
    clients = [_silo("eu", 1), _silo("us", 2)]
    res = federated_train(clients, rounds=10, local_config=_cfg(), seed=0)
    assert res.pooled_accuracy >= 0.9
    # Per-client guarantee composes over rounds x local_steps.
    expected = dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.5, steps=10 * 30, delta=1e-5)
    for cid in ("eu", "us"):
        assert res.per_client_epsilon[cid].steps == 300
        assert res.per_client_epsilon[cid].epsilon == pytest.approx(expected.epsilon)


def test_federated_train_deterministic():
    clients = [_silo("eu", 1), _silo("us", 2)]
    a = federated_train(clients, rounds=5, local_config=_cfg(), seed=0)
    b = federated_train(clients, rounds=5, local_config=_cfg(), seed=0)
    assert a.weights == b.weights and a.bias == b.bias


def test_secure_agg_matches_fedavg_end_to_end():
    clients = [_silo("eu", 1), _silo("us", 2)]
    fedavg = federated_train(clients, rounds=5, local_config=_cfg(), seed=0)
    secure = federated_train(
        clients, rounds=5, local_config=_cfg(), seed=0, aggregator=SecureSumAggregator(seed=9)
    )
    assert secure.weights == pytest.approx(fedavg.weights)
    assert secure.bias == pytest.approx(fedavg.bias)


@pytest.mark.parametrize("rounds", [0, -1])
def test_invalid_rounds_raise(rounds):
    with pytest.raises(ValueError):
        federated_train([_silo("eu", 1)], rounds=rounds, local_config=_cfg())


def test_no_clients_raises():
    with pytest.raises(ValueError):
        federated_train([], rounds=3, local_config=_cfg())


# ── CLI ──────────────────────────────────────────────────────────────────────


def _write_silo(tmp_path, name, seed):
    client = _silo(name, seed, n=15)
    p = tmp_path / f"{name}.jsonl"
    p.write_text(
        "\n".join(
            json.dumps({"x": x, "y": y})
            for x, y in zip(client.features, client.labels, strict=True)
        )
    )
    return str(p)


def test_cli_fl_train(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    eu = _write_silo(tmp_path, "eu", 1)
    us = _write_silo(tmp_path, "us", 2)
    r = runner.invoke(
        app,
        [
            "fl-train",
            "--silo",
            eu,
            "--silo",
            us,
            "--rounds",
            "8",
            "--local-steps",
            "30",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--lr",
            "0.5",
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    summary = json.loads(r.stdout)
    assert summary["n_silos"] == 2
    assert summary["pooled_accuracy"] >= 0.8
    assert set(summary["per_client"]) == {"eu", "us"}
    assert summary["per_client"]["eu"]["steps"] == 240


def test_cli_fl_train_secure_agg(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    eu = _write_silo(tmp_path, "eu", 1)
    r = runner.invoke(
        app,
        [
            "fl-train",
            "--silo",
            eu,
            "--rounds",
            "5",
            "--local-steps",
            "20",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--secure-agg",
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    assert json.loads(r.stdout)["secure_agg"] is True


def test_cli_fl_train_malformed_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"x": [1.0, 2.0]}) + "\n")  # missing y
    r = runner.invoke(
        app,
        [
            "fl-train",
            "--silo",
            str(bad),
            "--rounds",
            "3",
            "--local-steps",
            "10",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
        ],
    )
    assert r.exit_code == 1
