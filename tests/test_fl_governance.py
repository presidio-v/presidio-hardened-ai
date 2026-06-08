from __future__ import annotations

import json
import random

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.dp.budget import CHARGE_EVENT, BudgetExceeded
from presidio_ai.dp.trainer import DPSGDConfig
from presidio_ai.evidence import generate_ed25519_keypair, verify_ed25519
from presidio_ai.fl import FederatedClient, charge_federated, federated_train
from presidio_ai.ledger import Ledger, verify_chain

runner = CliRunner()


def _silo(cid, seed):
    rng = random.Random(seed)  # noqa: S311 - test fixture
    f, y = [], []
    for _ in range(20):
        f.append([rng.gauss(2, 0.5), rng.gauss(2, 0.5)])
        y.append(1)
        f.append([rng.gauss(-2, 0.5), rng.gauss(-2, 0.5)])
        y.append(0)
    return FederatedClient(cid, f, y)


def _result():
    cfg = DPSGDConfig(
        noise_multiplier=1.0,
        sample_rate=0.5,
        steps=20,
        delta=1e-5,
        clip_norm=1.0,
        learning_rate=0.5,
    )
    return federated_train([_silo("eu", 1), _silo("us", 2)], rounds=5, local_config=cfg, seed=0)


def test_charge_federated_per_silo_ledgers(tmp_path):
    gov = charge_federated(_result(), total_epsilon=1000, ledger_dir=tmp_path / "L", key="k")
    assert set(gov) == {"eu", "us"}
    for cid, g in gov.items():
        # Each silo has its own ledger with exactly one charge entry, chain intact.
        entries = verify_chain(tmp_path / "L" / f"{cid}.jsonl", key="k")
        assert [e.event for e in entries] == [CHARGE_EVENT]
        assert g.charge.remaining_epsilon < 1000
        assert g.evidence_path is None  # no evidence_dir


def test_charge_federated_ed25519_evidence(tmp_path):
    priv, pub = generate_ed25519_keypair()
    gov = charge_federated(
        _result(),
        total_epsilon=1000,
        ledger_dir=tmp_path / "L",
        key="k",
        evidence_dir=tmp_path / "E",
        signing_key=priv,
    )
    for g in gov.values():
        ref = json.loads(g.evidence_path.read_text())["evidence"][0]
        assert ref["item_id"] == "D4"
        assert verify_ed25519(ref["content_hash"], ref["signer"], ref["signature"], pub)


def test_charge_federated_over_budget_raises(tmp_path):
    with pytest.raises(BudgetExceeded):
        charge_federated(_result(), total_epsilon=0.0001, ledger_dir=tmp_path / "L", key="k")


def test_per_silo_budgets_independent(tmp_path):
    charge_federated(_result(), total_epsilon=1000, ledger_dir=tmp_path / "L", key="k")
    # Each silo's ledger holds only its own charge.
    eu = [e.payload["job_id"] for e in Ledger(tmp_path / "L" / "eu.jsonl", key="k").entries()]
    assert eu == ["fl/eu"]


# ── CLI ──────────────────────────────────────────────────────────────────────


def _write_silo(tmp_path, name, seed):
    c = _silo(name, seed)
    p = tmp_path / f"{name}.jsonl"
    p.write_text(
        "\n".join(json.dumps({"x": x, "y": y}) for x, y in zip(c.features, c.labels, strict=True))
    )
    return str(p)


def test_cli_fl_train_charge(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", "lk")
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    priv, pub = generate_ed25519_keypair()
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
            "5",
            "--local-steps",
            "20",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--lr",
            "0.5",
            "--charge",
            "--total-epsilon",
            "1000",
            "--ledger-dir",
            str(tmp_path / "L"),
            "--evidence-dir",
            str(tmp_path / "E"),
            "--signing-key",
            priv,
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    summary = json.loads(r.stdout)
    assert summary["charged"] is True
    for cid in ("eu", "us"):
        pc = summary["per_client"][cid]
        assert "remaining_epsilon" in pc and pc["evidence"]
        ref = json.loads((tmp_path / "E" / f"{cid}.evidence.json").read_text())["evidence"][0]
        assert verify_ed25519(ref["content_hash"], ref["signer"], ref["signature"], pub)


def test_cli_fl_train_charge_missing_args_exit_1(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", "lk")
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    eu = _write_silo(tmp_path, "eu", 1)
    r = runner.invoke(
        app,
        [
            "fl-train",
            "--silo",
            eu,
            "--rounds",
            "3",
            "--local-steps",
            "10",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--charge",
        ],  # no --total-epsilon/--ledger-dir
    )
    assert r.exit_code == 1
