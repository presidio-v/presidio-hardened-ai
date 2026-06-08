"""Tests for Ed25519 public-key evidence signing (v0.7.0, [crypto] extra)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.dp.accountant import dpsgd_epsilon
from presidio_ai.evidence import (
    build_ingest_evidence,
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
    verify_evidence,
)
from presidio_ai.ingest import ingest_records
from presidio_ai.ledger import Ledger

pytest.importorskip("cryptography")
runner = CliRunner()

# Golden vector: a fixed private key gives a deterministic Ed25519 signature (RFC 8032).
# Locks the wire format for the ikigov consumer's public-key verifier.
GOLD_PRIV = "01" * 32
GOLD_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
GOLD_CH = "abc123def456"
GOLD_SIGNER = "presidio-hardened-ai"
GOLD_SIG = (
    "a0dc8599958734457f194ebce15c60ec097754b59897ab5dc758f73abadafe36"
    "97874049d9f7736de4e3a9cc28b2fb4d76b15d8bce7fa0b26c8434bebbba590a"
)


def test_keypair_shapes():
    priv, pub = generate_ed25519_keypair()
    assert len(priv) == 64 and len(pub) == 64  # 32 bytes each, hex
    assert priv != pub


def test_golden_signature_is_deterministic():
    assert sign_ed25519(GOLD_CH, GOLD_SIGNER, GOLD_PRIV) == GOLD_SIG
    assert verify_ed25519(GOLD_CH, GOLD_SIGNER, GOLD_SIG, GOLD_PUB) is True


def test_verify_failures_are_fail_closed():
    sig = sign_ed25519(GOLD_CH, GOLD_SIGNER, GOLD_PRIV)
    assert verify_ed25519(GOLD_CH, GOLD_SIGNER, sig, "00" * 32) is False  # wrong pubkey
    assert verify_ed25519("tampered", GOLD_SIGNER, sig, GOLD_PUB) is False  # wrong content
    assert verify_ed25519(GOLD_CH, "mallory", sig, GOLD_PUB) is False  # wrong signer binding
    assert verify_ed25519(GOLD_CH, GOLD_SIGNER, "zz", GOLD_PUB) is False  # malformed sig


def test_roundtrip_random_key():
    priv, pub = generate_ed25519_keypair()
    sig = sign_ed25519(GOLD_CH, "s", priv)
    assert verify_ed25519(GOLD_CH, "s", sig, pub)


def test_build_evidence_ed25519(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", key="k")
    result = ingest_records([{"note": "a@b.com"}], source_id="s", ledger=ledger)
    priv, pub = generate_ed25519_keypair()
    refs = build_ingest_evidence(
        result, ledger=ledger, signing_key=priv, signer="prod", algorithm="ed25519"
    )
    for ref in refs:
        # Verifies under the Ed25519 public key...
        assert verify_ed25519(ref.content_hash, ref.signer, ref.signature, pub)
        # ...and NOT under HMAC with the private hex (different algorithm).
        assert verify_evidence(ref, priv) is False


def test_ed25519_requires_str_key(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", key="k")
    result = ingest_records([{"note": "x"}], source_id="s", ledger=ledger)
    with pytest.raises(ValueError):
        build_ingest_evidence(
            result, ledger=ledger, signing_key=b"bytes", signer="p", algorithm="ed25519"
        )


def test_unknown_algorithm_raises(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", key="k")
    result = ingest_records([{"note": "x"}], source_id="s", ledger=ledger)
    with pytest.raises(ValueError):
        build_ingest_evidence(result, ledger=ledger, signing_key="k", signer="p", algorithm="rsa")


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_keygen():
    r = runner.invoke(app, ["keygen", "--quiet"])
    assert r.exit_code == 0, r.stdout
    out = json.loads(r.stdout)
    assert len(out["private_key"]) == 64 and len(out["public_key"]) == 64


def test_cli_ingest_ed25519_signs_verifiably(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", "ledger-key")
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    priv, pub = generate_ed25519_keypair()
    inp = tmp_path / "in.jsonl"
    inp.write_text(json.dumps({"note": "mail a@b.com"}) + "\n")
    evidence = tmp_path / "evidence.json"
    r = runner.invoke(
        app,
        [
            "ingest",
            "--source",
            "crm",
            "--input",
            str(inp),
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--evidence-out",
            str(evidence),
            "--algorithm",
            "ed25519",
            "--signing-key",
            priv,
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    doc = json.loads(evidence.read_text())
    for ref in doc["evidence"]:
        assert verify_ed25519(ref["content_hash"], ref["signer"], ref["signature"], pub)


def test_cli_ingest_ed25519_without_key_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", "ledger-key")
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    inp = tmp_path / "in.jsonl"
    inp.write_text(json.dumps({"note": "x"}) + "\n")
    r = runner.invoke(
        app,
        [
            "ingest",
            "--source",
            "crm",
            "--input",
            str(inp),
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--evidence-out",
            str(tmp_path / "e.json"),
            "--algorithm",
            "ed25519",
            "--quiet",
        ],
    )
    assert r.exit_code == 1


def test_cli_dp_train_ed25519(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", "ledger-key")
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    priv, pub = generate_ed25519_keypair()
    data = tmp_path / "data.jsonl"
    rows = [{"x": [2.0, 2.0], "y": 1}, {"x": [-2.0, -2.0], "y": 0}] * 10
    data.write_text("\n".join(json.dumps(r) for r in rows))
    evidence = tmp_path / "dp.json"
    r = runner.invoke(
        app,
        [
            "dp-train",
            "--input",
            str(data),
            "--ledger",
            str(tmp_path / "l.jsonl"),
            "--total-epsilon",
            "1000",
            "--job-id",
            "ft",
            "--noise-multiplier",
            "1.0",
            "--sample-rate",
            "0.5",
            "--steps",
            "20",
            "--evidence-out",
            str(evidence),
            "--algorithm",
            "ed25519",
            "--signing-key",
            priv,
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    ref = json.loads(evidence.read_text())["evidence"][0]
    assert verify_ed25519(ref["content_hash"], ref["signer"], ref["signature"], pub)
    # sanity: the accountant still drives the charged epsilon
    assert dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.5, steps=20, delta=1e-5).epsilon > 0
