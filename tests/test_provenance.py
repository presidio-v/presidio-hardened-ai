"""ADR-0002 provenance parents on DP, consortium and ingest evidence (+ CLI --parent)."""

from __future__ import annotations

import hashlib
import json

import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.dp.accountant import DPResult
from presidio_ai.evidence import (
    build_consortium_evidence,
    build_dp_evidence,
    build_ingest_evidence,
    consortium_commitment,
    dp_evidence_content,
    ingest_evidence_content,
)
from presidio_ai.hashing import sha256_hex
from presidio_ai.ingest import SCOPE_RAW_BYTES, SCOPE_RECORDS_JSONL, ingest_records
from presidio_ai.ledger import Ledger, verify_chain
from presidio_ai.provenance import ParentError, normalize_parents, with_parents

runner = CliRunner()
KEY = "prov-key"
GATE = "a" * 64
CLASSIFICATION = "0123456789abcdef"

DP = DPResult(
    epsilon=1.6609311216485523,
    delta=1e-5,
    optimal_order=8,
    noise_multiplier=1.0,
    sample_rate=0.01,
    steps=500,
)
COMMITMENT_ARGS = dict(
    round_id="r1",
    aggregate_field=[1, 2, 3],
    max_epsilon=1.2686114429292281,
    delta=1e-5,
    n_parties=3,
    n_survivors=3,
)

# Pinned parent-less content hashes (canon 1). If one changes, every consumer that
# stored a D4 ref for a parent-less record would fail to re-derive it: do not update
# these without a schema version bump.
DP_CONTENT_HASH = "fc4b934a14b650a38e3cf1c147d247528f0284e42f388def392aabd9db660cf1"
CONSORTIUM_CONTENT_HASH = "d84a3df952dc266b4770a141af8780a239868dcad3cefd8c78e76428ce1f1c48"


# ── normalize / with_parents (ADR-0002 P2, P3) ─────────────────────────────────


def test_parents_order_preserved_and_deduplicated():
    assert normalize_parents([GATE, CLASSIFICATION, GATE]) == [GATE, CLASSIFICATION]
    assert normalize_parents(None) == [] and normalize_parents([]) == []


@pytest.mark.parametrize(
    "bad",
    ["A" * 64, "abc", "g" * 8, "a" * 129, " " + GATE, GATE + "\n", "", 123, None],
)
def test_malformed_parent_rejected(bad):
    with pytest.raises(ParentError):
        normalize_parents([GATE, bad])


def test_single_string_is_not_a_parent_list():
    with pytest.raises(ParentError):
        normalize_parents(GATE)


def test_parents_omitted_when_empty():
    assert with_parents({"a": "1"}, []) == {"a": "1"}
    assert with_parents({"a": "1"}, [GATE]) == {"a": "1", "parents": [GATE]}
    with pytest.raises(ParentError):
        with_parents({"parents": []}, [GATE])


# ── DP evidence ─────────────────────────────────────────────────────────────────


def test_dp_parentless_hash_is_unchanged():
    assert sha256_hex(DP.signed_dict()) == DP_CONTENT_HASH
    for parents in (None, []):
        assert sha256_hex(dp_evidence_content(DP, parents=parents)) == DP_CONTENT_HASH
    ref = build_dp_evidence(DP, signing_key="k", signer="s", charge_seq=0, algorithm="hmac-sha256")
    assert ref[0].content_hash == DP_CONTENT_HASH


def test_dp_parents_are_inside_the_hashed_content():
    content = dp_evidence_content(DP, parents=[GATE, CLASSIFICATION])
    assert content["parents"] == [GATE, CLASSIFICATION]
    ref = build_dp_evidence(
        DP,
        signing_key="k",
        signer="s",
        charge_seq=0,
        algorithm="hmac-sha256",
        parents=[GATE, CLASSIFICATION],
    )[0]
    assert ref.content_hash == sha256_hex(content) != DP_CONTENT_HASH
    rewired = dp_evidence_content(DP, parents=[CLASSIFICATION, GATE])
    assert sha256_hex(rewired) != ref.content_hash  # order is meaningful


def test_dp_invalid_parent_emits_nothing():
    with pytest.raises(ParentError):
        build_dp_evidence(DP, signing_key="k", signer="s", charge_seq=0, parents=["XYZ"])


# ── consortium evidence ─────────────────────────────────────────────────────────


def test_consortium_parentless_hash_is_unchanged():
    base = consortium_commitment(**COMMITMENT_ARGS)
    assert base["max_epsilon"] == "1.268611442929" and base["delta"] == "0.00001"
    assert sha256_hex(base) == CONSORTIUM_CONTENT_HASH
    assert sha256_hex(consortium_commitment(**COMMITMENT_ARGS, parents=[])) == (
        CONSORTIUM_CONTENT_HASH
    )


def test_consortium_parents_bind_the_ref():
    commitment = consortium_commitment(**COMMITMENT_ARGS, parents=[GATE])
    assert commitment["parents"] == [GATE]
    ref = build_consortium_evidence(
        commitment, signing_key="k", signer="s", round_seq=0, algorithm="hmac-sha256"
    )[0]
    assert ref.content_hash == sha256_hex(commitment) != CONSORTIUM_CONTENT_HASH


# ── ingest evidence ─────────────────────────────────────────────────────────────


def test_ingest_scopes_and_parents(tmp_path):
    raw = b'{"note": "mail alice@example.com", "w": 0.5}\n'
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    plain = ingest_records([{"note": "x"}], source_id="s", ledger=ledger)
    assert plain.source_commitment_scope == SCOPE_RECORDS_JSONL
    assert "parents" not in ingest_evidence_content(plain)

    result = ingest_records(
        [json.loads(raw)], source_id="s", ledger=ledger, raw_bytes=raw, parents=[GATE, GATE]
    )
    assert result.source_commitment == hashlib.sha256(raw).hexdigest()
    assert result.source_commitment_scope == SCOPE_RAW_BYTES
    assert result.parents == (GATE,)
    content = ingest_evidence_content(result)
    assert content["parents"] == [GATE]
    assert content["content_hash_scope"] == SCOPE_RECORDS_JSONL
    refs = build_ingest_evidence(
        result, ledger=ledger, signing_key="k", signer="s", algorithm="hmac-sha256"
    )
    assert refs[0].content_hash == sha256_hex(content)
    entry = verify_chain(ledger.path, key=KEY)[-1]
    assert entry.payload["parents"] == [GATE]
    assert entry.payload["source_commitment_scope"] == SCOPE_RAW_BYTES


def test_ingest_rejects_bad_parent_before_writing(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl", key=KEY)
    with pytest.raises(ParentError):
        ingest_records([{"a": "b"}], source_id="s", ledger=ledger, parents=["nothex!"])
    assert not ledger.path.exists()


# ── CLI --parent ────────────────────────────────────────────────────────────────


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    return tmp_path


def _evidence_hash(path):
    return json.loads(path.read_text())["evidence"][0]["content_hash"]


def test_cli_ingest_parent_and_hash_scopes(env):
    inp = env / "in.jsonl"
    inp.write_bytes(b'{"note": "mail alice@example.com"}\n{"note": "ok", "w": 1.5}\n')
    out, ev, ledger = env / "out.jsonl", env / "ev.json", env / "l.jsonl"
    r = runner.invoke(
        app,
        [
            "ingest", "--source", "src", "--input", str(inp), "--ledger", str(ledger),
            "--out", str(out), "--evidence-out", str(ev), "--algorithm", "hmac-sha256",
            "--parent", GATE, "--parent", CLASSIFICATION, "--quiet",
        ],
    )  # fmt: skip
    assert r.exit_code == 0, r.output
    summary = json.loads(r.stdout)
    assert summary["parents"] == [GATE, CLASSIFICATION]
    assert summary["source_commitment"] == hashlib.sha256(inp.read_bytes()).hexdigest()
    assert summary["content_hash"] == hashlib.sha256(out.read_bytes()).hexdigest()
    entry = verify_chain(ledger, key=KEY)[-1]
    assert entry.payload["parents"] == [GATE, CLASSIFICATION]
    content = {k: entry.payload[k] for k in entry.payload if k not in ("pii_mode", "pii_action")}
    assert _evidence_hash(ev) == sha256_hex(content)


def _dp_args(env, command, *extra):
    args = [command, "--ledger", str(env / "l.jsonl"), "--total-epsilon", "10",
            "--job-id", "job1", "--noise-multiplier", "1.0", "--sample-rate", "0.05",
            "--steps", "20", "--evidence-out", str(env / "ev.json"),
            "--algorithm", "hmac-sha256", "--quiet", *extra]  # fmt: skip
    if command == "dp-train":
        data = env / "train.jsonl"
        rows = [{"x": [i / 10, 1 - i / 10], "y": i % 2} for i in range(20)]
        data.write_text("".join(json.dumps(row) + "\n" for row in rows))
        args += ["--input", str(data)]
    return args


@pytest.mark.parametrize("command", ["dp-charge", "dp-train"])
def test_cli_dp_parent(env, command):
    r = runner.invoke(app, _dp_args(env, command, "--parent", GATE))
    assert r.exit_code == 0, r.output
    charge = [e for e in verify_chain(env / "l.jsonl", key=KEY) if e.event == "dp-budget-charge"]
    payload = charge[0].payload
    assert payload["parents"] == [GATE]
    content = {k: v for k, v in payload.items() if k != "job_id"}
    assert _evidence_hash(env / "ev.json") == sha256_hex(content)


@pytest.mark.parametrize("command", ["dp-charge", "dp-train"])
def test_cli_dp_without_parent_omits_field(env, command):
    r = runner.invoke(app, _dp_args(env, command))
    assert r.exit_code == 0, r.output
    payload = verify_chain(env / "l.jsonl", key=KEY)[-1].payload
    assert "parents" not in payload


@pytest.mark.parametrize("command", ["ingest", "dp-charge", "dp-train", "consortium-round"])
def test_cli_rejects_malformed_parent(env, command):
    if command == "ingest":
        inp = env / "in.jsonl"
        inp.write_text('{"a": "b"}\n')
        args = ["ingest", "--source", "s", "--input", str(inp), "--ledger", str(env / "l.jsonl")]
    elif command == "consortium-round":
        args = ["consortium-round", "--round-file", str(env / "r.json"),
                "--ledger", str(env / "l.jsonl")]  # fmt: skip
    else:
        args = _dp_args(env, command)
    r = runner.invoke(app, [*args, "--parent", GATE.upper()])
    assert r.exit_code == 1
    assert "--parent" in r.output
    assert not (env / "l.jsonl").exists()


def test_cli_consortium_round_parent(env):
    spec = {
        "round_id": "r1",
        "delta": 1e-5,
        "dim": 2,
        "threshold": 2,
        "updates": {"a": [0.1, 0.2], "b": [0.0, -0.1], "c": [0.2, 0.2]},
        "dp": {p: {"noise_multiplier": 1.1, "sample_rate": 0.01, "steps": 50} for p in "abc"},
    }
    (env / "r.json").write_text(json.dumps(spec))
    r = runner.invoke(
        app,
        [
            "consortium-round", "--round-file", str(env / "r.json"),
            "--ledger", str(env / "l.jsonl"), "--evidence-out", str(env / "ev.json"),
            "--algorithm", "hmac-sha256", "--parent", GATE, "--quiet",
        ],
    )  # fmt: skip
    assert r.exit_code == 0, r.output
    entry = verify_chain(env / "l.jsonl", key=KEY)[-1]
    assert entry.payload["parents"] == [GATE]
    keys = ("round_id", "aggregate_sha256", "max_epsilon", "delta", "n_parties", "n_survivors")
    content = {k: entry.payload[k] for k in keys} | {"parents": [GATE]}
    assert _evidence_hash(env / "ev.json") == sha256_hex(content)
