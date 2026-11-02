"""Verified gate-certificate parents on dp-train, dp-charge and consortium-round (#77).

Certificates are issued here by ikigov-assess itself (``build_certificate`` + ``sign``,
the ``[gate]`` extra) with the family Ed25519 test key, so the verifier under test is
the real one. Coverage:

- identity: presidio-evidence's ``gate-certificate/valid-certificate.json`` vector
  hashes to its pinned identity (ADR-0006) and equals sha256 over ikigov's own
  ``signing_bytes``; the signature is excluded; non-certificates fail closed;
- accept: a valid OPEN certificate's identity is appended to ``parents`` after the
  bare ``--parent`` values, once, in the ledger entry and in the evidence content;
- refuse, nothing charged: tampered, expired, untrusted issuer, wrong key, a decision
  other than OPEN, ``--gate-certificate`` without ``--gate-trust`` and the reverse,
  unreadable / oversized / non-JSON / non-UTF-8 files, the extra not installed.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import presidio_evidence
import pytest
from typer.testing import CliRunner

from presidio_ai.cli import app
from presidio_ai.gate_certificate import (
    MAX_FILE_BYTES,
    GateCertificateError,
    certificate_identity,
    verify_gate_certificates,
)
from presidio_ai.hashing import sha256_hex
from presidio_ai.ledger import verify_chain

pytest.importorskip("cryptography")
ikigov_cert = pytest.importorskip("presidio_ikigov_assess.certificate")

runner = CliRunner()

VECTORS = Path(presidio_evidence.vectors_dir()) / "gate-certificate"
VECTOR = json.loads((VECTORS / "valid-certificate.json").read_text(encoding="utf-8"))
NOTES = json.loads((VECTORS / "valid-certificate.notes.json").read_text(encoding="utf-8"))
VECTOR_IDENTITY = "dbb7c6a36f0aea55bbe5dead3daf8f4f3d59116966e79bd4b78ecfe2a83ebd4a"

KEY = "gate-key"
ISSUER = "presidio-hardened-ikigov-assess"
SEED = "01" * 32  # family test key (private seed)
PUBLIC_KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
OTHER_SEED = "02" * 32
G0_ITEMS = frozenset({"S1", "S2", "S3"})
BARE = "a" * 64


def _utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _issue(
    *,
    affirmed: frozenset[str] = G0_ITEMS,
    assessed_at: datetime | None = None,
    valid_days: int = 30,
    seed: str = SEED,
) -> dict:
    issued = assessed_at or datetime.now(UTC) - timedelta(days=1)
    doc = ikigov_cert.build_certificate(
        use_case="training-gate",
        gate="G0",
        risk_class="medium",
        affirmed=affirmed,
        skipped=G0_ITEMS - affirmed,
        issuer=ISSUER,
        assessed_at=_utc(issued),
        not_after=_utc(issued + timedelta(days=valid_days)),
    )
    return ikigov_cert.sign(doc, alg="ed25519", key_hex_or_secret=seed, signer=ISSUER)


def _write(directory: Path, name: str, payload: object) -> Path:
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_AI_LEDGER_KEY", KEY)
    monkeypatch.setenv("PRESIDIO_AI_HOME", str(tmp_path / "home"))
    return tmp_path


@pytest.fixture
def trust(tmp_path: Path) -> Path:
    return _write(tmp_path, "trust.json", {ISSUER: {"alg": "ed25519", "public_key": PUBLIC_KEY}})


def _dp_args(env: Path, command: str, *extra: str) -> list[str]:
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


def _round_args(env: Path, *extra: str) -> list[str]:
    spec = {
        "round_id": "r1",
        "delta": 1e-5,
        "dim": 2,
        "threshold": 2,
        "updates": {"a": [0.1, 0.2], "b": [0.0, -0.1], "c": [0.2, 0.2]},
        "dp": {p: {"noise_multiplier": 1.1, "sample_rate": 0.01, "steps": 50} for p in "abc"},
    }
    (env / "r.json").write_text(json.dumps(spec))
    return ["consortium-round", "--round-file", str(env / "r.json"),
            "--ledger", str(env / "l.jsonl"), "--evidence-out", str(env / "ev.json"),
            "--algorithm", "hmac-sha256", "--quiet", *extra]  # fmt: skip


def _args(env: Path, command: str, *extra: str) -> list[str]:
    if command == "consortium-round":
        return _round_args(env, *extra)
    return _dp_args(env, command, *extra)


def _evidence_hash(path: Path) -> str:
    return json.loads(path.read_text())["evidence"][0]["content_hash"]


COMMANDS = ["dp-train", "dp-charge", "consortium-round"]

# ── identity (ADR-0006) ──────────────────────────────────────────────────────


def test_vector_identity_is_pinned():
    assert NOTES["identity"] == VECTOR_IDENTITY
    assert certificate_identity(VECTOR) == VECTOR_IDENTITY


def test_identity_matches_ikigov_signing_bytes():
    assert (
        certificate_identity(VECTOR)
        == hashlib.sha256(ikigov_cert.signing_bytes(VECTOR)).hexdigest()
    )
    fresh = _issue()
    expected = hashlib.sha256(ikigov_cert.signing_bytes(fresh)).hexdigest()
    assert certificate_identity(fresh) == expected


def test_identity_ignores_signature():
    cert = copy.deepcopy(VECTOR)
    cert["signature"] = {"alg": "hmac-sha256", "signer": "x", "sig": "00"}
    assert certificate_identity(cert) == VECTOR_IDENTITY
    del cert["signature"]
    assert certificate_identity(cert) == VECTOR_IDENTITY


@pytest.mark.parametrize(
    "bad",
    [None, [], "x", {"schema": "presidio-hardened/training-run@1"}, {"no": "schema"}],
)
def test_identity_fails_closed(bad):
    with pytest.raises(GateCertificateError):
        certificate_identity(bad)


def test_identity_rejects_floats():
    with pytest.raises(GateCertificateError):
        certificate_identity(dict(VECTOR, extra=0.5))


def test_vector_verifies_at_its_instant(tmp_path):
    cert = _write(tmp_path, "cert.json", VECTOR)
    trust = _write(tmp_path, "trust.json", NOTES["trust_store"])
    at = datetime(2026, 7, 3, tzinfo=UTC)
    assert verify_gate_certificates([cert], trust, now=at) == [VECTOR_IDENTITY]
    with pytest.raises(GateCertificateError, match="expired"):
        verify_gate_certificates([cert], trust, now=datetime(2028, 1, 1, tzinfo=UTC))


def test_no_certificates_need_no_trust_store(tmp_path):
    assert verify_gate_certificates([], tmp_path / "missing.json") == []


# ── accept ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("command", COMMANDS)
def test_open_certificate_becomes_a_parent(env, trust, command):
    cert = _write(env, "cert.json", _issue())
    identity = certificate_identity(json.loads(cert.read_text()))
    r = runner.invoke(
        app,
        _args(
            env,
            command,
            "--parent",
            BARE,
            "--gate-certificate",
            str(cert),
            "--gate-certificate",
            str(cert),
            "--gate-trust",
            str(trust),
        ),  # fmt: skip
    )
    assert r.exit_code == 0, r.output
    entries = verify_chain(env / "l.jsonl", key=KEY)
    event = "consortium-round" if command == "consortium-round" else "dp-budget-charge"
    payload = [e for e in entries if e.event == event][0].payload
    assert payload["parents"] == [BARE, identity]  # bare first, the identity once
    if command == "consortium-round":
        keys = ("round_id", "aggregate_sha256", "max_epsilon", "delta", "n_parties", "n_survivors")
        content = {k: payload[k] for k in keys} | {"parents": [BARE, identity]}
    else:
        content = {k: v for k, v in payload.items() if k != "job_id"}
    assert _evidence_hash(env / "ev.json") == sha256_hex(content)


@pytest.mark.parametrize("command", ["dp-charge", "dp-train"])
def test_without_option_the_run_is_unchanged(env, command):
    r = runner.invoke(app, _dp_args(env, command, "--parent", BARE))
    assert r.exit_code == 0, r.output
    charge = [e for e in verify_chain(env / "l.jsonl", key=KEY) if e.event == "dp-budget-charge"]
    assert charge[0].payload["parents"] == [BARE]


# ── refuse: nothing charged ──────────────────────────────────────────────────


def _refused(env: Path, command: str, *extra: str, match: str) -> None:
    r = runner.invoke(app, _args(env, command, *extra))
    assert r.exit_code == 1, r.output
    assert match in r.output
    assert not (env / "l.jsonl").exists()
    assert not (env / "ev.json").exists()


def _tampered() -> dict:
    cert = _issue()
    cert["use_case"] = "something-else"
    return cert


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize(
    ("make", "match"),
    [
        (_tampered, "does not verify"),
        (lambda: _issue(assessed_at=datetime.now(UTC) - timedelta(days=40)), "expired"),
        (lambda: _issue(seed=OTHER_SEED), "does not verify"),
        (lambda: _issue(affirmed=frozenset({"S1"})), "not OPEN"),
    ],
    ids=["tampered", "expired", "wrong-key", "not-open"],
)
def test_bad_certificate_is_refused(env, trust, command, make, match):
    cert = _write(env, "cert.json", make())
    _refused(env, command, "--gate-certificate", str(cert), "--gate-trust", str(trust),
             match=match)  # fmt: skip


def test_untrusted_issuer_is_refused(env):
    cert = _write(env, "cert.json", _issue())
    entry = {"alg": "ed25519", "public_key": PUBLIC_KEY}
    other = _write(env, "trust.json", {"someone-else": entry})
    _refused(env, "dp-charge", "--gate-certificate", str(cert), "--gate-trust", str(other),
             match="does not verify")  # fmt: skip


@pytest.mark.parametrize("command", COMMANDS)
def test_certificate_without_trust_is_refused(env, command):
    cert = _write(env, "cert.json", _issue())
    _refused(env, command, "--gate-certificate", str(cert), match="requires --gate-trust")


@pytest.mark.parametrize("command", COMMANDS)
def test_trust_without_certificate_is_refused(env, trust, command):
    _refused(env, command, "--gate-trust", str(trust), match="without --gate-certificate")


@pytest.mark.parametrize(
    ("content", "match"),
    [
        (b"{not json", "not valid JSON"),
        (b'{"a": NaN}', "not valid JSON"),
        (b"\xff\xfe", "not UTF-8"),
        (b" " * (MAX_FILE_BYTES + 1), "exceeds"),
    ],
    ids=["not-json", "nan", "not-utf8", "oversized"],
)
def test_unreadable_certificate_file_is_refused(env, trust, content, match):
    cert = env / "cert.json"
    cert.write_bytes(content)
    _refused(env, "dp-charge", "--gate-certificate", str(cert), "--gate-trust", str(trust),
             match=match)  # fmt: skip


def test_missing_and_directory_paths_are_refused(env, trust):
    _refused(env, "dp-charge", "--gate-certificate", str(env / "nope.json"),
             "--gate-trust", str(trust), match="cannot read")  # fmt: skip
    _refused(env, "dp-charge", "--gate-certificate", str(env),
             "--gate-trust", str(trust), match="not a regular file")  # fmt: skip


def test_malformed_trust_store_is_refused(env):
    cert = _write(env, "cert.json", _issue())
    bad = env / "trust.json"
    bad.write_text("[]", encoding="utf-8")
    _refused(env, "dp-charge", "--gate-certificate", str(cert), "--gate-trust", str(bad),
             match="gate trust store")  # fmt: skip


def test_missing_extra_is_refused(env, trust):
    cert = _write(env, "cert.json", _issue())
    with patch.dict("sys.modules", {"presidio_ikigov_assess": None}):
        _refused(env, "dp-charge", "--gate-certificate", str(cert), "--gate-trust", str(trust),
                 match="[gate] extra")  # fmt: skip


def test_verifier_error_is_refused(env, trust):
    cert = _write(env, "cert.json", _issue())
    boom = ikigov_cert.CertificateError("malformed certificate")
    with patch.object(ikigov_cert, "verify_certificate", side_effect=boom):
        _refused(env, "dp-charge", "--gate-certificate", str(cert), "--gate-trust", str(trust),
                 match="malformed certificate")  # fmt: skip
