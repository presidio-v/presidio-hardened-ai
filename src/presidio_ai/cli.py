"""``pai`` — command-line front-end for the presidio-hardened-ai evidence layer.

Commands:
  * ``pai ingest``  — scrub a JSONL source, record lineage to the ledger, and
                      optionally export signed D1/D4/O5 evidence.
  * ``pai verify``  — verify the tamper-evident ledger chain.
  * ``pai version`` — print the tool version.

Confirmations go to stderr so ``--quiet`` keeps stdout pure JSON (family convention).
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

import typer

from presidio_ai import __version__
from presidio_ai.dp import (
    BudgetExceeded,
    DPSGDConfig,
    EpsilonBudget,
    MPADenied,
    MPAPolicy,
    build_request,
    dpsgd_epsilon,
    make_trainer,
    request_hash,
    sign_approval,
)
from presidio_ai.evidence import (
    build_dp_evidence,
    build_ingest_evidence,
    export_evidence,
    generate_ed25519_keypair,
)
from presidio_ai.fl import (
    ConsortiumError,
    FedAvgAggregator,
    FederatedClient,
    SecureAggregationSession,
    SecureSumAggregator,
    charge_federated,
    federated_train,
    run_consortium_round,
)
from presidio_ai.ingest import ingest_records, records_jsonl_bytes
from presidio_ai.ledger import Ledger, LedgerError, verify_chain
from presidio_ai.pii import PIIBlockedError, PIIScrubber
from presidio_ai.provenance import ParentError, normalize_parents
from presidio_ai.sanitize import (
    ValidationError,
    validate_identifier,
    validate_path,
    validate_pii_action,
    validate_pii_mode,
    validate_silo_id,
)
from presidio_ai.security import increment_session_count, log_security_event, session_limit

app = typer.Typer(add_completion=False, help="Training-time privacy evidence layer.")

_KEY_ENV = "PRESIDIO_AI_LEDGER_KEY"
_PARENT_HELP = "Upstream evidence content hash, lowercase hex (ADR-0002 parents; repeatable)."


def _err(message: str) -> None:
    typer.echo(message, err=True)


def _warn_if_seeded(seed: int | None) -> None:
    """A seeded run draws predictable DP noise: say so, so it is never mistaken for private."""
    if seed is not None:
        _err(
            "warning: --seed makes the DP noise reproducible and predictable; the reported "
            "epsilon does not hold against anyone who knows the seed. Use only for testing."
        )


def _resolve_key(key: str | None) -> str:
    resolved = key or os.environ.get(_KEY_ENV)
    if not resolved:
        _err(f"error: a ledger key is required (--key or ${_KEY_ENV})")
        raise typer.Exit(1)
    return resolved


def _resolve_signing(algorithm: str, ledger_key: str, signing_key: str | None) -> tuple[str, str]:
    """Pick the evidence signing (algorithm, key). HMAC reuses the ledger key;
    Ed25519 requires an explicit private key (hex)."""
    if algorithm == "hmac-sha256":
        return algorithm, signing_key or ledger_key
    if algorithm == "ed25519":
        if not signing_key:
            _err("error: --signing-key (ed25519 private hex) is required for --algorithm ed25519")
            raise typer.Exit(1)
        return algorithm, signing_key
    _err(f"error: unknown --algorithm {algorithm!r} (use hmac-sha256 | ed25519)")
    raise typer.Exit(1)


def _resolve_parents(parents: list[str] | None) -> list[str]:
    """Validate --parent values (ADR-0002 P2/P3); exit 1 on a malformed entry."""
    try:
        return normalize_parents(parents)
    except ParentError as exc:
        _err(f"error: --parent: {exc}")
        raise typer.Exit(1) from exc


_GATE_CERTIFICATE_HELP = (
    "ikigov-assess gate certificate (gate-certificate@1) whose decision admitted this "
    "training run (repeatable). Verified against --gate-trust before anything is "
    "charged or emitted: schema, issuer signature, expiry, embedded evidence-refs and "
    "the recomputed decision, which must be OPEN. Its identity (sha256 of the canonical "
    "document minus `signature`) is appended to the parents. Needs the gate extra "
    "(pip install 'presidio-hardened-ai[gate]')."
)
_GATE_TRUST_HELP = (
    "Trust-store JSON for --gate-certificate, in ikigov-assess's format: the issuer and "
    "every signer of an embedded evidence-ref. Required with --gate-certificate."
)


def _resolve_gate_parents(
    parents: list[str], gate_certificate: list[Path] | None, gate_trust: Path | None
) -> list[str]:
    """Verify each --gate-certificate and append its identity to ``parents``.

    Without --gate-certificate the parents are returned unchanged. Any refusal exits 1
    before the ledger is touched.
    """
    from presidio_ai.gate_certificate import GateCertificateError, verify_gate_certificates

    if not gate_certificate:
        if gate_trust is not None:
            _err("error: --gate-trust given without --gate-certificate; nothing charged")
            raise typer.Exit(1)
        return parents
    if gate_trust is None:
        _err(
            "error: --gate-certificate requires --gate-trust; a certificate is never used "
            "unverified; nothing charged"
        )
        raise typer.Exit(1)
    try:
        identities = verify_gate_certificates(list(gate_certificate), gate_trust)
    except GateCertificateError as exc:
        log_security_event(
            {"event": "pai-gate-certificate-refused", "certificates": len(gate_certificate)}
        )
        _err(f"GATE CERTIFICATE REFUSED: {exc}; nothing charged")
        raise typer.Exit(1) from exc
    log_security_event({"event": "pai-gate-certificate-verified", "certificates": len(identities)})
    return normalize_parents([*parents, *identities])


def _parse_jsonl(text: str) -> list[object]:
    records: list[object] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"invalid JSON on line {n}: {exc.msg}") from exc
    return records


def _read_jsonl(path: Path) -> list[object]:
    return _parse_jsonl(path.read_text(encoding="utf-8"))


@app.command()
def ingest(
    source: str = typer.Option(..., "--source", help="Source identifier for lineage."),
    input: Path = typer.Option(..., "--input", "-i", help="JSONL input file."),
    ledger_path: Path = typer.Option(..., "--ledger", help="Path to the JSON-L ledger."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write scrubbed JSONL here."),
    pii_mode: str = typer.Option("regex", "--pii-mode", help="regex | nlp"),
    pii_action: str = typer.Option("redact", "--pii-action", help="redact | block | warn"),
    key: str | None = typer.Option(None, "--key", help=f"Ledger/signing key (or ${_KEY_ENV})."),
    evidence_out: Path | None = typer.Option(
        None, "--evidence-out", help="Write EvidenceRef JSON."
    ),
    use_case: str = typer.Option(
        "unnamed", "--use-case", help="Use-case name for evidence export."
    ),
    signer: str = typer.Option("presidio-hardened-ai", "--signer", help="Evidence signer id."),
    algorithm: str = typer.Option(
        "ed25519", "--algorithm", help="Evidence signing: ed25519 | hmac-sha256."
    ),
    signing_key: str | None = typer.Option(
        None, "--signing-key", help="Ed25519 private key hex (for --algorithm ed25519)."
    ),
    parent: list[str] | None = typer.Option(None, "--parent", help=_PARENT_HELP),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Scrub a source, record lineage, and optionally export signed evidence."""
    parents = _resolve_parents(parent)
    try:
        source = validate_identifier(source, what="source")
        use_case = validate_identifier(use_case, what="use-case")
        validate_path(str(input))
        validate_path(str(ledger_path))
        pii_mode = validate_pii_mode(pii_mode)
        pii_action = validate_pii_action(pii_action)
        resolved_key = _resolve_key(key)

        if increment_session_count() > session_limit():
            _err(f"error: session limit reached ({session_limit()})")
            raise typer.Exit(1)
        if not input.exists():
            _err(f"error: input not found: {input}")
            raise typer.Exit(1)

        raw_bytes = input.read_bytes()
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError(f"input is not valid UTF-8: {exc.reason}") from exc
        records = _parse_jsonl(text)
        ledger = Ledger(ledger_path, key=resolved_key)
        scrubber = PIIScrubber(action=pii_action, mode=pii_mode)
        result = ingest_records(
            records,
            source_id=source,
            ledger=ledger,
            scrubber=scrubber,
            raw_bytes=raw_bytes,
            parents=parents,
        )

        if out is not None:
            # Exactly the bytes content_hash covers (records-jsonl@1): sha256sum reproduces it.
            out.write_bytes(records_jsonl_bytes(result.records))
            _err(f"Scrubbed records written to: {out}")

        evidence_payload = None
        if evidence_out is not None:
            alg, sig_key = _resolve_signing(algorithm, resolved_key, signing_key)
            refs = build_ingest_evidence(
                result, ledger=ledger, signing_key=sig_key, signer=signer, algorithm=alg
            )
            export_evidence(refs, evidence_out, use_case=use_case)
            evidence_payload = [r.to_dict() for r in refs]
            _err(f"Evidence ({len(refs)} refs) written to: {evidence_out}")

        log_security_event(
            {
                "event": "pai-ingest-complete",
                "n_records": result.n_records,
                "redactions_total": result.redactions_total,
                "pii_mode": scrubber.effective_mode,
                "pii_action": pii_action,
                "evidence_exported": evidence_out is not None,
            }
        )

        summary = {
            "source_id": result.source_id,
            "n_records": result.n_records,
            "n_fields_scrubbed": result.n_fields_scrubbed,
            "redaction_counts": result.redaction_counts,
            "content_hash": result.content_hash,
            "content_hash_scope": result.content_hash_scope,
            "source_commitment": result.source_commitment,
            "source_commitment_scope": result.source_commitment_scope,
            "parents": list(result.parents),
            "ledger_seq": result.ledger_seq,
            "evidence": evidence_payload,
        }
        if quiet:
            typer.echo(json.dumps(summary))
        else:
            typer.echo(f"Ingested {result.n_records} record(s) from '{result.source_id}'")
            typer.echo(f"  redactions: {result.redactions_total} {result.redaction_counts}")
            typer.echo(f"  content_hash: {result.content_hash}")
            typer.echo(f"  ledger seq:   {result.ledger_seq}")
    except (ValidationError, PIIBlockedError, LedgerError, ValueError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc


@app.command()
def verify(
    ledger_path: Path = typer.Option(..., "--ledger", help="Path to the JSON-L ledger."),
    key: str | None = typer.Option(None, "--key", help=f"Ledger key (or ${_KEY_ENV})."),
    expect_entry: str | None = typer.Option(
        None,
        "--expect-entry",
        help="SEQ:HEX anchor, e.g. the O5 head of a verified signed export; detects "
        "truncation or rollback past it.",
    ),
    min_entries: int = typer.Option(0, "--min-entries", min=0, help="Fail below N entries."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Verify the ledger chain; exit 0 if intact, 1 if tampered, truncated or missing.

    Without ``--expect-entry`` or ``--min-entries`` a ledger whose trailing entries were
    dropped still verifies: the chain alone cannot show that it ended earlier.
    """
    resolved_key = _resolve_key(key)
    try:
        anchor = _parse_anchor(expect_entry) if expect_entry is not None else None
        entries = verify_chain(
            ledger_path, key=resolved_key, anchor=anchor, min_entries=min_entries
        )
    except LedgerError as exc:
        log_security_event({"event": "pai-ledger-verify", "ok": False})
        if quiet:
            typer.echo(json.dumps({"ok": False, "error": str(exc)}))
        else:
            _err(f"LEDGER VERIFICATION FAILED: {exc}")
        raise typer.Exit(1) from exc
    log_security_event({"event": "pai-ledger-verify", "ok": True, "n_entries": len(entries)})
    if quiet:
        typer.echo(json.dumps({"ok": True, "n_entries": len(entries), "head": _head(entries)}))
    else:
        typer.echo(f"Ledger OK — {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} verified")


def _parse_anchor(text: str) -> tuple[int, str]:
    seq, sep, digest = text.partition(":")
    if not sep or not seq.isdigit() or len(digest) != 64:
        raise LedgerError("--expect-entry must be SEQ:HEX (64 hex characters)")
    if any(c not in "0123456789abcdef" for c in digest):
        raise LedgerError("--expect-entry hash must be lowercase hex")
    return int(seq), digest


def _head(entries: list) -> str | None:
    return entries[-1].entry_hash if entries else None


@app.command(name="dp-train")
def dp_train(
    input: Path = typer.Option(..., "--input", "-i", help='JSONL of {"x": [floats], "y": 0|1}.'),
    ledger_path: Path = typer.Option(..., "--ledger", help="Path to the JSON-L ledger."),
    total_epsilon: float = typer.Option(..., "--total-epsilon", help="Org epsilon budget."),
    job_id: str = typer.Option(..., "--job-id", help="Identifier for this training job."),
    noise_multiplier: float = typer.Option(..., "--noise-multiplier", help="Gaussian noise sigma."),
    sample_rate: float = typer.Option(..., "--sample-rate", help="Poisson sampling rate q."),
    steps: int = typer.Option(..., "--steps", help="DP-SGD steps."),
    delta: float = typer.Option(1e-5, "--delta", help="Budget/guarantee delta."),
    clip_norm: float = typer.Option(1.0, "--clip-norm", help="Per-example L2 gradient clip."),
    learning_rate: float = typer.Option(0.1, "--lr", help="Learning rate."),
    seed: int | None = typer.Option(
        None,
        "--seed",
        help="Seed the DP noise for a reproducible TEST run (predictable noise: not private). "
        "Default: CSPRNG noise.",
    ),
    key: str | None = typer.Option(None, "--key", help=f"Ledger/signing key (or ${_KEY_ENV})."),
    evidence_out: Path | None = typer.Option(
        None, "--evidence-out", help="Write D4 EvidenceRef JSON."
    ),
    signer: str = typer.Option("presidio-hardened-ai", "--signer", help="Evidence signer id."),
    algorithm: str = typer.Option(
        "ed25519", "--algorithm", help="Evidence signing: ed25519 | hmac-sha256."
    ),
    signing_key: str | None = typer.Option(
        None, "--signing-key", help="Ed25519 private key hex (for --algorithm ed25519)."
    ),
    parent: list[str] | None = typer.Option(None, "--parent", help=_PARENT_HELP),
    gate_certificate: list[Path] | None = typer.Option(
        None, "--gate-certificate", help=_GATE_CERTIFICATE_HELP
    ),
    gate_trust: Path | None = typer.Option(None, "--gate-trust", help=_GATE_TRUST_HELP),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Train a DP-SGD logistic model, charge the budget, optionally export evidence.

    Runs the dependency-free reference DP-SGD trainer (per-example clipping + Gaussian
    noise), so the (epsilon, delta) charged is the guarantee of a real private run.
    """
    resolved_key = _resolve_key(key)
    job_id = validate_identifier(job_id, what="job-id")
    parents = _resolve_gate_parents(_resolve_parents(parent), gate_certificate, gate_trust)
    try:
        validate_path(str(input))
        if not input.exists():
            _err(f"error: input not found: {input}")
            raise typer.Exit(1)
        features: list[list[float]] = []
        labels: list[int] = []
        for n, record in enumerate(_read_jsonl(input), 1):
            if not isinstance(record, dict) or "x" not in record or "y" not in record:
                raise ValidationError(f"line {n}: each record needs 'x' (list) and 'y' (0/1)")
            x, y = record["x"], record["y"]
            if not isinstance(x, list) or not all(isinstance(v, (int, float)) for v in x):
                raise ValidationError(f"line {n}: 'x' must be a list of numbers")
            if y not in (0, 1):
                raise ValidationError(f"line {n}: 'y' must be 0 or 1")
            features.append([float(v) for v in x])
            labels.append(int(y))
        if not features:
            raise ValidationError("no training records found")

        config = DPSGDConfig(
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate,
            steps=steps,
            delta=delta,
            clip_norm=clip_norm,
            learning_rate=learning_rate,
        )
        _warn_if_seeded(seed)
        model = make_trainer("reference").train(
            features, labels, config, seed=seed or 0, secure_rng=seed is None
        )
        ledger = Ledger(ledger_path, key=resolved_key)
        budget = EpsilonBudget(total_epsilon, delta, ledger)
        charge = budget.charge(model.result, job_id=job_id, parents=parents)
    except BudgetExceeded as exc:
        _err(f"BUDGET EXCEEDED: {exc}")
        raise typer.Exit(2) from exc
    except (ValidationError, ValueError, LedgerError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc

    evidence_payload = None
    if evidence_out is not None:
        alg, sig_key = _resolve_signing(algorithm, resolved_key, signing_key)
        refs = build_dp_evidence(
            charge.result,
            signing_key=sig_key,
            signer=signer,
            charge_seq=charge.ledger_seq,
            algorithm=alg,
            parents=parents,
        )
        export_evidence(refs, evidence_out, use_case=job_id)
        evidence_payload = [r.to_dict() for r in refs]
        _err(f"Evidence ({len(refs)} ref) written to: {evidence_out}")

    log_security_event(
        {
            "event": "pai-dp-train",
            "n_records": len(features),
            "epsilon": charge.result.epsilon,
            "accuracy": model.accuracy,
            "remaining_epsilon": charge.remaining_epsilon,
        }
    )
    summary = {
        "job_id": charge.job_id,
        "epsilon": charge.result.epsilon,
        "delta": charge.result.delta,
        "accuracy": model.accuracy,
        "n_records": len(features),
        "n_features": model.n_features,
        "remaining_epsilon": charge.remaining_epsilon,
        "ledger_seq": charge.ledger_seq,
        "evidence": evidence_payload,
    }
    if quiet:
        typer.echo(json.dumps(summary))
    else:
        typer.echo(f"Trained '{charge.job_id}': accuracy={model.accuracy:.3f}")
        typer.echo(f"  epsilon={charge.result.epsilon:.4f}  ledger seq {charge.ledger_seq}")
        typer.echo(f"  remaining {charge.remaining_epsilon:.4f}/{total_epsilon:.4f}")


@app.command(name="fl-train")
def fl_train(
    silo: list[str] = typer.Option(
        ..., "--silo", help='Silo JSONL of {"x":[...],"y":0|1} (repeatable).'
    ),
    rounds: int = typer.Option(..., "--rounds", help="Federated rounds."),
    local_steps: int = typer.Option(..., "--local-steps", help="DP-SGD steps per round per silo."),
    noise_multiplier: float = typer.Option(..., "--noise-multiplier", help="Gaussian noise sigma."),
    sample_rate: float = typer.Option(..., "--sample-rate", help="Poisson sampling rate q."),
    delta: float = typer.Option(1e-5, "--delta", help="Guarantee delta."),
    clip_norm: float = typer.Option(1.0, "--clip-norm", help="Per-example L2 gradient clip."),
    learning_rate: float = typer.Option(0.1, "--lr", help="Learning rate."),
    seed: int | None = typer.Option(
        None,
        "--seed",
        help="Seed the DP noise for a reproducible TEST run (predictable noise: not private). "
        "Default: CSPRNG noise.",
    ),
    secure_agg: bool = typer.Option(False, "--secure-agg", help="Use secure-sum aggregation."),
    charge: bool = typer.Option(
        False, "--charge", help="Charge each silo a per-silo epsilon budget."
    ),
    total_epsilon: float = typer.Option(
        0.0, "--total-epsilon", help="Per-silo epsilon budget (with --charge)."
    ),
    ledger_dir: str | None = typer.Option(
        None, "--ledger-dir", help="Directory for per-silo ledgers (with --charge)."
    ),
    key: str | None = typer.Option(
        None, "--key", help=f"Ledger key (or ${_KEY_ENV}); also HMAC signing key."
    ),
    evidence_dir: str | None = typer.Option(
        None, "--evidence-dir", help="Directory for per-silo D4 evidence."
    ),
    algorithm: str = typer.Option(
        "ed25519", "--algorithm", help="Evidence signing: ed25519 | hmac-sha256."
    ),
    signing_key: str | None = typer.Option(
        None, "--signing-key", help="Ed25519 private key hex (for evidence)."
    ),
    signer: str = typer.Option("presidio-hardened-ai", "--signer", help="Evidence signer id."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Train across silos (FedAvg). Raw data stays per-silo; only DP updates are shared.

    Reports the global model accuracy and each silo's composed (epsilon, delta) over
    rounds x local_steps. With --secure-agg the coordinator recovers only the combined
    update, not any individual silo's.
    """
    try:
        clients = []
        for path_str in silo:
            validate_path(path_str)
            path = Path(path_str)
            if not path.exists():
                _err(f"error: silo not found: {path}")
                raise typer.Exit(1)
            features: list[list[float]] = []
            labels: list[int] = []
            for n, record in enumerate(_read_jsonl(path), 1):
                if not isinstance(record, dict) or "x" not in record or "y" not in record:
                    raise ValidationError(f"{path.name} line {n}: need 'x' (list) and 'y' (0/1)")
                x, y = record["x"], record["y"]
                if not isinstance(x, list) or not all(isinstance(v, (int, float)) for v in x):
                    raise ValidationError(f"{path.name} line {n}: 'x' must be a list of numbers")
                if y not in (0, 1):
                    raise ValidationError(f"{path.name} line {n}: 'y' must be 0 or 1")
                features.append([float(v) for v in x])
                labels.append(int(y))
            if not features:
                raise ValidationError(f"{path.name}: no training records")
            clients.append(FederatedClient(path.stem, features, labels))

        config = DPSGDConfig(
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate,
            steps=local_steps,
            delta=delta,
            clip_norm=clip_norm,
            learning_rate=learning_rate,
        )
        _warn_if_seeded(seed)
        aggregator = (
            SecureSumAggregator(seed=seed if seed is not None else secrets.randbits(63))
            if secure_agg
            else FedAvgAggregator()
        )
        result = federated_train(
            clients,
            rounds=rounds,
            local_config=config,
            seed=seed or 0,
            aggregator=aggregator,
            secure_rng=seed is None,
        )
        governance = None
        if charge:
            if total_epsilon <= 0 or not ledger_dir:
                raise ValidationError("--charge requires --total-epsilon > 0 and --ledger-dir")
            resolved_key = _resolve_key(key)
            sign_key = signing_key
            if algorithm == "ed25519" and evidence_dir is not None and not sign_key:
                raise ValidationError("--algorithm ed25519 needs --signing-key for --evidence-dir")
            governance = charge_federated(
                result,
                total_epsilon=total_epsilon,
                ledger_dir=ledger_dir,
                key=resolved_key,
                evidence_dir=evidence_dir,
                signer=signer,
                algorithm=algorithm,
                signing_key=sign_key,
            )
    except (ValidationError, ValueError, LedgerError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc
    except BudgetExceeded as exc:
        _err(f"BUDGET EXCEEDED: {exc}")
        raise typer.Exit(2) from exc

    log_security_event(
        {
            "event": "pai-fl-train",
            "n_silos": len(clients),
            "rounds": rounds,
            "pooled_accuracy": result.pooled_accuracy,
            "secure_agg": secure_agg,
            "charged": charge,
        }
    )
    per_client = {
        cid: {"epsilon": r.epsilon, "delta": r.delta, "steps": r.steps}
        for cid, r in result.per_client_epsilon.items()
    }
    if governance is not None:
        for cid, g in governance.items():
            per_client[cid]["remaining_epsilon"] = g.charge.remaining_epsilon
            per_client[cid]["ledger_seq"] = g.charge.ledger_seq
            per_client[cid]["evidence"] = str(g.evidence_path) if g.evidence_path else None
    summary = {
        "rounds": result.rounds,
        "n_silos": len(clients),
        "pooled_accuracy": result.pooled_accuracy,
        "secure_agg": secure_agg,
        "charged": charge,
        "per_client": per_client,
    }
    if quiet:
        typer.echo(json.dumps(summary))
    else:
        typer.echo(
            f"Federated {result.rounds} rounds over {len(clients)} silo(s) "
            f"({'secure-agg' if secure_agg else 'fedavg'})"
        )
        typer.echo(f"  pooled accuracy: {result.pooled_accuracy:.3f}")
        for cid, r in result.per_client_epsilon.items():
            typer.echo(f"  {cid}: epsilon={r.epsilon:.4f} over {r.steps} steps")


@app.command()
def keygen(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Generate an Ed25519 keypair for signing evidence (store the private key securely)."""
    try:
        private_key, public_key = generate_ed25519_keypair()
    except ImportError as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc
    if quiet:
        typer.echo(json.dumps({"private_key": private_key, "public_key": public_key}))
    else:
        _err("Store the private key secretly; share only the public key (trust store).")
        typer.echo(f"private_key: {private_key}")
        typer.echo(f"public_key:  {public_key}")


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(__version__)


@app.command(name="dp-account")
def dp_account(
    noise_multiplier: float = typer.Option(..., "--noise-multiplier", help="Gaussian noise sigma."),
    sample_rate: float = typer.Option(
        ..., "--sample-rate", help="Poisson sampling rate q in [0,1]."
    ),
    steps: int = typer.Option(..., "--steps", help="Number of DP-SGD steps."),
    delta: float = typer.Option(1e-5, "--delta", help="Target delta in (0,1)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Compute the (epsilon, delta) guarantee of a DP-SGD run (no ledger)."""
    try:
        result = dpsgd_epsilon(
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate,
            steps=steps,
            delta=delta,
        )
    except ValueError as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc
    if quiet:
        typer.echo(json.dumps(result.as_dict()))
    else:
        typer.echo(f"epsilon = {result.epsilon:.4f}  (delta = {result.delta:g})")
        typer.echo(f"  optimal RDP order: {result.optimal_order}")
        typer.echo(
            f"  sigma={result.noise_multiplier:g} q={result.sample_rate:g} steps={result.steps}"
        )


def _parse_approvals(items: list[str] | None) -> dict[str, str]:
    approvals: dict[str, str] = {}
    for item in items or []:
        approver_id, sep, sig = item.partition(":")
        if not sep or not approver_id or not sig:
            raise ValidationError(f"--approval must be 'id:hexsig', got {item!r}")
        approvals[approver_id] = sig
    return approvals


@app.command(name="dp-authorize")
def dp_authorize(
    job_id: str = typer.Option(..., "--job-id", help="Job being authorized."),
    noise_multiplier: float = typer.Option(..., "--noise-multiplier", help="Gaussian noise sigma."),
    sample_rate: float = typer.Option(..., "--sample-rate", help="Poisson sampling rate q."),
    steps: int = typer.Option(..., "--steps", help="Number of DP-SGD steps."),
    delta: float = typer.Option(1e-5, "--delta", help="Guarantee delta."),
    approver: str = typer.Option(..., "--approver", help="This approver's id."),
    approver_key: str = typer.Option(..., "--approver-key", help="This approver's signing key."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Approver-side: countersign a job's authorization request (n-of-m approval)."""
    try:
        result = dpsgd_epsilon(
            noise_multiplier=noise_multiplier, sample_rate=sample_rate, steps=steps, delta=delta
        )
    except ValueError as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc
    req_hash = request_hash(build_request(result, job_id=job_id))
    signature = sign_approval(req_hash, approver_id=approver, approver_key=approver_key)
    out = {
        "approver": approver,
        "request_hash": req_hash,
        "signature": signature,
        "epsilon": result.epsilon,
        "approval": f"{approver}:{signature}",
    }
    if quiet:
        typer.echo(json.dumps(out))
    else:
        typer.echo(f"approver {approver} signed job '{job_id}' (epsilon={result.epsilon:.4f})")
        typer.echo(f"  --approval {approver}:{signature}")


@app.command(name="dp-charge")
def dp_charge(
    ledger_path: Path = typer.Option(..., "--ledger", help="Path to the JSON-L ledger."),
    total_epsilon: float = typer.Option(..., "--total-epsilon", help="Org epsilon budget."),
    job_id: str = typer.Option(..., "--job-id", help="Identifier for this training job."),
    noise_multiplier: float = typer.Option(..., "--noise-multiplier", help="Gaussian noise sigma."),
    sample_rate: float = typer.Option(..., "--sample-rate", help="Poisson sampling rate q."),
    steps: int = typer.Option(..., "--steps", help="Number of DP-SGD steps."),
    delta: float = typer.Option(1e-5, "--delta", help="Budget/guarantee delta."),
    key: str | None = typer.Option(None, "--key", help=f"Ledger/signing key (or ${_KEY_ENV})."),
    evidence_out: Path | None = typer.Option(
        None, "--evidence-out", help="Write D4 EvidenceRef JSON."
    ),
    signer: str = typer.Option("presidio-hardened-ai", "--signer", help="Evidence signer id."),
    algorithm: str = typer.Option(
        "ed25519", "--algorithm", help="Evidence signing: ed25519 | hmac-sha256."
    ),
    signing_key: str | None = typer.Option(
        None, "--signing-key", help="Ed25519 private key hex (for --algorithm ed25519)."
    ),
    mpa_threshold: int = typer.Option(
        0, "--mpa-threshold", help="Require n-of-m approval (0=off)."
    ),
    mpa_min_epsilon: float = typer.Option(
        0.0, "--mpa-min-epsilon", help="Authorize at/above this epsilon."
    ),
    approver_keys: Path | None = typer.Option(
        None, "--approver-keys", help="JSON file: {approver_id: key}."
    ),
    approval: list[str] | None = typer.Option(
        None, "--approval", help="Approval as id:hexsig (repeatable)."
    ),
    parent: list[str] | None = typer.Option(None, "--parent", help=_PARENT_HELP),
    gate_certificate: list[Path] | None = typer.Option(
        None, "--gate-certificate", help=_GATE_CERTIFICATE_HELP
    ),
    gate_trust: Path | None = typer.Option(None, "--gate-trust", help=_GATE_TRUST_HELP),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Account a DP-SGD job, charge it to the ledger budget, optionally export evidence."""
    resolved_key = _resolve_key(key)
    job_id = validate_identifier(job_id, what="job-id")
    parents = _resolve_gate_parents(_resolve_parents(parent), gate_certificate, gate_trust)
    try:
        policy = None
        keys: dict[str, str] = {}
        approvals: dict[str, str] = {}
        if mpa_threshold > 0:
            if approver_keys is None or not approver_keys.exists():
                _err("error: --approver-keys JSON file is required when --mpa-threshold > 0")
                raise typer.Exit(1)
            keys = json.loads(approver_keys.read_text())
            policy = MPAPolicy(
                threshold=mpa_threshold,
                min_epsilon=mpa_min_epsilon,
                approvers=tuple(sorted(keys)),
            )
            approvals = _parse_approvals(approval)
        ledger = Ledger(ledger_path, key=resolved_key)
        budget = EpsilonBudget(total_epsilon, delta, ledger)
        charge = budget.charge_dpsgd(
            job_id=job_id,
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate,
            steps=steps,
            policy=policy,
            approvals=approvals,
            approver_keys=keys,
            parents=parents,
        )
    except MPADenied as exc:
        _err(f"AUTHORIZATION DENIED: {exc}")
        raise typer.Exit(3) from exc
    except BudgetExceeded as exc:
        _err(f"BUDGET EXCEEDED: {exc}")
        raise typer.Exit(2) from exc
    except (ValueError, LedgerError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc

    evidence_payload = None
    if evidence_out is not None:
        alg, sig_key = _resolve_signing(algorithm, resolved_key, signing_key)
        refs = build_dp_evidence(
            charge.result,
            signing_key=sig_key,
            signer=signer,
            charge_seq=charge.ledger_seq,
            algorithm=alg,
            parents=parents,
        )
        export_evidence(refs, evidence_out, use_case=job_id)
        evidence_payload = [r.to_dict() for r in refs]
        _err(f"Evidence ({len(refs)} ref) written to: {evidence_out}")

    log_security_event(
        {
            "event": "pai-dp-charge",
            "epsilon": charge.result.epsilon,
            "remaining_epsilon": charge.remaining_epsilon,
            "steps": charge.result.steps,
            "evidence_exported": evidence_out is not None,
        }
    )
    summary = {
        "job_id": charge.job_id,
        "epsilon": charge.result.epsilon,
        "delta": charge.result.delta,
        "optimal_order": charge.result.optimal_order,
        "spent_epsilon": charge.spent_epsilon,
        "remaining_epsilon": charge.remaining_epsilon,
        "ledger_seq": charge.ledger_seq,
        "evidence": evidence_payload,
    }
    if quiet:
        typer.echo(json.dumps(summary))
    else:
        typer.echo(f"Charged job '{charge.job_id}': epsilon={charge.result.epsilon:.4f}")
        typer.echo(
            f"  spent {charge.spent_epsilon:.4f}/{total_epsilon:.4f} "
            f"(remaining {charge.remaining_epsilon:.4f})"
        )
        typer.echo(f"  ledger seq: {charge.ledger_seq}")


@app.command(name="dp-budget")
def dp_budget(
    ledger_path: Path = typer.Option(..., "--ledger", help="Path to the JSON-L ledger."),
    total_epsilon: float = typer.Option(..., "--total-epsilon", help="Org epsilon budget."),
    delta: float = typer.Option(1e-5, "--delta", help="Budget delta."),
    key: str | None = typer.Option(None, "--key", help=f"Ledger key (or ${_KEY_ENV})."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Report epsilon spent and remaining, re-derived from the verified ledger."""
    resolved_key = _resolve_key(key)
    try:
        ledger = Ledger(ledger_path, key=resolved_key)
        budget = EpsilonBudget(total_epsilon, delta, ledger)
        spent = budget.spent()
        remaining = budget.remaining()
    except (ValueError, LedgerError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc
    if quiet:
        typer.echo(
            json.dumps({"total_epsilon": total_epsilon, "spent": spent, "remaining": remaining})
        )
    else:
        typer.echo(f"budget: {spent:.4f} / {total_epsilon:.4f} spent (remaining {remaining:.4f})")


@app.command(name="consortium-round")
def consortium_round(
    round_file: Path = typer.Option(
        ..., "--round-file", help="JSON: {round_id, delta, dim, threshold, updates, dp, dropped?}."
    ),
    ledger_path: Path = typer.Option(..., "--ledger", help="Path to the round JSON-L ledger."),
    key: str | None = typer.Option(None, "--key", help=f"Ledger/signing key (or ${_KEY_ENV})."),
    budget_dir: Path | None = typer.Option(
        None, "--budget-dir", help="Per-silo budget ledgers <dir>/<silo>.jsonl."
    ),
    budget_epsilon: float = typer.Option(
        10.0, "--budget-epsilon", help="Per-silo total epsilon budget (with --budget-dir)."
    ),
    mpa_threshold: int = typer.Option(
        0, "--mpa-threshold", help="Require n-of-m approval (0=off)."
    ),
    mpa_min_epsilon: float = typer.Option(
        0.0, "--mpa-min-epsilon", help="Authorize at/above this round epsilon."
    ),
    approver_keys: Path | None = typer.Option(
        None, "--approver-keys", help="JSON file: {approver_id: key}."
    ),
    approval: list[str] | None = typer.Option(
        None, "--approval", help="Approval as id:hexsig (repeatable)."
    ),
    evidence_out: Path | None = typer.Option(
        None, "--evidence-out", help="Write the round's signed D4 EvidenceRef JSON."
    ),
    signer: str = typer.Option("presidio-hardened-ai", "--signer", help="Evidence signer id."),
    algorithm: str = typer.Option(
        "ed25519", "--algorithm", help="Evidence signing: ed25519 | hmac-sha256."
    ),
    signing_key: str | None = typer.Option(
        None, "--signing-key", help="Ed25519 private key hex (for --algorithm ed25519)."
    ),
    parent: list[str] | None = typer.Option(None, "--parent", help=_PARENT_HELP),
    gate_certificate: list[Path] | None = typer.Option(
        None, "--gate-certificate", help=_GATE_CERTIFICATE_HELP
    ),
    gate_trust: Path | None = typer.Option(None, "--gate-trust", help=_GATE_TRUST_HELP),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Machine-readable JSON only."),
) -> None:
    """Run one governed secure-aggregation round: MPA -> aggregate -> per-silo charge -> D4."""
    resolved_key = _resolve_key(key)
    parents = _resolve_gate_parents(_resolve_parents(parent), gate_certificate, gate_trust)
    try:
        spec = json.loads(round_file.read_text(encoding="utf-8"))
        round_id = validate_identifier(str(spec["round_id"]), what="round-id")
        delta = float(spec["delta"])
        dim = int(spec["dim"])
        threshold = int(spec["threshold"])
        updates = {
            validate_silo_id(str(k)): [float(x) for x in v] for k, v in spec["updates"].items()
        }
        dp_spec = spec["dp"]
        dropped = [validate_silo_id(str(x)) for x in spec.get("dropped", [])]
        parties = sorted(set(updates) | set(dropped))
        dp_results = {
            s: dpsgd_epsilon(
                noise_multiplier=float(dp_spec[s]["noise_multiplier"]),
                sample_rate=float(dp_spec[s]["sample_rate"]),
                steps=int(dp_spec[s]["steps"]),
                delta=delta,
            )
            for s in updates
        }
        session = SecureAggregationSession(parties, dim=dim, threshold=threshold)

        policy = None
        keys: dict[str, str] = {}
        approvals: dict[str, str] = {}
        if mpa_threshold > 0:
            if approver_keys is None or not approver_keys.exists():
                _err("error: --approver-keys JSON file is required when --mpa-threshold > 0")
                raise typer.Exit(1)
            keys = json.loads(approver_keys.read_text())
            policy = MPAPolicy(
                threshold=mpa_threshold, min_epsilon=mpa_min_epsilon, approvers=tuple(sorted(keys))
            )
            approvals = _parse_approvals(approval)

        budgets = None
        if budget_dir is not None:
            budget_dir.mkdir(parents=True, exist_ok=True)
            root = budget_dir.resolve()
            budgets = {}
            for s in updates:
                silo_ledger = budget_dir / f"{s}.jsonl"
                if silo_ledger.resolve().parent != root:  # defence in depth (symlinks)
                    raise ValidationError(f"silo ledger for {s!r} would leave --budget-dir")
                if silo_ledger.resolve() == ledger_path.resolve():
                    raise ValidationError(f"silo ledger for {s!r} is the round ledger")
                budgets[s] = EpsilonBudget(
                    budget_epsilon, delta, Ledger(silo_ledger, key=resolved_key)
                )

        alg, sig_key = (algorithm, None)
        if evidence_out is not None:
            alg, sig_key = _resolve_signing(algorithm, resolved_key, signing_key)

        result = run_consortium_round(
            round_id=round_id,
            updates=updates,
            dp_results=dp_results,
            session=session,
            ledger=Ledger(ledger_path, key=resolved_key),
            budgets=budgets,
            dropped=dropped,
            policy=policy,
            approvals=approvals,
            approver_keys=keys,
            signing_key=sig_key,
            signer=signer,
            algorithm=alg,
            evidence_path=evidence_out,
            parents=parents,
        )
    except MPADenied as exc:
        _err(f"AUTHORIZATION DENIED: {exc}")
        raise typer.Exit(3) from exc
    except BudgetExceeded as exc:
        _err(f"BUDGET EXCEEDED: {exc}")
        raise typer.Exit(2) from exc
    except (KeyError, ValueError, ConsortiumError, LedgerError, ValidationError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc

    log_security_event(
        {
            "event": "pai-consortium-round",
            "round_id": result.round_id,
            "n_survivors": len(result.survivors),
            "n_dropped": len(result.dropped),
            "max_epsilon": result.max_epsilon,
            "authorized": bool(result.approvers),
            "evidence_exported": evidence_out is not None,
        }
    )
    summary = {
        "round_id": result.round_id,
        "n_survivors": len(result.survivors),
        "dropped": result.dropped,
        "max_epsilon": result.max_epsilon,
        "delta": result.delta,
        "approvers": result.approvers,
        "ledger_seq": result.ledger_seq,
        "aggregate": result.aggregate,
        "evidence": str(result.evidence_path) if result.evidence_path else None,
    }
    if quiet:
        typer.echo(json.dumps(summary))
    else:
        typer.echo(f"Consortium round '{result.round_id}': {len(result.survivors)} survivors")
        if result.dropped:
            typer.echo(f"  recovered from dropout of: {', '.join(map(str, result.dropped))}")
        if result.approvers:
            typer.echo(f"  authorized by: {', '.join(result.approvers)}")
        typer.echo(f"  max per-silo epsilon: {result.max_epsilon:.4f}  (delta={result.delta})")
        typer.echo(f"  ledger seq: {result.ledger_seq}")
        if result.evidence_path:
            typer.echo(f"  evidence: {result.evidence_path}")


def main() -> None:  # pragma: no cover - console-script entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
