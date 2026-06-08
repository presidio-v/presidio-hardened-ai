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
import sys
from pathlib import Path

import typer

from presidio_ai import __version__
from presidio_ai.evidence import build_ingest_evidence, export_evidence
from presidio_ai.ingest import ingest_records
from presidio_ai.ledger import Ledger, LedgerError, verify_chain
from presidio_ai.pii import PIIBlockedError, PIIScrubber
from presidio_ai.sanitize import (
    ValidationError,
    validate_identifier,
    validate_path,
    validate_pii_action,
    validate_pii_mode,
)
from presidio_ai.security import increment_session_count, log_security_event, session_limit

app = typer.Typer(add_completion=False, help="Training-time privacy evidence layer.")

_KEY_ENV = "PRESIDIO_AI_LEDGER_KEY"


def _err(message: str) -> None:
    typer.echo(message, err=True)


def _resolve_key(key: str | None) -> str:
    resolved = key or os.environ.get(_KEY_ENV)
    if not resolved:
        _err(f"error: a ledger key is required (--key or ${_KEY_ENV})")
        raise typer.Exit(1)
    return resolved


def _read_jsonl(path: Path) -> list[object]:
    records: list[object] = []
    with path.open("r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValidationError(f"invalid JSON on line {n}: {exc.msg}") from exc
    return records


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
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Scrub a source, record lineage, and optionally export signed evidence."""
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

        records = _read_jsonl(input)
        ledger = Ledger(ledger_path, key=resolved_key)
        scrubber = PIIScrubber(action=pii_action, mode=pii_mode)
        result = ingest_records(records, source_id=source, ledger=ledger, scrubber=scrubber)

        if out is not None:
            with out.open("w", encoding="utf-8") as fh:
                for record in result.records:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            _err(f"Scrubbed records written to: {out}")

        evidence_payload = None
        if evidence_out is not None:
            refs = build_ingest_evidence(
                result, ledger=ledger, signing_key=resolved_key, signer=signer
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
    except (ValidationError, PIIBlockedError, LedgerError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(1) from exc


@app.command()
def verify(
    ledger_path: Path = typer.Option(..., "--ledger", help="Path to the JSON-L ledger."),
    key: str | None = typer.Option(None, "--key", help=f"Ledger key (or ${_KEY_ENV})."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Verify the ledger chain; exit 0 if intact, 1 if tampered or missing."""
    resolved_key = _resolve_key(key)
    try:
        entries = verify_chain(ledger_path, key=resolved_key)
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


def _head(entries: list) -> str | None:
    return entries[-1].entry_hash if entries else None


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(__version__)


def main() -> None:  # pragma: no cover - console-script entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
