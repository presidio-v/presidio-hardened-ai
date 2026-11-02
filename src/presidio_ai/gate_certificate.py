"""Gate-certificate parents: verify an ikigov-assess certificate, then name it.

``pai dp-train``, ``dp-charge`` and ``consortium-round`` accept
``--gate-certificate PATH`` (repeatable) with ``--gate-trust PATH``. Each
certificate is verified with ikigov-assess's own verifier before its identity
enters ``parents``, so a training run can only name a gate decision that
verifies at the time of the run:

* ``verify_certificate`` checks the schema, the issuer signature against the
  trust store, the predicate identity, the validity bound (``expired``), every
  embedded evidence-ref and the recomputed decision. Any failure refuses.
* the verified decision must be ``OPEN``. A PARTIAL or BLOCKED gate did not
  admit the run, however well it verifies.

The identity is the family identity of a ``gate-certificate@1`` (presidio-evidence
ADR-0006, :func:`presidio_evidence.gate_certificate_identity`): SHA-256 over the
canonical JSON of the document minus its top-level ``signature``, i.e. exactly the
bytes the issuer signs. ``framework_content_hash`` names the gate rule, shared by
every certificate under it, and is never used as a parent.

Verifying is this producer's policy (ADR-0006 G4); resolving parents later is still
the consumer's walk (ADR-0002 P4). The verifier comes from the optional ``[gate]``
extra and is imported only when the option is used. Refusal happens before any
ledger entry is written.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

import presidio_evidence

#: Schema id of an ikigov-assess gate certificate.
GATE_CERTIFICATE_SCHEMA = presidio_evidence.GATE_CERTIFICATE_SCHEMA_ID

#: Upper bound on a certificate or trust-store file. A certificate embeds one
#: evidence-ref per gate item; 1 MiB is far above any real one.
MAX_FILE_BYTES = 1024 * 1024

_REQUIRED_DECISION = "OPEN"
_EXTRA_HINT = "--gate-certificate needs the [gate] extra: pip install 'presidio-hardened-ai[gate]'"


class GateCertificateError(ValueError):
    """A gate certificate was refused (fail-closed: nothing is charged or emitted)."""


def certificate_identity(document: object) -> str:
    """ADR-0006 identity of a ``gate-certificate@1`` (lowercase hex SHA-256).

    Fails closed on a non-object, a foreign schema or content the canonical profile
    rejects. Says nothing about validity.
    """
    try:
        return presidio_evidence.gate_certificate_identity(document)  # type: ignore[arg-type]
    except presidio_evidence.EvidenceError as exc:
        raise GateCertificateError(str(exc)) from exc


def _read_bounded(path: Path, what: str) -> str:
    try:
        info = path.stat()
    except OSError as exc:
        raise GateCertificateError(f"cannot read {what} {path}: {exc.strerror}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise GateCertificateError(f"{what} {path} is not a regular file")
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError as exc:  # pragma: no cover - race between stat and open
        raise GateCertificateError(f"cannot read {what} {path}: {exc.strerror}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise GateCertificateError(f"{what} {path} exceeds {MAX_FILE_BYTES} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateCertificateError(f"{what} {path} is not UTF-8") from exc


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-finite number {name}")


def _load_json(path: Path, what: str) -> object:
    text = _read_bounded(path, what)
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise GateCertificateError(f"{what} {path} is not valid JSON") from exc


def _ikigov():  # noqa: ANN202
    try:
        from presidio_ikigov_assess import certificate, evidence
    except ImportError as exc:
        raise GateCertificateError(_EXTRA_HINT) from exc
    return certificate, evidence


def verify_gate_certificates(
    certificate_paths: Sequence[Path],
    trust_path: Path,
    *,
    now: datetime | None = None,
) -> list[str]:
    """Verify each certificate against the trust store; return their identities.

    Order follows ``certificate_paths``. The first refusal raises
    :class:`GateCertificateError` and nothing is returned. ``now``
    (timezone-aware) overrides the wall clock for the expiry check.
    """
    if not certificate_paths:
        return []
    cert_mod, evidence_mod = _ikigov()
    trust_text = _read_bounded(trust_path, "gate trust store")
    try:
        trust = evidence_mod.load_trust_store(trust_text)
    except (evidence_mod.EvidenceError, ImportError, ValueError) as exc:
        raise GateCertificateError(f"gate trust store {trust_path}: {exc}") from exc

    identities: list[str] = []
    for path in certificate_paths:
        document = _load_json(path, "gate certificate")
        identity = certificate_identity(document)
        try:
            result = cert_mod.verify_certificate(document, trust, now=now)
        except (cert_mod.CertificateError, evidence_mod.EvidenceError) as exc:
            raise GateCertificateError(f"gate certificate {path}: {exc}") from exc
        if not result.ok:
            raise GateCertificateError(f"gate certificate {path} does not verify: {result.reason}")
        if result.decision_recomputed != _REQUIRED_DECISION:
            raise GateCertificateError(
                f"gate certificate {path} records decision {result.decision_recomputed}, "
                f"not {_REQUIRED_DECISION}; only an open gate admits a training run"
            )
        identities.append(identity)
    return identities


__all__ = [
    "GATE_CERTIFICATE_SCHEMA",
    "MAX_FILE_BYTES",
    "GateCertificateError",
    "certificate_identity",
    "verify_gate_certificates",
]
