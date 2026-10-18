"""Canonical hashing and keyed-MAC primitives shared by the ledger and evidence layers.

Two canonicalisers live here, and only one of them may produce new bytes:

* :func:`canonical_json` is the family's Layer-0 **strict** profile (presidio-evidence
  ADR-0001 D1): sorted keys, compact ``(",", ":")`` separators, UTF-8 without ASCII
  escaping, ``allow_nan=False``, and **floats rejected at any depth**. Every new
  content hash, ledger MAC, approval request and signing message is computed over
  it. Conformance is pinned by ``tests/vectors/canonical-json`` (copied from
  presidio-evidence), so the planned import swap (presidio-evidence MIGRATION step 2)
  changes no signed bytes. Non-integer numbers are encoded as decimal strings before
  they reach it (:mod:`presidio_ai.numeric`, family ADR-0005 draft).
* :func:`_legacy_canonical_v0` is a frozen copy of the pre-0.31 encoder, which let
  Python floats through. It exists **only** to verify bytes stored before 0.31: ledger
  entries without a ``canon`` tag and approvals over an untagged request. Nothing new
  is ever encoded with it, and stored bytes are never rewritten. Removal is tracked in
  ``MIGRATION.md``.

For float-free payloads the two encoders are byte-identical, so every existing
string-only signature (evidence signing messages, approval countersignatures,
survivor-set MACs) verifies unchanged under the strict profile.

Signatures here are HMAC-SHA256 detached MACs: the v0.9.0 baseline integrity
mechanism. A public-key scheme (sigstore/minisign) can be layered later without
changing the ``EvidenceRef`` shape.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from typing import Any

_ENCODING = "utf-8"

#: Canonicalisation tag carried by new ledger entries and approval requests.
CANON_STRICT = 1
#: Implicit tag of untagged (pre-0.31) records.
CANON_LEGACY = 0


class CanonicalError(ValueError):
    """Raised when a payload cannot be encoded under the strict profile."""


def _reject_floats(payload: Any, path: str = "$") -> None:
    if isinstance(payload, float):
        raise CanonicalError(
            f"float at {path} is not permitted in canonical payloads (strict profile); "
            "encode it as a decimal string (presidio_ai.numeric.decimal_string)"
        )
    if isinstance(payload, dict):
        for key, value in payload.items():
            _reject_floats(key, f"{path}.<key>")
            _reject_floats(value, f"{path}.{key}")
    elif isinstance(payload, (list, tuple)):
        for i, value in enumerate(payload):
            _reject_floats(value, f"{path}[{i}]")


def canonical_json(payload: Any) -> bytes:
    """Strict Layer-0 canonical encoding of ``payload`` (floats and NaN rejected)."""
    _reject_floats(payload)
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode(_ENCODING)
    except (TypeError, ValueError) as exc:
        raise CanonicalError(f"payload is not canonically encodable: {exc}") from exc


# Same name as presidio-evidence's Layer-0 function, so the MIGRATION step-2 import swap
# is a drop-in replacement.
canonical_bytes = canonical_json


def _legacy_canonical_v0(payload: Any) -> bytes:
    """FROZEN pre-0.31 encoder. Verify-only: never use it to produce new bytes.

    Byte-for-byte what ``canonical_bytes`` returned up to 0.30.0 (floats encoded with
    Python ``repr``, NaN allowed). Do not edit: stored MACs and approvals depend on it.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode(_ENCODING)


def canonical_for(canon: int) -> Callable[[Any], bytes]:
    """Return the encoder for a stored ``canon`` tag (verification paths only)."""
    if canon == CANON_STRICT and not isinstance(canon, bool):
        return canonical_json
    if canon == CANON_LEGACY and not isinstance(canon, bool):
        return _legacy_canonical_v0
    raise CanonicalError(f"unsupported canon tag: {canon!r}")


def sha256_hex(payload: Any) -> str:
    """Content hash (sha256, hex) over the strict canonical encoding of ``payload``."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def sha256_bytes_hex(data: bytes) -> str:
    """sha256 (hex) over raw bytes, for commitments to data rather than to payloads."""
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, payload: Any, *, canon: int = CANON_STRICT) -> str:
    """Keyed MAC (HMAC-SHA256, hex) over the canonical encoding of ``payload``.

    ``canon`` defaults to the strict profile; pass a stored record's tag only when
    *verifying* that record.
    """
    return hmac.new(key, canonical_for(canon)(payload), hashlib.sha256).hexdigest()


def legacy_sha256_hex_v0(payload: Any) -> str:
    """Verify-only: content hash over :func:`_legacy_canonical_v0`."""
    return hashlib.sha256(_legacy_canonical_v0(payload)).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe comparison of two hex digests."""
    return hmac.compare_digest(a, b)
