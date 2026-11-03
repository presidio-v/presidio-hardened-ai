"""Canonical hashing and keyed-MAC primitives shared by the ledger and evidence layers.

The canonical encoding is the family's Layer-0 **strict** profile from
``presidio-evidence`` (ADR-0001 D1): sorted keys, compact ``(",", ":")`` separators,
UTF-8 without ASCII escaping, ``allow_nan=False``, and **floats rejected at any
depth**. :func:`canonical_json` delegates the encoding to
:func:`presidio_evidence.canonical_bytes`; it only adds a JSON path to the error for
a rejected float and raises :class:`CanonicalError`. Every content hash, ledger MAC,
approval request and signing message is computed over it. The golden vectors pinned
in ``tests/vectors/`` check the library against this repository's own copy, so a
change in the library that altered any signed byte fails the tests here.

Non-integer numbers are encoded as decimal strings before they reach the encoder
(:mod:`presidio_ai.numeric`, family ADR-0005).

Up to 0.31 a frozen float-tolerant encoder verified bytes stored before 0.31
(untagged ledger entries and approvals over untagged requests). It was removed in
0.32: such records now fail closed. See ``MIGRATION.md``.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

from presidio_evidence import canonical_bytes as _library_canonical_bytes

#: Canonicalisation tag carried by ledger entries and approval requests.
CANON_STRICT = 1


class CanonicalError(ValueError):
    """Raised when a payload cannot be encoded under the strict profile."""


def _reject_floats(payload: Any, path: str = "$") -> None:
    """Name the JSON path of the first float, for a usable error message."""
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
        return _library_canonical_bytes(payload)
    except (TypeError, ValueError) as exc:
        raise CanonicalError(f"payload is not canonically encodable: {exc}") from exc


#: Same name as presidio-evidence's Layer-0 function.
canonical_bytes = canonical_json


def canonical_for(canon: int) -> Callable[[Any], bytes]:
    """Return the encoder for a stored ``canon`` tag (verification paths only).

    Only the strict tag is supported; anything else, including an untagged
    pre-0.31 record, fails closed.
    """
    if canon == CANON_STRICT and not isinstance(canon, bool):
        return canonical_json
    raise CanonicalError(f"unsupported canon tag: {canon!r}")


def sha256_hex(payload: Any) -> str:
    """Content hash (sha256, hex) over the strict canonical encoding of ``payload``."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def sha256_bytes_hex(data: bytes) -> str:
    """sha256 (hex) over raw bytes, for commitments to data rather than to payloads."""
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, payload: Any, *, canon: int = CANON_STRICT) -> str:
    """Keyed MAC (HMAC-SHA256, hex) over the canonical encoding of ``payload``."""
    return hmac.new(key, canonical_for(canon)(payload), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe comparison of two hex digests.

    Both sides are compared as UTF-8 bytes, so an attacker-supplied value with non-ASCII
    characters (or a lone surrogate from JSON) compares unequal instead of raising.
    """
    return hmac.compare_digest(
        a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass")
    )
