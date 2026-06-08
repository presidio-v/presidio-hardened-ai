"""Canonical hashing and keyed-MAC primitives shared by the ledger and evidence layers.

Canonicalisation is deterministic JSON (sorted keys, no insignificant whitespace,
UTF-8) so that a content hash is reproducible across processes and languages — the
same property the IKI-Gov v0.9.0 evidence-pack manifest relies on.

Signatures here are HMAC-SHA256 detached MACs: the v0.9.0 baseline integrity
mechanism. A public-key scheme (sigstore/minisign) can be layered later without
changing the ``EvidenceRef`` shape.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

_ENCODING = "utf-8"


def canonical_bytes(payload: Any) -> bytes:
    """Return the deterministic canonical encoding of a JSON-serialisable value."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode(_ENCODING)


def sha256_hex(payload: Any) -> str:
    """Content hash (sha256, hex) over the canonical encoding of ``payload``."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def hmac_hex(key: bytes, payload: Any) -> str:
    """Keyed MAC (HMAC-SHA256, hex) over the canonical encoding of ``payload``."""
    return hmac.new(key, canonical_bytes(payload), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe comparison of two hex digests."""
    return hmac.compare_digest(a, b)
