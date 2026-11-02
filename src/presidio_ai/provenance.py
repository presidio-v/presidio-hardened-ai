"""Provenance ``parents`` for evidence payloads (presidio-evidence ADR-0002).

A payload names the upstream evidence it was produced under (for example the ikigov
gate certificate that authorised a training run, or the ingest record of its
dataset) by listing their content hashes in a top-level ``parents`` array *inside*
the hashed content, so rewiring lineage breaks the hash and the signature.

Rules implemented here:

* **P2** every entry is lowercase hex, ``^[0-9a-f]{8,128}$``; a malformed entry is
  rejected (fail closed, nothing is emitted);
* **P3** order is preserved, duplicates are dropped (first occurrence wins), and the
  field is omitted when empty, so a parent-less payload hashes exactly as it did
  before the field existed;
* **P4** producers do not resolve parents; walking the DAG is the consumer's job. The
  one exception is producer policy (family ADR-0006 G4): a gate certificate given with
  ``--gate-certificate`` is verified before its identity becomes a parent
  (:mod:`presidio_ai.gate_certificate`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

_PARENT = re.compile(r"^[0-9a-f]{8,128}$")


class ParentError(ValueError):
    """Raised on a malformed provenance parent."""


def normalize_parents(parents: Iterable[str] | None) -> list[str]:
    """Validate and de-duplicate ``parents`` (order-preserving). ``None`` means none."""
    if parents is None:
        return []
    if isinstance(parents, (str, bytes)):
        raise ParentError("parents must be a sequence of hex strings, not a single string")
    out: list[str] = []
    seen: set[str] = set()
    for i, parent in enumerate(parents):
        if not isinstance(parent, str) or _PARENT.fullmatch(parent) is None:
            raise ParentError(
                f"parent #{i + 1} must be lowercase hex of 8-128 characters, got {parent!r}"
            )
        if parent not in seen:
            seen.add(parent)
            out.append(parent)
    return out


def with_parents(content: Mapping[str, Any], parents: Iterable[str] | None) -> dict[str, Any]:
    """Return ``content`` with a top-level ``parents`` field, omitted when empty."""
    if "parents" in content:
        raise ParentError("content already carries a 'parents' field")
    out = dict(content)
    normalized = normalize_parents(parents)
    if normalized:
        out["parents"] = normalized
    return out
