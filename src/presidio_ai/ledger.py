"""Tamper-evident, append-only privacy ledger (HMAC-chained JSON-L).

Each entry is one JSON object per line. Its ``entry_hash`` is the HMAC-SHA256 over
the canonical encoding of ``(canon, seq, timestamp, event, payload, prev_hash)``; the
first entry chains from a fixed genesis.

``canon`` names the canonicaliser the MAC was computed over. Entries written since
0.31 carry ``canon: 1`` (strict profile, floats rejected) and the tag is itself
covered by the MAC, so it cannot be stripped. Entries without the tag were written
before 0.31; since 0.32 they fail verification (see ``MIGRATION.md``). Anyone without
the key who inserts, reorders, edits or deletes an *interior* entry breaks the chain,
and :func:`verify_chain` detects it.

Dropping trailing entries, or the whole file, leaves a valid shorter chain. That is
detected only against an **anchor**, a ``(seq, entry_hash)`` known from elsewhere: the
live :class:`Ledger` object (which :class:`~presidio_ai.dp.budget.EpsilonBudget` uses by
default), the O5 head in a signed evidence export, or an external store. Whoever holds
the key can rewrite the whole chain; only signed exports held by others constrain that.

Invariant: ``payload`` carries **commitments and structural metadata only** — hashes,
counts, identifiers — never raw PII or organisational content. Callers are responsible
for honouring this; :mod:`presidio_ai.ingest` does so by construction.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from presidio_ai.hashing import (
    CANON_STRICT,
    CanonicalError,
    constant_time_equals,
    hmac_hex,
)

GENESIS_HASH = "0" * 64
_KEY_ENV = "PRESIDIO_AI_LEDGER_KEY"


class LedgerError(RuntimeError):
    """Raised when the ledger chain fails verification or is misconfigured."""


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    timestamp: str  # ISO-8601 UTC
    event: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str
    canon: int | None = None  # None: untagged pre-0.31 entry (rejected by verify_chain)

    def signed_view(self) -> dict[str, Any]:
        """The fields covered by ``entry_hash`` (everything except the hash itself)."""
        view: dict[str, Any] = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event": self.event,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }
        if self.canon is not None:
            view["canon"] = self.canon
        return view

    def to_record(self) -> dict[str, Any]:
        """The stored JSON-L object (an untagged entry stays untagged)."""
        record = asdict(self)
        if self.canon is None:
            record.pop("canon")
        return record


def _resolve_key(key: bytes | str | None) -> bytes:
    if key is None:
        env = os.environ.get(_KEY_ENV)
        if not env:
            raise LedgerError(
                f"No ledger key provided and {_KEY_ENV} is unset. "
                "A keyed MAC is required so the chain is tamper-evident."
            )
        key = env
    return key.encode("utf-8") if isinstance(key, str) else key


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Ledger:
    """Append-only, HMAC-chained JSON-L ledger backed by a file.

    The file is created ``0600`` and its directory ``0700`` (family convention:
    the ledger is integrity-sensitive even though it holds no content).
    """

    def __init__(self, path: str | Path, key: bytes | str | None = None) -> None:
        self.path = Path(path)
        self._key = _resolve_key(key)
        self._seq, self._last_hash = self._load_tail()

    def _load_tail(self) -> tuple[int, str]:
        """Return (next_seq, last_entry_hash) without verifying the whole chain."""
        if not self.path.exists():
            return 0, GENESIS_HASH
        last: LedgerEntry | None = None
        for last in self._iter_entries():  # noqa: B007 - we want the final value
            pass
        if last is None:
            return 0, GENESIS_HASH
        return last.seq + 1, last.entry_hash

    def _iter_entries(self) -> Iterator[LedgerEntry]:
        import json

        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                yield LedgerEntry(**raw)

    def append(self, event: str, payload: dict[str, Any] | None = None) -> LedgerEntry:
        """Append an entry and return it. ``payload`` must be commitments-only."""
        if not event or not isinstance(event, str):
            raise LedgerError("event must be a non-empty string")
        payload = dict(payload or {})
        signed = {
            "seq": self._seq,
            "timestamp": _utc_now(),
            "event": event,
            "payload": payload,
            "prev_hash": self._last_hash,
            "canon": CANON_STRICT,
        }
        try:
            entry_hash = hmac_hex(self._key, signed)
        except CanonicalError as exc:
            raise LedgerError(f"ledger payload for {event!r} is not canonical: {exc}") from exc
        entry = LedgerEntry(entry_hash=entry_hash, **signed)
        self._write(entry)
        self._seq += 1
        self._last_hash = entry_hash
        return entry

    def _write(self, entry: LedgerEntry) -> None:
        import json

        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        new = not self.path.exists()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_record(), ensure_ascii=False, allow_nan=False) + "\n")
        if new:
            os.chmod(self.path, 0o600)

    def entries(self) -> list[LedgerEntry]:
        """Read all entries (no verification — use :func:`verify_chain` for that)."""
        return list(self._iter_entries()) if self.path.exists() else []

    @property
    def head_hash(self) -> str:
        """The most recent entry hash (or genesis for an empty ledger)."""
        return self._last_hash

    @property
    def anchor(self) -> tuple[int, str] | None:
        """``(seq, entry_hash)`` of the last entry this object loaded or wrote, or None."""
        return None if self._seq == 0 else (self._seq - 1, self._last_hash)


def verify_chain(
    path: str | Path,
    key: bytes | str | None = None,
    *,
    anchor: tuple[int, str] | None = None,
    min_entries: int = 0,
    missing_ok: bool = False,
) -> list[LedgerEntry]:
    """Verify the full ledger chain, returning the entries on success.

    Raises :class:`LedgerError` on the first broken link: a mismatched recomputed
    MAC, a non-contiguous ``seq``, or a ``prev_hash`` that does not match the prior
    entry's hash. Also raises when the file is missing (unless ``missing_ok``), when
    fewer than ``min_entries`` entries remain, or when ``anchor = (seq, entry_hash)`` is
    given and entry ``seq`` is absent or has a different hash (truncated, replaced or
    rolled back). The chain may grow past the anchor.
    """
    resolved = _resolve_key(key)
    path = Path(path)
    if anchor is not None:
        a_seq, a_hash = anchor
        if not isinstance(a_seq, int) or isinstance(a_seq, bool) or a_seq < 0:
            raise LedgerError("anchor seq must be a non-negative integer")
        min_entries = max(min_entries, a_seq + 1)
    if not path.exists():
        if missing_ok and min_entries == 0:
            return []
        raise LedgerError(f"ledger {path} is missing")

    ledger = Ledger.__new__(Ledger)  # iterate without re-reading the tail
    ledger.path = path
    ledger._key = resolved

    entries = list(ledger._iter_entries())
    prev = GENESIS_HASH
    for i, entry in enumerate(entries):
        if entry.seq != i:
            raise LedgerError(f"non-contiguous seq at position {i}: got {entry.seq}")
        if entry.prev_hash != prev:
            raise LedgerError(f"broken link at seq {entry.seq}: prev_hash mismatch")
        if entry.canon is None:
            raise LedgerError(
                f"untagged pre-0.31 entry at seq {entry.seq}: no longer verifiable "
                "(support removed in 0.32, see MIGRATION.md)"
            )
        if entry.canon != CANON_STRICT or isinstance(entry.canon, bool):
            raise LedgerError(f"unsupported canon tag at seq {entry.seq}: {entry.canon!r}")
        try:
            recomputed = hmac_hex(resolved, entry.signed_view(), canon=entry.canon)
        except CanonicalError as exc:
            raise LedgerError(f"unverifiable entry at seq {entry.seq}: {exc}") from exc
        if not constant_time_equals(recomputed, entry.entry_hash):
            raise LedgerError(f"tampered entry at seq {entry.seq}: MAC mismatch")
        prev = entry.entry_hash
    if len(entries) < min_entries:
        raise LedgerError(
            f"ledger truncated: {len(entries)} entries, expected at least {min_entries}"
        )
    if anchor is not None and not constant_time_equals(entries[anchor[0]].entry_hash, anchor[1]):
        raise LedgerError(f"ledger does not match its anchor at seq {anchor[0]} (rolled back?)")
    return entries
