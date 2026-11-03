# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Atheris coverage-guided fuzz harness for the lineage ledger.

Writes arbitrary bytes as a JSON-L ledger file and runs ``verify_chain`` and
``Ledger`` (tail load) on it. The invariant under test is the fail-closed
contract: a malformed, tampered or truncated file raises only ``LedgerError``,
and a file that verifies is returned as contiguous entries. Seed it with real
ledgers (``fuzz/make_corpus.py``).

Linux only (Atheris ships no macOS wheel); CI runs it on Python 3.12.
"""

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from presidio_ai.ledger import Ledger, LedgerError, verify_chain

KEY = "fuzz-ledger-key"
PATH = Path(tempfile.mkdtemp(prefix="pai-fuzz-")) / "ledger.jsonl"


def TestOneInput(data: bytes) -> None:
    PATH.write_bytes(data)
    try:
        entries = verify_chain(PATH, key=KEY)
    except LedgerError:
        pass
    else:
        assert [e.seq for e in entries] == list(range(len(entries)))
    try:
        Ledger(PATH, key=KEY)
    except LedgerError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
