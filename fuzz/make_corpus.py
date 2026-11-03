# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Write seed inputs for the fuzz harnesses into a corpus directory.

Seeds are real artefacts: a verifying ledger (with the harness key), a ledger
cut short, a signed submission, signed close/read commands and valid validator
inputs, so coverage starts from the accepted paths.

Usage: python fuzz/make_corpus.py fuzz/corpus
"""

import json
import sys
import tempfile
from pathlib import Path

from presidio_ai.evidence import generate_ed25519_keypair
from presidio_ai.fl.transport import encode_command, encode_submission
from presidio_ai.ledger import Ledger

LEDGER_KEY = "fuzz-ledger-key"  # matches fuzz_ledger.py


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger.jsonl"
        ledger = Ledger(path, key=LEDGER_KEY)
        ledger.append("data-ingested", {"n_records": 3, "content_hash": "ab" * 32})
        ledger.append("dp-charged", {"epsilon": "1.25", "delta": "0.00001"})
        data = path.read_bytes()
    seeds = {
        "ledger-valid": data,
        "ledger-truncated": data.splitlines(keepends=True)[0],
        "ledger-empty": b"",
    }
    priv, _ = generate_ed25519_keypair()
    seeds["submission"] = json.dumps(
        encode_submission("A", "r1", [1, 2], private_key_hex=priv)
    ).encode()
    for action in ("close", "read"):
        seeds[f"command-{action}"] = json.dumps(
            encode_command("coord", "r1", action, private_key_hex=priv)
        ).encode()
    seeds["parents"] = json.dumps(["ab" * 16, "cd" * 16]).encode()
    seeds["silo-id"] = b"bank-01.eu"
    seeds["decimal"] = b'"0.00001"'
    for name, blob in seeds.items():
        (out / name).write_bytes(blob)


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "fuzz/corpus"))
