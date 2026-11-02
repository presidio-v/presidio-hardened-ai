"""Structural-only security event log and a per-session abuse guard.

Mirrors the family convention (cf. ikigov ``security.log``): events record
*structural metadata only* — event name, counts, mode flags — never use-case
content, source data, PII, or ledger-ref values. The log lives at
``~/.presidio-ai/security.log`` (override with ``PRESIDIO_AI_HOME``).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_HOME_ENV = "PRESIDIO_AI_HOME"
_MAX_ENV = "PRESIDIO_AI_MAX_OPS"
_DEFAULT_MAX_OPS = 1000

_session_count = 0


def home_dir() -> Path:
    return Path(os.environ.get(_HOME_ENV, str(Path.home() / ".presidio-ai")))


def session_limit() -> int:
    try:
        return int(os.environ.get(_MAX_ENV, _DEFAULT_MAX_OPS))
    except ValueError:
        return _DEFAULT_MAX_OPS


def increment_session_count() -> int:
    global _session_count
    _session_count += 1
    return _session_count


def reset_session_count() -> None:
    global _session_count
    _session_count = 0


def log_security_event(event: dict[str, Any]) -> None:
    """Append a structural event. Best-effort: logging never breaks the operation."""
    record = {"ts": datetime.now(UTC).isoformat(), **event}
    try:
        directory = home_dir()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / "security.log"
        new = not path.exists()
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        if new:
            os.chmod(path, 0o600)
    except OSError:
        pass
