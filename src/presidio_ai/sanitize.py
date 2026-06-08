"""Input validation and output sanitisation (family-wide Presidio convention).

All externally supplied scalars are bounds-checked and allow-listed before use;
free-text identifiers are HTML-escaped before they appear in any rendered output.
"""

from __future__ import annotations

import html

MAX_ID_LEN = 256
MAX_PATH_LEN = 4096
_PII_ACTIONS = {"redact", "block", "warn"}
_PII_MODES = {"regex", "nlp"}


class ValidationError(ValueError):
    """Raised when user-supplied input fails validation."""


def validate_identifier(value: str, *, what: str = "identifier") -> str:
    """Validate a use-case / source identifier: non-empty, bounded, no control bytes."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{what} must be a non-empty string")
    if len(value) > MAX_ID_LEN:
        raise ValidationError(f"{what} exceeds {MAX_ID_LEN} characters")
    if any(ord(ch) < 32 for ch in value):
        raise ValidationError(f"{what} contains control characters")
    return value


def validate_path(value: str) -> str:
    """Validate a filesystem path: non-empty, bounded, no NUL byte."""
    if not isinstance(value, str) or not value:
        raise ValidationError("path must be a non-empty string")
    if len(value) > MAX_PATH_LEN:
        raise ValidationError(f"path exceeds {MAX_PATH_LEN} characters")
    if "\x00" in value:
        raise ValidationError("path contains a null byte")
    return value


def validate_pii_action(value: str) -> str:
    if value not in _PII_ACTIONS:
        raise ValidationError(f"pii-action must be one of {sorted(_PII_ACTIONS)}")
    return value


def validate_pii_mode(value: str) -> str:
    if value not in _PII_MODES:
        raise ValidationError(f"pii-mode must be one of {sorted(_PII_MODES)}")
    return value


def escape(value: str) -> str:
    """HTML-escape a free-text value for safe inclusion in rendered output."""
    return html.escape(value, quote=True)
