"""Decimal-string encoding of non-integer numbers in signed payloads (family ADR-0005 draft).

The strict canonical profile rejects floats (:mod:`presidio_ai.hashing`), so every
non-integer value that enters a hashed or MAC'd payload goes through
:func:`decimal_string` exactly once, at the producer:

* the value is rounded **half-even** to the field's declared precision (maximum
  fractional digits, :data:`PRECISION`, documented in ``docs/schemas/signed-payloads.md``);
* it is written in **plain notation**: no exponent, no trailing zeros, no trailing
  decimal point, optional leading ``-``, at least one digit before the point;
* NaN and +/-Infinity are rejected. For ``delta`` and ``sample_rate`` a non-zero value
  that would round to ``"0"`` is rejected too (:data:`NONZERO_FIELDS`), since that
  would record a stronger privacy guarantee than was computed.

Verifiers compare these strings byte-wise and never parse them back to float.
Rounding uses the float's exact binary value (``Decimal(float)``), not its ``repr``,
so there is a single rounding step.
"""

from __future__ import annotations

import decimal
import math
import re
from decimal import ROUND_HALF_EVEN, Decimal

#: Per-field precision (maximum fractional digits) for the signed payload schemas in
#: ``docs/schemas/signed-payloads.md``. Keep the two in lockstep (a test checks this).
PRECISION: dict[str, int] = {
    "epsilon": 12,
    "max_epsilon": 12,
    "noise_multiplier": 12,
    "delta": 18,
    "sample_rate": 18,
    "optimal_order": 6,
    "score": 12,
    "clip_bound": 12,
    "l2_bound": 12,
    "norm_bound": 12,
}

#: Fields where a non-zero value must not round to ``"0"``: recording ``delta = "0"``
#: would claim pure DP, and ``sample_rate = "0"`` would claim no data was touched.
#: This is a schema-level producer check on top of the ADR-0005 encoding.
NONZERO_FIELDS: frozenset[str] = frozenset({"delta", "sample_rate"})

#: Family string bound for decimal strings (ADR-0005 draft).
MAX_LENGTH = 512

_PLAIN = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?")
_CONTEXT = decimal.Context(prec=MAX_LENGTH, rounding=ROUND_HALF_EVEN)


def _to_decimal(value: float | int | Decimal | str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal, str)):
        raise TypeError(f"expected a real number, got {type(value).__name__}")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"non-finite value {value!r} cannot be encoded (NaN/Infinity)")
    try:
        exact = Decimal(value)
    except decimal.InvalidOperation as exc:
        raise ValueError(f"not a number: {value!r}") from exc
    if not exact.is_finite():
        raise ValueError(f"non-finite value {value!r} cannot be encoded (NaN/Infinity)")
    return exact


def decimal_string(value: float | int | Decimal | str, precision: int) -> str:
    """Encode ``value`` as a plain-notation decimal string rounded half-even.

    Floats are taken at their exact binary value (one rounding step). Strings are
    parsed as decimal literals (``"1e-05"`` is accepted as input, never emitted).
    """
    if not isinstance(precision, int) or isinstance(precision, bool) or precision < 0:
        raise ValueError("precision must be a non-negative integer")
    exact = _to_decimal(value)
    rounded = exact.quantize(Decimal(1).scaleb(-precision), context=_CONTEXT)
    text = format(rounded, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text == "-0":
        text = "0"
    return text


def encode_field(name: str, value: float | int | Decimal) -> str:
    """Encode a schema field by name using its declared precision."""
    try:
        precision = PRECISION[name]
    except KeyError as exc:
        raise KeyError(f"no declared precision for field {name!r}") from exc
    text = decimal_string(value, precision)
    if name in NONZERO_FIELDS and text == "0" and not _to_decimal(value).is_zero():
        raise ValueError(
            f"{name}={value!r} rounds to 0 at {precision} fractional digits; "
            "refusing to record a stronger guarantee than was computed"
        )
    return text


def is_decimal_string(text: object, precision: int | None = None) -> bool:
    """Verifier-side grammar check (byte-wise, never a float parse)."""
    if not isinstance(text, str) or len(text) > MAX_LENGTH or text == "-0":
        return False
    if _PLAIN.fullmatch(text) is None:
        return False
    if precision is not None:
        _, _, fraction = text.partition(".")
        return len(fraction) <= precision
    return True
