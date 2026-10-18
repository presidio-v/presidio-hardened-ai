"""Decimal-string encoding of non-integer numbers (family ADR-0005 draft)."""

from __future__ import annotations

import re
from decimal import Decimal
from pathlib import Path

import pytest

from presidio_ai.dp.accountant import DPResult, dpsgd_epsilon
from presidio_ai.hashing import canonical_json
from presidio_ai.numeric import (
    PRECISION,
    decimal_string,
    encode_field,
    is_decimal_string,
)

SCHEMA_DOC = Path(__file__).resolve().parents[1] / "docs" / "schemas" / "signed-payloads.md"


@pytest.mark.parametrize(
    ("value", "precision", "expected"),
    [
        (1e-5, 18, "0.00001"),  # never "1e-05"
        (12.0, 6, "12"),  # no trailing zeros or point
        (12, 2, "12"),
        (Decimal("0.125"), 2, "0.12"),  # half-even: down to even
        (Decimal("0.135"), 2, "0.14"),  # half-even: up to even
        (Decimal("2.5"), 0, "2"),
        (Decimal("3.5"), 0, "4"),
        (Decimal("-0.001"), 2, "0"),  # never "-0"
        (-12.5, 6, "-12.5"),
        ("1E+3", 6, "1000"),
        (Decimal("123456789.987654321"), 6, "123456789.987654"),
        (0.1, 12, "0.1"),
        (1.6609311216485523, 12, "1.660931121649"),
        (256.0, 6, "256"),
        (1.25, 6, "1.25"),
    ],
)
def test_decimal_string(value, precision, expected):
    out = decimal_string(value, precision)
    assert out == expected
    assert is_decimal_string(out, precision)


def test_float_rounds_from_its_exact_binary_value():
    # 2.675 is 2.67499999999999982236431605997495353221893310546875 in binary.
    assert decimal_string(2.675, 2) == "2.67"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -float("inf"), "NaN", "sNaN", "x"])
def test_non_finite_and_non_numbers_rejected(bad):
    with pytest.raises(ValueError):
        decimal_string(bad, 6)


@pytest.mark.parametrize("bad", [True, None, [1.0]])
def test_non_numeric_types_rejected(bad):
    with pytest.raises(TypeError):
        decimal_string(bad, 6)


def test_negative_precision_rejected():
    with pytest.raises(ValueError):
        decimal_string(1.0, -1)


@pytest.mark.parametrize(
    ("text", "precision", "valid"),
    [
        ("0", 6, True),
        ("-0.5", 6, True),
        ("1e-05", 6, False),
        ("12.0", 6, False),
        ("5.", 6, False),
        (".5", 6, False),
        ("01.5", 6, False),
        ("+1", 6, False),
        ("-0", 6, False),
        ("0.0000001", 6, False),
        ("1\n", 6, False),
        ("１", 6, False),
        (12, 6, False),
        ("1" * 513, 6, False),
    ],
)
def test_is_decimal_string(text, precision, valid):
    assert is_decimal_string(text, precision) is valid


def test_nonzero_fields_refuse_to_round_to_zero():
    with pytest.raises(ValueError, match="rounds to 0"):
        encode_field("delta", 1e-19)
    with pytest.raises(ValueError, match="rounds to 0"):
        encode_field("sample_rate", 1e-20)
    assert encode_field("sample_rate", 0.0) == "0"  # an exact zero is honest
    assert encode_field("epsilon", 1e-13) == "0"  # epsilon has no such guard


def test_unknown_field_has_no_precision():
    with pytest.raises(KeyError):
        encode_field("temperature", 1.0)


def test_dp_signed_dict_is_float_free_and_canonical():
    result = dpsgd_epsilon(noise_multiplier=1.0, sample_rate=0.01, steps=500, delta=1e-5)
    signed = result.signed_dict()
    assert not any(isinstance(v, float) for v in signed.values())
    assert signed["delta"] == "0.00001"
    assert signed["sample_rate"] == "0.01"
    assert signed["noise_multiplier"] == "1"
    assert signed["steps"] == 500
    for key in ("epsilon", "delta", "optimal_order", "noise_multiplier", "sample_rate"):
        assert is_decimal_string(signed[key], PRECISION[key]), key
    canonical_json(signed)  # does not raise


def test_optimal_order_is_always_a_string():
    base = dict(epsilon=1.0, delta=1e-5, noise_multiplier=1.0, sample_rate=0.1, steps=1)
    assert DPResult(optimal_order=8, **base).signed_dict()["optimal_order"] == "8"
    assert DPResult(optimal_order=128.0, **base).signed_dict()["optimal_order"] == "128"
    assert DPResult(optimal_order=1.25, **base).signed_dict()["optimal_order"] == "1.25"


def test_schema_doc_declares_every_precision():
    doc = SCHEMA_DOC.read_text(encoding="utf-8")
    declared = {
        m.group(1): int(m.group(2))
        for m in re.finditer(r"^\| `(\w+)` \| decimal string \| (\d+) \|", doc, re.MULTILINE)
    }
    assert declared == PRECISION
