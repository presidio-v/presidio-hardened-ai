"""PII discovery and redaction on ingest.

Two modes, mirroring ``presidio-hardened-x402``:

* ``regex`` (default, zero-setup) — structured identifiers via curated patterns.
* ``nlp`` — Microsoft Presidio + spaCy NER for unstructured entities (PERSON,
  LOCATION, ...). Imported lazily; falls back to ``regex`` if the extra is absent,
  so the package never hard-fails on a missing model.

Scrubbing is the *first* line of defence; differential privacy (a later phase) is
the mathematical backstop for whatever detection misses. Detection counts — never
the matched values — are what flow onward to the ledger.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

DEFAULT_ENTITIES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "IP_ADDRESS",
)

# Overlap priority (lower wins). Specific structured identifiers must beat the
# deliberately-generic PHONE_NUMBER matcher when they cover the same span, so an SSN
# or card number is never mislabelled (and under-redacted) as a phone number.
_PRIORITY: dict[str, int] = {
    "EMAIL_ADDRESS": 0,
    "US_SSN": 1,
    "CREDIT_CARD": 1,
    "IBAN_CODE": 1,
    "IP_ADDRESS": 2,
    "PHONE_NUMBER": 3,
}

# Curated, conservative patterns. Precision is favoured over recall: DP is the
# backstop, so a false negative is bounded downstream while a false positive would
# corrupt training data.
_PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL_ADDRESS": re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    "PHONE_NUMBER": re.compile(
        r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]\d{2,4}){1,3}(?!\d)"
    ),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "IBAN_CODE": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


class PIIBlockedError(RuntimeError):
    """Raised when PII is detected and the configured action is ``block``."""


@dataclass(frozen=True)
class ScrubResult:
    """Outcome of scrubbing one text. ``counts`` and ``total`` are ledger-safe;
    ``text`` is the redacted output and is never written to the ledger."""

    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class PIIScrubber:
    def __init__(
        self,
        entities: tuple[str, ...] = DEFAULT_ENTITIES,
        action: str = "redact",
        mode: str = "regex",
    ) -> None:
        if action not in {"redact", "block", "warn"}:
            raise ValueError(f"unknown action: {action!r}")
        if mode not in {"regex", "nlp"}:
            raise ValueError(f"unknown mode: {mode!r}")
        self.entities = tuple(entities)
        self.action = action
        self.mode = mode
        self._analyzer = self._load_analyzer() if mode == "nlp" else None

    def _load_analyzer(self):  # pragma: no cover - exercised only with the nlp extra
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError:
            return None
        return AnalyzerEngine()

    @property
    def effective_mode(self) -> str:
        """``nlp`` only if the analyzer actually loaded, else ``regex``."""
        return "nlp" if self._analyzer is not None else "regex"

    def _detect(self, text: str) -> list[tuple[int, int, str]]:
        if self._analyzer is not None:  # pragma: no cover - needs the nlp extra
            results = self._analyzer.analyze(text=text, entities=list(self.entities), language="en")
            return [(r.start, r.end, r.entity_type) for r in results]
        spans: list[tuple[int, int, str]] = []
        for entity in self.entities:
            pattern = _PATTERNS.get(entity)
            if pattern is None:
                continue
            for m in pattern.finditer(text):
                if m.group().strip():
                    spans.append((m.start(), m.end(), entity))
        return _resolve_overlaps(spans)

    def scrub(self, text: str) -> ScrubResult:
        """Detect PII in ``text`` and apply the configured action."""
        if not text:
            return ScrubResult(text=text, counts={})
        spans = self._detect(text)
        counts = dict(Counter(entity for _, _, entity in spans))

        if not spans:
            return ScrubResult(text=text, counts={})
        if self.action == "block":
            raise PIIBlockedError(f"PII detected ({sum(counts.values())} span(s)); action=block")
        if self.action == "warn":
            return ScrubResult(text=text, counts=counts)

        out, cursor = [], 0
        for start, end, entity in sorted(spans):
            out.append(text[cursor:start])
            out.append(f"<{entity}>")
            cursor = end
        out.append(text[cursor:])
        return ScrubResult(text="".join(out), counts=counts)


def _resolve_overlaps(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Resolve overlapping detections by entity priority, then span length.

    Greedy interval selection over all candidates ranked best-first: higher-priority
    entity wins, ties broken by the longer span. Accepted spans never overlap.
    """
    chosen: list[tuple[int, int, str]] = []
    ranked = sorted(spans, key=lambda s: (_PRIORITY.get(s[2], 99), -(s[1] - s[0]), s[0]))
    for start, end, entity in ranked:
        if all(end <= cs or start >= ce for cs, ce, _ in chosen):
            chosen.append((start, end, entity))
    return sorted(chosen)
