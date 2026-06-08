"""presidio-hardened-ai — training-time privacy controls for the presidio-hardened-* suite.

P1 (v0.1.0) ships the **evidence layer**: a tamper-evident, append-only privacy
ledger; PII discovery/scrub on ingest; and signed ``EvidenceRef`` export that
populates the IKI-Gov governance spine (``presidio-hardened-ikigov-assess`` v0.13.0
"external evidence-backed affirmation").

Design invariant — *the ledger holds commitments, never content*: only hashes,
counts, and structural metadata are recorded, never raw PII or organisational data.
"""

from __future__ import annotations

__version__ = "0.3.0"

from presidio_ai.dp import DPResult, DPSGDConfig, EpsilonBudget, dpsgd_epsilon, plan_privacy
from presidio_ai.evidence import (
    EvidenceRef,
    build_dp_evidence,
    build_ingest_evidence,
    sign_evidence,
    verify_evidence,
)
from presidio_ai.ingest import IngestResult, ingest_records
from presidio_ai.ledger import Ledger, LedgerEntry, verify_chain
from presidio_ai.pii import PIIScrubber, ScrubResult

__all__ = [
    "__version__",
    "Ledger",
    "LedgerEntry",
    "verify_chain",
    "PIIScrubber",
    "ScrubResult",
    "IngestResult",
    "ingest_records",
    "EvidenceRef",
    "build_ingest_evidence",
    "build_dp_evidence",
    "sign_evidence",
    "verify_evidence",
    "DPResult",
    "DPSGDConfig",
    "EpsilonBudget",
    "dpsgd_epsilon",
    "plan_privacy",
]
