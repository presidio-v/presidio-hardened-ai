"""Per-silo budget governance and signed evidence for federated runs (v0.9.0).

Closes the FL governance loop: each silo's composed (epsilon, delta) is charged to its
**own** tamper-evident ledger budget and (optionally) exported as signed D4 evidence —
the same artifacts a single-node ``dp-train`` produces, now per silo. A consortium can
then feed each silo's evidence into an IKI-Gov assessment independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from presidio_ai.dp.budget import ChargeResult, EpsilonBudget
from presidio_ai.evidence import build_dp_evidence, export_evidence
from presidio_ai.fl.coordinator import FederatedResult
from presidio_ai.ledger import Ledger


@dataclass(frozen=True)
class SiloGovernance:
    client_id: str
    charge: ChargeResult
    evidence_path: Path | None


def charge_federated(
    result: FederatedResult,
    *,
    total_epsilon: float,
    ledger_dir: str | Path,
    key: bytes | str,
    evidence_dir: str | Path | None = None,
    signer: str = "presidio-hardened-ai",
    algorithm: str = "ed25519",
    signing_key: bytes | str | None = None,
) -> dict[str, SiloGovernance]:
    """Charge each silo's epsilon to its own ledger budget; optionally export D4 evidence.

    Each silo ``<cid>`` gets ``ledger_dir/<cid>.jsonl`` (its budget ledger) and, when
    ``evidence_dir`` is set, ``evidence_dir/<cid>.evidence.json``. The signing key
    defaults to the ledger ``key`` for HMAC; Ed25519 (the default) needs an explicit
    ``signing_key`` (private hex). Per-silo budgets are independent.
    """
    ledger_dir = Path(ledger_dir)
    ledger_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, SiloGovernance] = {}
    for client_id, dp_result in result.per_client_epsilon.items():
        ledger = Ledger(ledger_dir / f"{client_id}.jsonl", key=key)
        budget = EpsilonBudget(total_epsilon, dp_result.delta, ledger)
        charge = budget.charge(dp_result, job_id=f"fl/{client_id}")

        evidence_path: Path | None = None
        if evidence_dir is not None:
            refs = build_dp_evidence(
                charge.result,
                signing_key=signing_key if signing_key is not None else key,
                signer=signer,
                charge_seq=charge.ledger_seq,
                algorithm=algorithm,
            )
            evidence_path = Path(evidence_dir) / f"{client_id}.evidence.json"
            export_evidence(refs, evidence_path, use_case=f"fl/{client_id}")
        out[client_id] = SiloGovernance(client_id, charge, evidence_path)
    return out
