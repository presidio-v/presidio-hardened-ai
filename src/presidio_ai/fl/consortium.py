"""Per-round consortium composition (P4 / v0.13.0).

Ties the secure-aggregation core (ADR-0001) to the family's governance primitives
so that one *consortium round* is, end to end, a governed operation:

1. **Authorize the round (n-of-m MPA).** If a policy is set and the round's
   worst-case per-party epsilon meets the threshold, the round runs only after
   ``threshold`` recognised approvers have countersigned it. The authorization is
   recorded to the round ledger before any aggregation.
2. **Aggregate under secure aggregation.** Each surviving silo's (already
   DP-noised) update is masked and combined in the exact field domain; the
   coordinator recovers only the aggregate, never an individual update. Dropouts
   are recovered via Shamir reconstruction, or the round fails closed.
3. **Charge per-silo DP.** Each silo's composed ``(epsilon, delta)`` for the round
   is charged to its *own* tamper-evident ledger budget (distributed DP: privacy
   is accounted per party, the aggregate adds the secure-aggregation guarantee on
   top).
4. **Emit one signed D4 per round.** A single evidence reference commits to the
   *aggregate only* (its field-domain hash) plus the round's worst-case
   ``(epsilon, delta)`` and participation counts — never a member's update — and
   points at the round's ledger entry. Commitments only.

This is the in-process reference: the coordinator masks each update here. In a
deployment each silo masks locally with seeds from authenticated key agreement
(:mod:`presidio_ai.fl.keyagreement`) and the masked vectors arrive over the
``[mpc]`` transport; the governance flow above is identical.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from presidio_ai.dp.accountant import DPResult
from presidio_ai.dp.authorization import MPAPolicy, authorize_request, requires_authorization
from presidio_ai.dp.budget import (
    AUTHORIZED_EVENT,
    ChargeResult,
    EpsilonBudget,
    authorization_payload,
)
from presidio_ai.evidence import (
    build_consortium_evidence,
    consortium_commitment,
    export_evidence,
    sign_ed25519,
    verify_ed25519,
)
from presidio_ai.fl.commit import MODP2048_GROUP, SchnorrGroup, pedersen_commit
from presidio_ai.fl.god import deal_input, god_aggregate
from presidio_ai.fl.proof_backend import ProofBackend, get_backend
from presidio_ai.fl.robustness import RobustnessPolicy, RobustnessVerdict, rejected_round_fields
from presidio_ai.fl.robustness import evaluate as _robustness_evaluate
from presidio_ai.fl.secure_agg import DEFAULT_FRAC_BITS, PRIME, SecureAggregationSession, dequantize
from presidio_ai.fl.zk import (
    ProofError,
    prove_bounded,
    prove_commitment_equality,
    prove_l2_bounded,
    verify_bounded,
    verify_commitment_equality,
    verify_l2_bounded,
)
from presidio_ai.hashing import sha256_hex
from presidio_ai.ledger import Ledger
from presidio_ai.numeric import encode_field
from presidio_ai.provenance import normalize_parents, with_parents

CONSORTIUM_EVENT = "consortium-round"
SURVIVOR_SET_EVENT = "consortium-survivor-set"


class ConsortiumError(RuntimeError):
    """Raised on a malformed or unauthorized consortium round."""


class PartyMisbehavior(ConsortiumError):
    """An attributable misbehavior by a specific party (enables exclude-and-retry, ADR-0006)."""

    def __init__(self, party_id, message: str) -> None:
        super().__init__(message)
        self.party_id = party_id


def _per_silo_epsilon(
    dp_results: Mapping[Hashable, DPResult], parties: Iterable[Hashable]
) -> dict[str, str]:
    """Per-silo epsilon for the round ledger entry, as decimal strings."""
    return {str(p): encode_field("epsilon", dp_results[p].epsilon) for p in parties}


def _optional_decimal(name: str, value: float | None) -> str | None:
    return None if value is None else encode_field(name, value)


@dataclass(frozen=True)
class ConsortiumRoundResult:
    round_id: str
    aggregate: list[float]  # de-quantised aggregate update
    aggregate_field: list[int]  # exact field-domain aggregate (the committed value)
    survivors: list[Hashable]
    dropped: list[Hashable]
    max_epsilon: float
    delta: float
    per_silo_charge: dict[str, ChargeResult]
    approvers: list[str]  # empty if the round was below the authorization threshold
    ledger_seq: int  # the consortium-round ledger entry
    evidence_path: Path | None


def run_consortium_round(
    *,
    round_id: str,
    updates: Mapping[Hashable, Sequence[float]],
    dp_results: Mapping[Hashable, DPResult],
    session: SecureAggregationSession,
    ledger: Ledger,
    budgets: Mapping[Hashable, EpsilonBudget] | None = None,
    dropped: Sequence[Hashable] = (),
    policy: MPAPolicy | None = None,
    approvals: Mapping[str, str] | None = None,
    approver_keys: Mapping[str, str] | None = None,
    signing_key: bytes | str | None = None,
    signer: str = "presidio-hardened-ai",
    algorithm: str = "ed25519",
    evidence_path: str | Path | None = None,
    parents: Iterable[str] | None = None,
) -> ConsortiumRoundResult:
    """Run one governed secure-aggregation round. See the module docstring for the flow."""
    if not round_id:
        raise ConsortiumError("round_id must be non-empty")
    parent_list = normalize_parents(parents)  # fail closed before any side effect
    survivors = [p for p in session.party_ids if p in updates]
    if not survivors:
        raise ConsortiumError("no surviving updates to aggregate")
    missing_dp = [s for s in survivors if s not in dp_results]
    if missing_dp:
        raise ConsortiumError(f"missing DP results for survivors: {missing_dp}")
    deltas = {dp_results[s].delta for s in survivors}
    if len(deltas) != 1:
        raise ConsortiumError("all surviving silos must share one delta for the round")
    delta = deltas.pop()
    # Worst-case per-party exposure gates the round (the most privacy-costly member).
    gating = max((dp_results[s] for s in survivors), key=lambda r: r.epsilon)
    max_epsilon = gating.epsilon

    # 1. Authorize the round (n-of-m), bound to (round_id, gating privacy params).
    approvers: list[str] = []
    if requires_authorization(policy, max_epsilon):
        _req_hash, approved, _req_canon = authorize_request(
            gating,
            job_id=f"consortium/{round_id}",
            policy=policy,
            approvals=approvals or {},
            approver_keys=approver_keys or {},
        )
        approvers = list(approved)
        ledger.append(
            AUTHORIZED_EVENT,
            authorization_payload(
                job_id=f"consortium/{round_id}",
                epsilon=max_epsilon,
                threshold=policy.threshold,
                approvers=approvers,
                request_hash=_req_hash,
                request_canon=_req_canon,
            ),
        )

    # 2. Secure aggregation (exact field domain; coordinator sees only the aggregate).
    masked = {s: session.mask(s, updates[s]) for s in survivors}
    agg_field = session.aggregate_field(masked, dropped=dropped)
    aggregate = session.aggregate(masked, dropped=dropped)
    dropped_list = [p for p in session.party_ids if p not in updates]

    # 3. Charge each silo's own budget (the round is already authorized as a whole).
    per_silo_charge: dict[str, ChargeResult] = {}
    if budgets is not None:
        for s in survivors:
            budget = budgets.get(s)
            if budget is None:
                continue
            per_silo_charge[str(s)] = budget.charge(
                dp_results[s], job_id=f"consortium/{round_id}/{s}"
            )

    # 4. One commitment + ledger entry + signed D4 for the round (aggregate only).
    commitment = consortium_commitment(
        round_id=round_id,
        aggregate_field=agg_field,
        max_epsilon=max_epsilon,
        delta=delta,
        n_parties=len(session.party_ids),
        n_survivors=len(survivors),
        parents=parent_list,
    )
    entry = ledger.append(
        CONSORTIUM_EVENT,
        with_parents(
            {
                "round_id": round_id,
                "aggregate_sha256": commitment["aggregate_sha256"],
                "max_epsilon": commitment["max_epsilon"],
                "delta": commitment["delta"],
                "n_parties": len(session.party_ids),
                "n_survivors": len(survivors),
                "n_dropped": len(dropped_list),
                "per_silo_epsilon": _per_silo_epsilon(dp_results, survivors),
            },
            parent_list,
        ),
    )

    out_path: Path | None = None
    if evidence_path is not None:
        if signing_key is None:
            raise ConsortiumError("evidence_path requires a signing_key")
        refs = build_consortium_evidence(
            commitment,
            signing_key=signing_key,
            signer=signer,
            round_seq=entry.seq,
            algorithm=algorithm,
        )
        out_path = export_evidence(refs, evidence_path, use_case=f"consortium/{round_id}")

    return ConsortiumRoundResult(
        round_id=round_id,
        aggregate=aggregate,
        aggregate_field=agg_field,
        survivors=survivors,
        dropped=dropped_list,
        max_epsilon=max_epsilon,
        delta=delta,
        per_silo_charge=per_silo_charge,
        approvers=approvers,
        ledger_seq=entry.seq,
        evidence_path=out_path,
    )


# ── Malicious-security hardening (ADR-0002) ─────────────────────────────────
# Two checks turn the honest-but-curious round into one that survives a *deviating*
# coordinator or party, with security-with-abort:
#   1. a signed, ledger-anchored agreement on the survivor set (defeats the
#      coordinator-equivocation unmasking attack), and
#   2. a homomorphic check of the returned aggregate against Pedersen-committed inputs
#      (defeats a coordinator that returns a false aggregate).
# Feldman-VSS share verification (the third leg) lives in the verifiable-mode
# SecureAggregationSession and fires during reconstruction.


def survivor_set_message(round_id: str, alive: Sequence[str], *, attempt: int = 1) -> dict:
    """Canonical statement a party signs: this round, this attempt, exactly this set."""
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ConsortiumError("attempt must be an integer >= 1")
    return {"round_id": round_id, "attempt": attempt, "alive": sorted(str(a) for a in alive)}


def survivor_set_hash(round_id: str, alive: Sequence[str], *, attempt: int = 1) -> str:
    """SHA-256 (lowercase hex) of the canonical survivor-set statement."""
    return sha256_hex(survivor_set_message(round_id, alive, attempt=attempt))


def sign_survivor_set(
    round_id: str,
    alive: Sequence[str],
    *,
    party_id: str,
    private_key_hex: str,
    attempt: int = 1,
) -> str:
    """A party's Ed25519 signature over the survivor-set statement, bound to its id.

    Uses the party's long-term identity key (the same key that signs its X25519 key in
    :mod:`presidio_ai.fl.keyagreement`), so only the party can produce it and anyone with
    the public key can check it. Needs ``presidio-evidence[crypto]``. Prefer
    :class:`SurvivorSetSigner`, which also refuses to sign two different sets.
    """
    digest = survivor_set_hash(round_id, alive, attempt=attempt)
    try:
        return sign_ed25519(digest, party_id, private_key_hex)
    except ImportError as exc:  # pragma: no cover - crypto extra missing
        raise ConsortiumError("survivor-set agreement needs presidio-evidence[crypto]") from exc


class SurvivorSetSigner:
    """One party's survivor-set signer: signs at most one set per ``(round_id, attempt)``.

    This is the party-side half of the anti-equivocation defence: an honest party never
    signs two different survivor sets for the same round attempt, so a coordinator cannot
    collect ``threshold`` signatures on two sets from an honest majority. In a deployment
    each party runs its own signer; the coordinator only receives signatures.
    """

    def __init__(self, party_id: str, private_key_hex: str) -> None:
        self.party_id = str(party_id)
        self._key = private_key_hex
        self._signed: dict[tuple[str, int], str] = {}

    def __call__(self, round_id: str, alive: Sequence[str], *, attempt: int = 1) -> str:
        digest = survivor_set_hash(round_id, alive, attempt=attempt)
        prior = self._signed.get((round_id, attempt))
        if prior is not None and prior != digest:
            raise ConsortiumError(
                f"{self.party_id} already signed a different survivor set for "
                f"round {round_id!r} attempt {attempt}"
            )
        self._signed[(round_id, attempt)] = digest
        return sign_survivor_set(
            round_id, alive, party_id=self.party_id, private_key_hex=self._key, attempt=attempt
        )


def verify_survivor_set(
    round_id: str,
    alive: Sequence[str],
    *,
    signatures: Mapping[str, str],
    identity_trust: Mapping[str, str],
    threshold: int,
    eligible: Iterable[str] | None = None,
    attempt: int = 1,
) -> list[str]:
    """Return the parties that validly signed *this* survivor set; abort below threshold.

    A signature counts only if its party is in ``alive``, in ``eligible`` (the session's
    parties, when given) and in ``identity_trust``, and the Ed25519 signature verifies
    against that public key. Everything else is ignored. Verification needs public keys
    only, so the coordinator cannot mint signatures. Fail-closed.
    """
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ConsortiumError("survivor threshold must be an integer >= 1")
    alive_set = {str(a) for a in alive}
    allowed = alive_set if eligible is None else alive_set & {str(e) for e in eligible}
    digest = survivor_set_hash(round_id, alive, attempt=attempt)
    good: list[str] = []
    for party_id, sig in signatures.items():
        pid = str(party_id)
        public = identity_trust.get(pid)
        if pid not in allowed or public is None or not isinstance(sig, str):
            continue
        try:
            ok = verify_ed25519(digest, pid, sig, public)
        except ImportError as exc:  # pragma: no cover - crypto extra missing
            raise ConsortiumError("survivor-set agreement needs presidio-evidence[crypto]") from exc
        if ok:
            good.append(pid)
    if len(good) < threshold:
        raise ConsortiumError(
            f"survivor-set agreement failed for round '{round_id}' attempt {attempt}: "
            f"{len(good)} valid signature(s) over the presented set, need {threshold}"
        )
    return sorted(good)


def commit_quantized(
    q_vector: Sequence[int], *, backend: ProofBackend, rng=None
) -> tuple[list, list[int]]:
    """Per-coordinate Pedersen commitments to a vector; return (commits, randomness).

    Commitments are opaque backend objects (int for MODP, point bytes for Ristretto).
    """
    randomness = [backend.random_blinding() for _ in q_vector]
    commits = [backend.commit(v, r) for v, r in zip(q_vector, randomness, strict=True)]
    return commits, randomness


def verify_aggregate_commitment(
    aggregate_field: Sequence[int],
    party_commits: Mapping[Hashable, Sequence[Any]],
    party_randomness: Mapping[Hashable, Sequence[int]],
    *,
    backend: ProofBackend,
    prime: int = PRIME,
) -> bool:
    """Check the aggregate against the homomorphic sum of per-party input commitments.

    Parties commit to *signed* fixed-point values, so per coordinate ``k`` the product
    ``Π_i C[i][k]`` must equal ``pedersen_commit(centered(aggregate[k]), Σ_i r[i][k])``,
    where ``centered`` maps a masking-field element above ``prime/2`` to its negative.
    Holds when the true per-coordinate sum does not wrap the masking field (the same
    no-overflow operating range that correct de-quantisation already requires).
    """
    dim = len(aggregate_field)
    for k in range(dim):
        product = backend.sum([party_commits[p][k] for p in party_commits])
        r_sum = sum(party_randomness[p][k] for p in party_randomness)
        centered = (
            aggregate_field[k] - prime if aggregate_field[k] > prime // 2 else aggregate_field[k]
        )
        if product != backend.commit(centered, r_sum):
            return False
    return True


@dataclass(frozen=True)
class SecureConsortiumResult:
    round_id: str
    aggregate: list[float]
    aggregate_field: list[int]
    survivors: list[Hashable]
    survivor_signers: list[str]
    max_epsilon: float
    delta: float
    per_silo_charge: dict[str, ChargeResult]
    approvers: list[str]
    ledger_seq: int
    evidence_path: Path | None
    applied: bool = True
    robustness: RobustnessVerdict | None = None


def run_secure_consortium_round(
    *,
    round_id: str,
    updates: Mapping[Hashable, Sequence[float]],
    dp_results: Mapping[Hashable, DPResult],
    session: SecureAggregationSession,
    ledger: Ledger,
    survivor_signatures: Mapping[str, str],
    survivor_trust: Mapping[str, str],
    survivor_threshold: int,
    survivor_attempt: int = 1,
    backend: ProofBackend | None = None,
    budgets: Mapping[Hashable, EpsilonBudget] | None = None,
    policy: MPAPolicy | None = None,
    approvals: Mapping[str, str] | None = None,
    approver_keys: Mapping[str, str] | None = None,
    signing_key: bytes | str | None = None,
    signer: str = "presidio-hardened-ai",
    algorithm: str = "ed25519",
    evidence_path: str | Path | None = None,
    parents: Iterable[str] | None = None,
    clip_bound: float | None = None,
    l2_bound: float | None = None,
    robustness: RobustnessPolicy | None = None,
    previous_score: float | None = None,
    rng=None,
) -> SecureConsortiumResult:
    """A consortium round hardened against active deviation (ADR-0002, security-with-abort).

    Order of operations is abort-before-side-effects: (1) the survivor set is agreed by
    ``survivor_threshold`` signatures and anchored to the ledger; (2) inputs are
    Pedersen-committed; (3) the verifiable-mode session aggregates (Feldman-VSS-checked
    reconstruction); (4) the aggregate is checked homomorphically against the commitments —
    only then are (5) MPA authorization, per-silo DP charges, the round ledger entry, and
    the signed ``D4`` evidence performed.

    If ``clip_bound`` is given (ADR-0003), each survivor must also supply a zero-knowledge
    L∞ bounded-norm proof that every committed coordinate lies in ``[-B, B]``; a
    contribution whose proof fails, or whose update is out of bound, is rejected. This
    bounds poisoning but does not prove the accountant's L2 sensitivity (an L∞ bound
    allows L2 norm up to ``B·sqrt(dim)``), so it leaves ``sensitivity_proven`` false.

    If ``l2_bound`` is given (ADR-0005), each survivor proves ``‖x‖₂ ≤ l2_bound`` in zero
    knowledge and ``sensitivity_proven`` is recorded true. That is a DP-sensitivity claim
    only when ``l2_bound`` is the clip norm the noise was calibrated to; the ledger and the
    signed D4 commitment record the proven norm and bound so an auditor can check this.
    """
    if session.group is None:
        raise ConsortiumError("run_secure_consortium_round requires a verifiable-mode session")
    if not round_id:
        raise ConsortiumError("round_id must be non-empty")
    parent_list = normalize_parents(parents)  # fail closed before any side effect
    backend = backend if backend is not None else get_backend()
    survivors = [p for p in session.party_ids if p in updates]
    if not survivors:
        raise ConsortiumError("no surviving updates to aggregate")
    missing_dp = [s for s in survivors if s not in dp_results]
    if missing_dp:
        raise ConsortiumError(f"missing DP results for survivors: {missing_dp}")
    deltas = {dp_results[s].delta for s in survivors}
    if len(deltas) != 1:
        raise ConsortiumError("all surviving silos must share one delta for the round")
    delta = deltas.pop()

    # 1. Survivor-set agreement (defeats coordinator equivocation), anchored to the ledger
    # with the signatures themselves, so anyone holding the parties' public keys can check it.
    alive = sorted(str(s) for s in survivors)
    signers = verify_survivor_set(
        round_id,
        alive,
        signatures=survivor_signatures,
        identity_trust=survivor_trust,
        threshold=survivor_threshold,
        eligible=[str(p) for p in session.party_ids],
        attempt=survivor_attempt,
    )
    for prior in ledger.entries():  # self-consistency only: the coordinator holds this file
        if (
            prior.event == SURVIVOR_SET_EVENT
            and prior.payload.get("round_id") == round_id
            and prior.payload.get("attempt") == survivor_attempt
        ):
            raise ConsortiumError(
                f"round '{round_id}' attempt {survivor_attempt} already has a survivor set"
            )
    ledger.append(
        SURVIVOR_SET_EVENT,
        {
            "round_id": round_id,
            "attempt": survivor_attempt,
            "alive": alive,
            "threshold": survivor_threshold,
            "signers": signers,
            "signatures": {p: survivor_signatures[p] for p in signers},
            "set_hash": survivor_set_hash(round_id, alive, attempt=survivor_attempt),
        },
    )

    # 2. Commit each survivor's *signed* fixed-point input (Pedersen, additively homomorphic;
    # signed so the same commitment is range-provable and the homomorphic check composes).
    scale = 1 << session.frac_bits
    s_updates = {s: [round(v * scale) for v in updates[s]] for s in survivors}
    party_commits: dict[Hashable, list[Any]] = {}
    party_randomness: dict[Hashable, list[int]] = {}
    for s in survivors:
        party_commits[s], party_randomness[s] = commit_quantized(
            s_updates[s], backend=backend, rng=rng
        )

    # 2b. Bounded-norm gate (ADR-0003): each input is ZK-proven within the clip sensitivity,
    # against the *same* commitments, so a poisoning (out-of-norm) contribution is rejected.
    # ``sensitivity_proven`` means: every survivor's update is ZK-proven to have L2 norm at
    # most ``l2_bound``. Only the L2 gate can say that; an L∞ bound B allows L2 norm up to
    # B·sqrt(dim), so the L∞ gate bounds poisoning but proves no DP sensitivity.
    sensitivity_proven = False
    proven_norm: str | None = None
    if clip_bound is not None:
        if clip_bound <= 0:
            raise ConsortiumError("clip_bound must be > 0")
        bound_fp = round(clip_bound * scale)
        for sid in survivors:
            try:
                norm_proof = backend.prove_bounded(
                    s_updates[sid], party_randomness[sid], bound=bound_fp, rng=rng
                )
            except ProofError as exc:
                raise PartyMisbehavior(
                    sid, f"input failed bounded-norm for '{sid}' (norm > clip sensitivity): {exc}"
                ) from exc
            if not backend.verify_bounded(party_commits[sid], norm_proof, bound=bound_fp):
                raise PartyMisbehavior(sid, f"bounded-norm proof did not verify for '{sid}'")
        proven_norm = "linf"

    if l2_bound is not None:
        if l2_bound <= 0:
            raise ConsortiumError("l2_bound must be > 0")
        l2_fp = round(l2_bound * scale)
        for sid in survivors:
            try:
                l2_proof = backend.prove_l2_bounded(
                    s_updates[sid], party_randomness[sid], bound=l2_fp, rng=rng
                )
            except ProofError as exc:
                raise PartyMisbehavior(
                    sid, f"input failed L2 bound for '{sid}' (||x||2 > clip sensitivity): {exc}"
                ) from exc
            if not backend.verify_l2_bounded(party_commits[sid], l2_proof, bound=l2_fp):
                raise PartyMisbehavior(sid, f"L2 bounded-norm proof did not verify for '{sid}'")
        sensitivity_proven = True
        proven_norm = "l2"

    # 3. Secure aggregation (verifiable session: VSS-checked reconstruction).
    masked = {s: session.mask_field(s, s_updates[s]) for s in survivors}
    agg_field = session.aggregate_field(masked)

    # 4. Homomorphic aggregate check (defeats a false aggregate). Abort before side effects.
    if not verify_aggregate_commitment(
        agg_field, party_commits, party_randomness, backend=backend, prime=session.prime
    ):
        raise ConsortiumError(
            f"aggregate does not match committed inputs for round '{round_id}' (false aggregate)"
        )
    aggregate = [dequantize(v, frac_bits=session.frac_bits, prime=session.prime) for v in agg_field]

    # Robustness gate (ADR-0007): validate the aggregate before side effects; reject -> rollback.
    verdict = None
    if robustness is not None:
        verdict = _robustness_evaluate(aggregate, robustness, previous_score=previous_score)
        if not verdict.accepted:
            entry = ledger.append(
                "consortium-round-rejected",
                {
                    "round_id": round_id,
                    "mode": "secure",
                    "reason": verdict.reason,
                    **rejected_round_fields(verdict.metrics),
                    "n_survivors": len(survivors),
                },
            )
            return SecureConsortiumResult(
                round_id=round_id,
                aggregate=aggregate,
                aggregate_field=agg_field,
                survivors=survivors,
                survivor_signers=signers,
                max_epsilon=0.0,
                delta=delta,
                per_silo_charge={},
                approvers=[],
                ledger_seq=entry.seq,
                evidence_path=None,
                applied=False,
                robustness=verdict,
            )

    # 5. Governance: worst-case ε gates MPA; per-silo charge; one signed D4; commitments-only entry.
    gating = max((dp_results[s] for s in survivors), key=lambda r: r.epsilon)
    max_epsilon = gating.epsilon
    approvers: list[str] = []
    if requires_authorization(policy, max_epsilon):
        _req_hash, approved, _req_canon = authorize_request(
            gating,
            job_id=f"consortium/{round_id}",
            policy=policy,
            approvals=approvals or {},
            approver_keys=approver_keys or {},
        )
        approvers = list(approved)
        ledger.append(
            AUTHORIZED_EVENT,
            authorization_payload(
                job_id=f"consortium/{round_id}",
                epsilon=max_epsilon,
                threshold=policy.threshold,
                approvers=approvers,
                request_hash=_req_hash,
                request_canon=_req_canon,
            ),
        )

    per_silo_charge: dict[str, ChargeResult] = {}
    if budgets is not None:
        for s in survivors:
            budget = budgets.get(s)
            if budget is not None:
                per_silo_charge[str(s)] = budget.charge(
                    dp_results[s], job_id=f"consortium/{round_id}/{s}"
                )

    commitment = consortium_commitment(
        round_id=round_id,
        aggregate_field=agg_field,
        max_epsilon=max_epsilon,
        delta=delta,
        n_parties=len(session.party_ids),
        n_survivors=len(survivors),
        parents=parent_list,
        proven_norm=proven_norm,
        norm_bound=(l2_bound if proven_norm == "l2" else clip_bound) if proven_norm else None,
    )
    commit_digest = sha256_hex(
        {
            "backend": backend.name,
            "commits": {
                str(s): [backend.serialize_commitment(c) for c in party_commits[s]]
                for s in survivors
            },
        }
    )
    entry = ledger.append(
        CONSORTIUM_EVENT,
        with_parents(
            {
                "round_id": round_id,
                "aggregate_sha256": commitment["aggregate_sha256"],
                "input_commitments_sha256": commit_digest,
                "max_epsilon": commitment["max_epsilon"],
                "delta": commitment["delta"],
                "n_parties": len(session.party_ids),
                "n_survivors": len(survivors),
                "survivor_signers": signers,
                "sensitivity_proven": sensitivity_proven,
                "proven_norm": proven_norm,
                "clip_bound": _optional_decimal("clip_bound", clip_bound),
                "l2_bound": _optional_decimal("l2_bound", l2_bound),
                "per_silo_epsilon": _per_silo_epsilon(dp_results, survivors),
            },
            parent_list,
        ),
    )

    out_path: Path | None = None
    if evidence_path is not None:
        if signing_key is None:
            raise ConsortiumError("evidence_path requires a signing_key")
        refs = build_consortium_evidence(
            commitment,
            signing_key=signing_key,
            signer=signer,
            round_seq=entry.seq,
            algorithm=algorithm,
        )
        out_path = export_evidence(refs, evidence_path, use_case=f"consortium/{round_id}")

    return SecureConsortiumResult(
        round_id=round_id,
        aggregate=aggregate,
        aggregate_field=agg_field,
        survivors=survivors,
        survivor_signers=signers,
        max_epsilon=max_epsilon,
        delta=delta,
        robustness=verdict,
        per_silo_charge=per_silo_charge,
        approvers=approvers,
        ledger_seq=entry.seq,
        evidence_path=out_path,
    )


# ── Guaranteed-output-delivery interim: exclude-and-retry (ADR-0006, Option D) ──
# Liveness under a bounded number of *attributable* cheaters, with no new crypto: run the
# ADR-0002 security-with-abort round; on a PartyMisbehavior, drop that party (it becomes a
# dropout the round already tolerates) and re-run among the rest. Honest parties re-sign the
# (now smaller) survivor set each attempt. This handles malicious *parties*; a malicious
# coordinator is the case the full GOD aggregation (run_god_consortium_round) removes.


@dataclass(frozen=True)
class RetryRoundResult:
    result: SecureConsortiumResult
    excluded: list[Hashable]
    attempts: int


def run_consortium_round_with_retry(
    *,
    round_id: str,
    updates: Mapping[Hashable, Sequence[float]],
    dp_results: Mapping[Hashable, DPResult],
    session: SecureAggregationSession,
    ledger: Ledger,
    survivor_signers: Mapping[str, Callable[..., str]],
    survivor_trust: Mapping[str, str],
    survivor_threshold: int,
    max_retries: int | None = None,
    **round_kwargs: Any,
) -> RetryRoundResult:
    """Run the secure round, excluding attributable cheaters and retrying until it completes.

    ``survivor_signers`` maps each party to its own signer, typically a
    :class:`SurvivorSetSigner`; in a deployment each entry is a request to that party. On a
    :class:`PartyMisbehavior`, the offending party is excluded from the session and the
    round re-runs among the remainder as the next ``attempt``, which every honest party
    signs afresh. Bounded by ``max_retries`` (default: the party count). Fails closed if
    fewer than ``survivor_threshold`` honest parties remain or the retry budget is exhausted.

    Excluding a party and re-aggregating lets the coordinator compare two aggregates and
    learn the excluded party's update. That party is an attributed cheater, so the leak is
    limited to it; see ADR-0006 (exclude-and-retry).
    """
    remaining = dict(updates)
    excluded: list[Hashable] = []
    budget = max_retries if max_retries is not None else len(remaining)
    for attempt in range(1, budget + 2):
        alive = sorted(str(p) for p in remaining)
        if len(alive) < survivor_threshold:
            raise ConsortiumError(
                f"only {len(alive)} honest parties remain (< threshold {survivor_threshold})"
            )
        signatures = {}
        for p in alive:
            signer = survivor_signers.get(p)
            if signer is None:
                continue  # a party without a signer cannot attest; it simply does not count
            signatures[p] = signer(round_id, alive, attempt=attempt)
        try:
            result = run_secure_consortium_round(
                round_id=round_id,
                updates=remaining,
                dp_results=dp_results,
                session=session,
                ledger=ledger,
                survivor_signatures=signatures,
                survivor_trust=survivor_trust,
                survivor_threshold=survivor_threshold,
                survivor_attempt=attempt,
                **round_kwargs,
            )
        except PartyMisbehavior as exc:
            culprit = exc.party_id
            excluded.append(culprit)
            session.exclude(next(p for p in session.party_ids if str(p) == str(culprit)))
            remaining = {p: v for p, v in remaining.items() if str(p) != str(culprit)}
            continue
        return RetryRoundResult(result=result, excluded=excluded, attempts=attempt)
    raise ConsortiumError(f"retry budget exhausted after excluding {excluded}")


# ── Guaranteed-output-delivery round (ADR-0006, Option A) ───────────────────


@dataclass(frozen=True)
class GODConsortiumResult:
    round_id: str
    aggregate: list[float]
    aggregate_field: list[int]
    included: list[Hashable]
    excluded: list[Hashable]
    max_epsilon: float
    delta: float
    per_silo_charge: dict[str, ChargeResult]
    approvers: list[str]
    ledger_seq: int
    evidence_path: Path | None
    applied: bool = True
    robustness: RobustnessVerdict | None = None


def run_god_consortium_round(
    *,
    round_id: str,
    updates: Mapping[Hashable, Sequence[float]],
    dp_results: Mapping[Hashable, DPResult],
    threshold: int,
    ledger: Ledger,
    frac_bits: int = DEFAULT_FRAC_BITS,
    group: SchnorrGroup = MODP2048_GROUP,
    budgets: Mapping[Hashable, EpsilonBudget] | None = None,
    policy: MPAPolicy | None = None,
    approvals: Mapping[str, str] | None = None,
    approver_keys: Mapping[str, str] | None = None,
    signing_key: bytes | str | None = None,
    signer: str = "presidio-hardened-ai",
    algorithm: str = "ed25519",
    evidence_path: str | Path | None = None,
    parents: Iterable[str] | None = None,
    holder_overrides: Mapping[Hashable, Mapping[int, int]] | None = None,
    clip_bound: float | None = None,
    l2_bound: float | None = None,
    robustness: RobustnessPolicy | None = None,
    previous_score: float | None = None,
    rng=None,
) -> GODConsortiumResult:
    """Run a guaranteed-output-delivery round (honest majority ``n ≥ 2*threshold-1``).

    Each party VSS-shares its DP-noised update; the sum is **robustly reconstructed** so a
    misbehaving minority (bad dealers excluded, bad holders discarded) cannot halt the round
    and there is no coordinator single-point-of-failure. Then the usual governance applies:
    n-of-m MPA on the worst-case ε, per-silo DP charges, and one signed ``D4`` (aggregate
    only). ``threshold`` is the reconstruction quorum (``t+1``); honest majority means at
    least ``threshold`` honest parties.
    """
    if not round_id:
        raise ConsortiumError("round_id must be non-empty")
    parent_list = normalize_parents(parents)  # fail closed before any side effect
    parties = list(updates)
    if len(parties) < threshold:
        raise ConsortiumError(f"need >= {threshold} parties, got {len(parties)}")
    missing_dp = [p for p in parties if p not in dp_results]
    if missing_dp:
        raise ConsortiumError(f"missing DP results for: {missing_dp}")
    deltas = {dp_results[p].delta for p in parties}
    if len(deltas) != 1:
        raise ConsortiumError("all parties must share one delta for the round")
    delta = deltas.pop()

    scale = 1 << frac_bits
    n = len(parties)
    dims = {len(updates[p]) for p in parties}
    if len(dims) != 1 or 0 in dims:
        raise ConsortiumError("all parties must submit non-empty updates of one dimension")
    dim = dims.pop()
    dealt = {
        p: deal_input(
            [round(v * scale) for v in updates[p]],
            threshold=threshold,
            n_holders=n,
            group=group,
            rng=rng,
        )
        for p in parties
    }

    # Bounded-norm gate on the *shared* inputs (ADR-0006 item 4): each party's Pedersen
    # commitment + bounded-norm proof is bound to its VSS commitment (C_0 = g^s) by a
    # commitment-equality proof, so the proven norm constrains the value actually aggregated.
    # A party failing the norm or the binding is excluded; GOD still delivers over the rest.
    proven_norm = None
    norm_excluded: list[Hashable] = []
    if clip_bound is not None or l2_bound is not None:
        is_l2 = l2_bound is not None
        bound_fp = round((l2_bound if is_l2 else clip_bound) * scale)
        for party in parties:
            svals = [round(v * scale) for v in updates[party]]
            blinds = [
                (rng.randrange(group.q) if rng is not None else secrets.randbelow(group.q))
                for _ in svals
            ]
            try:
                if is_l2:
                    proof = prove_l2_bounded(svals, blinds, bound=bound_fp, group=group, rng=rng)
                else:
                    proof = prove_bounded(svals, blinds, bound=bound_fp, group=group, rng=rng)
            except ProofError:
                norm_excluded.append(party)
                continue
            ped = [pedersen_commit(v, r, group) for v, r in zip(svals, blinds, strict=True)]
            if is_l2:
                ok = verify_l2_bounded(ped, proof, bound=bound_fp, group=group)
            else:
                ok = proof.bound == bound_fp and verify_bounded(ped, proof, group=group)
            if not ok:
                norm_excluded.append(party)
                continue
            pfx = int(sha256_hex({"round": round_id, "party": str(party)}), 16) % group.q
            bound_ok = True
            for k in range(len(svals)):
                c_fel = dealt[party].commitments[k][0]  # Feldman C_0 = g^{s_k}
                eq = prove_commitment_equality(
                    ped[k], c_fel, blinds[k], group=group, prefix=pfx, rng=rng
                )
                if not verify_commitment_equality(ped[k], c_fel, eq, group=group, prefix=pfx):
                    bound_ok = False
                    break
            if not bound_ok:
                norm_excluded.append(party)
        dealt = {p: d for p, d in dealt.items() if p not in norm_excluded}
        if not dealt:
            raise ConsortiumError("all parties failed the bounded-norm gate")
        proven_norm = "l2" if is_l2 else "linf"

    # Robust reconstruction delivers the sum despite a misbehaving minority (no coordinator).
    god = god_aggregate(
        dealt,
        threshold=threshold,
        n_holders=n,
        dim=dim,
        group=group,
        holder_overrides=holder_overrides,
    )
    q = group.q
    aggregate = [(v - q if v > q // 2 else v) / scale for v in god.aggregate_field]

    # Robustness gate (ADR-0007): validate the *aggregate* candidate before any side effects;
    # a rejected round is rolled back (no charge, no evidence) and flagged on the ledger.
    verdict = None
    if robustness is not None:
        verdict = _robustness_evaluate(aggregate, robustness, previous_score=previous_score)
        if not verdict.accepted:
            entry = ledger.append(
                "consortium-round-rejected",
                {
                    "round_id": round_id,
                    "mode": "god",
                    "reason": verdict.reason,
                    **rejected_round_fields(verdict.metrics),
                    "n_parties": n,
                    "n_included": len(god.included),
                },
            )
            return GODConsortiumResult(
                round_id=round_id,
                aggregate=aggregate,
                aggregate_field=god.aggregate_field,
                included=god.included,
                excluded=list(god.excluded) + norm_excluded,
                max_epsilon=0.0,
                delta=delta,
                per_silo_charge={},
                approvers=[],
                ledger_seq=entry.seq,
                evidence_path=None,
                applied=False,
                robustness=verdict,
            )

    # Governance over the *delivered* (included) set.
    gating = max((dp_results[p] for p in god.included), key=lambda r: r.epsilon)
    max_epsilon = gating.epsilon
    approvers: list[str] = []
    if requires_authorization(policy, max_epsilon):
        _req_hash, approved, _req_canon = authorize_request(
            gating,
            job_id=f"consortium/{round_id}",
            policy=policy,
            approvals=approvals or {},
            approver_keys=approver_keys or {},
        )
        approvers = list(approved)
        ledger.append(
            AUTHORIZED_EVENT,
            authorization_payload(
                job_id=f"consortium/{round_id}",
                epsilon=max_epsilon,
                threshold=policy.threshold,
                approvers=approvers,
                request_hash=_req_hash,
                request_canon=_req_canon,
            ),
        )

    per_silo_charge: dict[str, ChargeResult] = {}
    if budgets is not None:
        for p in god.included:
            budget = budgets.get(p)
            if budget is not None:
                per_silo_charge[str(p)] = budget.charge(
                    dp_results[p], job_id=f"consortium/{round_id}/{p}"
                )

    commitment = consortium_commitment(
        round_id=round_id,
        aggregate_field=god.aggregate_field,
        max_epsilon=max_epsilon,
        delta=delta,
        n_parties=n,
        n_survivors=len(god.included),
        parents=parent_list,
        proven_norm=proven_norm,
        norm_bound=(l2_bound if proven_norm == "l2" else clip_bound) if proven_norm else None,
    )
    entry = ledger.append(
        CONSORTIUM_EVENT,
        with_parents(
            {
                "round_id": round_id,
                "mode": "god",
                "aggregate_sha256": commitment["aggregate_sha256"],
                "max_epsilon": commitment["max_epsilon"],
                "delta": commitment["delta"],
                "n_parties": n,
                "n_included": len(god.included),
                "n_excluded": len(god.excluded),
                "excluded": [str(p) for p in god.excluded],
                "honest_majority_threshold": threshold,
                "proven_norm": proven_norm,
                "norm_excluded": [str(p) for p in norm_excluded],
                "per_silo_epsilon": _per_silo_epsilon(dp_results, god.included),
            },
            parent_list,
        ),
    )

    out_path: Path | None = None
    if evidence_path is not None:
        if signing_key is None:
            raise ConsortiumError("evidence_path requires a signing_key")
        refs = build_consortium_evidence(
            commitment,
            signing_key=signing_key,
            signer=signer,
            round_seq=entry.seq,
            algorithm=algorithm,
        )
        out_path = export_evidence(refs, evidence_path, use_case=f"consortium/{round_id}")

    return GODConsortiumResult(
        round_id=round_id,
        aggregate=aggregate,
        aggregate_field=god.aggregate_field,
        included=god.included,
        excluded=list(god.excluded) + norm_excluded,
        max_epsilon=max_epsilon,
        delta=delta,
        per_silo_charge=per_silo_charge,
        approvers=approvers,
        ledger_seq=entry.seq,
        evidence_path=out_path,
        robustness=verdict,
    )
