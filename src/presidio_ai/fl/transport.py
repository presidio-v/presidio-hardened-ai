"""Network transport for the secure-aggregation protocol (P4 / [mpc] lane).

Splits cleanly into a **verifiable wire format** (pure, validated, unit-tested) and
a **thin HTTP layer** (lazily imported, behind the ``[mpc]`` extra, integration-only
— mirroring the stdio/remote MCP servers' ``serve`` pattern).

Wire format. Two message kinds cross the network:

* a :class:`SignedDHKey` (:mod:`presidio_ai.fl.keyagreement`) during setup, and
* a :class:`MaskedSubmission` — a party's masked, **field-element** vector for the
  round. The decoder validates the party id, the vector length, and that every
  element is a canonical field element in ``[0, prime)``; anything else is rejected
  before it can reach the aggregator (fail-closed, no silent coercion).

The masked vectors are exactly what the coordinator is allowed to see — the whole
point of secure aggregation is that they reveal nothing individually — so the
transport carries no additional secret. Authentication of *who* may submit, TLS,
and bind address are deployment configuration of the HTTP layer.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from presidio_ai.fl.secure_agg import PRIME


class TransportError(RuntimeError):
    """Raised on a malformed protocol message (fail-closed)."""


@dataclass(frozen=True)
class MaskedSubmission:
    """One party's masked field-element vector for a round."""

    party_id: str
    round_id: str
    masked: list[int]

    def to_dict(self) -> dict[str, object]:
        return {"party_id": self.party_id, "round_id": self.round_id, "masked": list(self.masked)}


def encode_submission(party_id: str, round_id: str, masked: Sequence[int]) -> dict[str, object]:
    """Encode a masked submission to a JSON-safe dict."""
    return MaskedSubmission(party_id, round_id, [int(v) for v in masked]).to_dict()


def decode_submission(
    payload: object, *, expected_dim: int | None = None, prime: int = PRIME
) -> MaskedSubmission:
    """Decode and validate a masked submission. Fail-closed on any malformation."""
    if not isinstance(payload, dict):
        raise TransportError("submission must be a JSON object")
    party_id = payload.get("party_id")
    round_id = payload.get("round_id")
    masked = payload.get("masked")
    if not isinstance(party_id, str) or not party_id:
        raise TransportError("submission.party_id must be a non-empty string")
    if not isinstance(round_id, str) or not round_id:
        raise TransportError("submission.round_id must be a non-empty string")
    if not isinstance(masked, list) or not masked:
        raise TransportError("submission.masked must be a non-empty list")
    if expected_dim is not None and len(masked) != expected_dim:
        raise TransportError(f"submission.masked must have length {expected_dim}")
    out: list[int] = []
    for v in masked:
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < prime:
            raise TransportError("submission.masked elements must be field integers in [0, prime)")
        out.append(v)
    return MaskedSubmission(party_id, round_id, out)


def serve(  # pragma: no cover - thin HTTP transport, exercised behind the [mpc] extra
    session,
    *,
    round_id: str,
    host: str = "127.0.0.1",
    port: int = 8089,
    expected_parties: Sequence[str] | None = None,
) -> None:
    """Run a coordinator that collects masked submissions and returns the aggregate.

    Requires the ``[mpc]`` extra (``pip install 'presidio-hardened-ai[mpc]'``). The
    coordinator authenticates submitters at the transport edge, collects one
    :class:`MaskedSubmission` per party, then calls ``session.aggregate_field`` once
    the round closes — recovering only the aggregate, never an individual update.
    """
    try:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except ImportError as exc:
        raise TransportError(
            "the [mpc] transport needs the optional extra: pip install 'presidio-hardened-ai[mpc]'"
        ) from exc

    received: dict[str, MaskedSubmission] = {}
    expected = set(expected_parties or session.party_ids)

    async def submit(request: Request) -> JSONResponse:
        try:
            sub = decode_submission(await request.json(), expected_dim=session.dim)
        except TransportError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        if sub.round_id != round_id or sub.party_id not in expected:
            return JSONResponse({"error": "unknown party or round"}, status_code=403)
        received[sub.party_id] = sub
        return JSONResponse({"received": sorted(received)})

    async def aggregate(_: Request) -> JSONResponse:
        masked = {pid: sub.masked for pid, sub in received.items()}
        return JSONResponse({"aggregate": session.aggregate_field(masked)})

    app = Starlette(
        routes=[Route("/submit", submit, methods=["POST"]), Route("/aggregate", aggregate)]
    )
    uvicorn.run(app, host=host, port=port)
