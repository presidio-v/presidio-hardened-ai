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

The masked vectors are exactly what the coordinator is allowed to see; they reveal
nothing individually. Every message is **signed** with the sender's Ed25519 identity key
(the key that also signs its X25519 key in :mod:`presidio_ai.fl.keyagreement`), so the
party id is authenticated by the message, not by the connection. :class:`RoundCoordinator`
enforces one submission per party, aggregates exactly once (when every expected party
has submitted, or on a signed ``close`` from the coordinator identity) and serves only
that cached result, so no caller can obtain two aggregates over different sets. The HTTP
layer serves TLS when given a certificate and key, and refuses to bind a non-loopback
address without them; rate limiting remains deployment configuration.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from presidio_ai.evidence import sign_ed25519, verify_ed25519
from presidio_ai.fl.secure_agg import PRIME
from presidio_ai.hashing import sha256_hex


class TransportError(RuntimeError):
    """Raised on a malformed protocol message (fail-closed)."""


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def check_bind(host: str, *, ssl_certfile: str | None, ssl_keyfile: str | None) -> None:
    """Refuse a plaintext bind beyond loopback, and a half-configured TLS pair."""
    if (ssl_certfile is None) != (ssl_keyfile is None):
        raise TransportError("TLS needs both ssl_certfile and ssl_keyfile")
    if ssl_certfile is None and host not in _LOOPBACK_HOSTS:
        raise TransportError(
            f"refusing to serve plaintext HTTP on {host!r}: pass ssl_certfile and ssl_keyfile, "
            "or bind a loopback address behind a TLS-terminating proxy"
        )


@dataclass(frozen=True)
class MaskedSubmission:
    """One party's masked field-element vector for a round, with its Ed25519 signature."""

    party_id: str
    round_id: str
    masked: list[int]
    signature: str

    def content_hash(self) -> str:
        return submission_hash(self.party_id, self.round_id, self.masked)

    def to_dict(self) -> dict[str, object]:
        return {
            "party_id": self.party_id,
            "round_id": self.round_id,
            "masked": list(self.masked),
            "signature": self.signature,
        }


def submission_hash(party_id: str, round_id: str, masked: Sequence[int]) -> str:
    """SHA-256 over the canonical ``{party_id, round_id, masked}`` the party signs."""
    return sha256_hex(
        {"kind": "submission", "party_id": party_id, "round_id": round_id, "masked": list(masked)}
    )


def command_hash(party_id: str, round_id: str, action: str) -> str:
    """SHA-256 over a signed ``close`` / ``read`` command."""
    return sha256_hex(
        {"kind": "command", "party_id": party_id, "round_id": round_id, "action": action}
    )


def encode_submission(
    party_id: str, round_id: str, masked: Sequence[int], *, private_key_hex: str
) -> dict[str, object]:
    """Sign and encode a masked submission to a JSON-safe dict."""
    values = [int(v) for v in masked]
    sig = sign_ed25519(submission_hash(party_id, round_id, values), party_id, private_key_hex)
    return MaskedSubmission(party_id, round_id, values, sig).to_dict()


def encode_command(
    party_id: str, round_id: str, action: str, *, private_key_hex: str
) -> dict[str, object]:
    """Sign a coordinator ``close`` or a party/coordinator ``read`` command."""
    if action not in _ACTIONS:
        raise TransportError(f"action must be one of {sorted(_ACTIONS)}")
    sig = sign_ed25519(command_hash(party_id, round_id, action), party_id, private_key_hex)
    return {"party_id": party_id, "round_id": round_id, "action": action, "signature": sig}


_ACTIONS = frozenset({"close", "read"})


def _require_str(payload: dict, name: str, what: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise TransportError(f"{what}.{name} must be a non-empty string")
    return value


def decode_submission(
    payload: object, *, expected_dim: int | None = None, prime: int = PRIME
) -> MaskedSubmission:
    """Decode and validate a masked submission. Fail-closed on any malformation.

    Checks shape only; :meth:`RoundCoordinator.submit` verifies the signature.
    """
    if not isinstance(payload, dict):
        raise TransportError("submission must be a JSON object")
    party_id = _require_str(payload, "party_id", "submission")
    round_id = _require_str(payload, "round_id", "submission")
    signature = _require_str(payload, "signature", "submission")
    masked = payload.get("masked")
    if not isinstance(masked, list) or not masked:
        raise TransportError("submission.masked must be a non-empty list")
    if expected_dim is not None and len(masked) != expected_dim:
        raise TransportError(f"submission.masked must have length {expected_dim}")
    out: list[int] = []
    for v in masked:
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < prime:
            raise TransportError("submission.masked elements must be field integers in [0, prime)")
        out.append(v)
    return MaskedSubmission(party_id, round_id, out, signature)


class RoundCoordinator:
    """Transport-independent coordinator state for one round (what :func:`serve` exposes).

    Each method takes a decoded JSON payload and returns ``(status, body)``:

    * :meth:`submit` — 400 malformed, 403 unknown party or round, 401 bad signature,
      409 already submitted or round closed, 200 accepted. The round closes by itself once
      every expected party has submitted.
    * :meth:`close` — signed ``close`` from ``coordinator_id``: 401/403 as above, 409 below
      the session threshold, 200 closed (idempotent).
    * :meth:`read` — signed ``read`` from an expected party or the coordinator: 425 before
      the round closes, 200 with the one cached aggregate after.
    """

    def __init__(
        self,
        session,
        *,
        round_id: str,
        identity_trust: Mapping[str, str],
        coordinator_id: str,
        expected_parties: Sequence[str] | None = None,
    ) -> None:
        self.session = session
        self.round_id = round_id
        self.identity_trust = dict(identity_trust)
        self.coordinator_id = coordinator_id
        self.expected = {str(p) for p in (expected_parties or session.party_ids)}
        if coordinator_id not in self.identity_trust:
            raise TransportError("coordinator_id needs a public key in identity_trust")
        self._by_str = {str(p): p for p in session.party_ids}
        self.received: dict[str, MaskedSubmission] = {}
        self.aggregate: list[int] | None = None

    def _verified(self, party_id: str, content_hash: str, signature: str) -> bool:
        public = self.identity_trust.get(party_id)
        return public is not None and verify_ed25519(content_hash, party_id, signature, public)

    def submit(self, payload: object) -> tuple[int, dict]:
        try:
            sub = decode_submission(payload, expected_dim=self.session.dim)
        except TransportError as exc:
            return 400, {"error": str(exc)}
        if sub.round_id != self.round_id or sub.party_id not in self.expected:
            return 403, {"error": "unknown party or round"}
        if not self._verified(sub.party_id, sub.content_hash(), sub.signature):
            return 401, {"error": "bad signature"}
        if self.aggregate is not None:
            return 409, {"error": "round closed"}
        if sub.party_id in self.received:
            return 409, {"error": "party already submitted"}
        self.received[sub.party_id] = sub
        if set(self.received) == self.expected:
            self._close()
        return 200, {"received": sorted(self.received), "closed": self.aggregate is not None}

    def _command(self, payload: object, action: str) -> tuple[int, dict] | str:
        if not isinstance(payload, dict) or payload.get("action") != action:
            return 400, {"error": f"expected a signed {action!r} command"}
        try:
            party_id = _require_str(payload, "party_id", "command")
            round_id = _require_str(payload, "round_id", "command")
            signature = _require_str(payload, "signature", "command")
        except TransportError as exc:
            return 400, {"error": str(exc)}
        if round_id != self.round_id:
            return 403, {"error": "unknown round"}
        if not self._verified(party_id, command_hash(party_id, round_id, action), signature):
            return 401, {"error": "bad signature"}
        return party_id

    def close(self, payload: object) -> tuple[int, dict]:
        who = self._command(payload, "close")
        if not isinstance(who, str):
            return who
        if who != self.coordinator_id:
            return 403, {"error": "only the coordinator may close the round"}
        if self.aggregate is None:
            if len(self.received) < self.session.threshold:
                return 409, {"error": "fewer submissions than the session threshold"}
            self._close()
        return 200, {"closed": True, "survivors": sorted(self.received)}

    def read(self, payload: object) -> tuple[int, dict]:
        who = self._command(payload, "read")
        if not isinstance(who, str):
            return who
        if who != self.coordinator_id and who not in self.expected:
            return 403, {"error": "not a party of this round"}
        if self.aggregate is None:
            return 425, {"error": "round not closed yet"}
        return 200, {"aggregate": list(self.aggregate), "survivors": sorted(self.received)}

    def _close(self) -> None:
        masked = {self._by_str[pid]: sub.masked for pid, sub in self.received.items()}
        self.aggregate = self.session.aggregate_field(masked)


def serve(  # pragma: no cover - thin HTTP layer over RoundCoordinator, behind the [mpc] extra
    session,
    *,
    round_id: str,
    identity_trust: Mapping[str, str],
    coordinator_id: str,
    host: str = "127.0.0.1",
    port: int = 8089,
    expected_parties: Sequence[str] | None = None,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
) -> None:
    """Serve a :class:`RoundCoordinator` over HTTP: ``POST /submit``, ``/close``, ``/aggregate``.

    Requires the ``[mpc]`` extra (``pip install 'presidio-hardened-ai[mpc]'``). Every
    request body is a signed message (see :func:`encode_submission` and
    :func:`encode_command`); the HTTP layer adds nothing to the authentication. With
    ``ssl_certfile`` and ``ssl_keyfile`` it serves HTTPS (Python's TLS defaults: TLS 1.2
    minimum); without them it binds loopback only (see :func:`check_bind`).
    """
    check_bind(host, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)
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

    coordinator = RoundCoordinator(
        session,
        round_id=round_id,
        identity_trust=identity_trust,
        coordinator_id=coordinator_id,
        expected_parties=expected_parties,
    )

    def route(handler):
        async def endpoint(request: Request) -> JSONResponse:
            try:
                payload = await request.json()
            except ValueError:
                return JSONResponse({"error": "body must be JSON"}, status_code=400)
            status, body = handler(payload)
            return JSONResponse(body, status_code=status)

        return endpoint

    app = Starlette(
        routes=[
            Route("/submit", route(coordinator.submit), methods=["POST"]),
            Route("/close", route(coordinator.close), methods=["POST"]),
            Route("/aggregate", route(coordinator.read), methods=["POST"]),
        ]
    )
    uvicorn.run(app, host=host, port=port, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)
