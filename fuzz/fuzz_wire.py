# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Atheris coverage-guided fuzz harness for the consortium wire format and inputs.

Parses arbitrary bytes as JSON and drives the network-facing round coordinator
(``RoundCoordinator.submit`` / ``close`` / ``read``) plus ``decode_submission``,
and the input validators (``validate_silo_id``, ``normalize_parents``,
``is_decimal_string``). Invariants: the coordinator answers every payload with
a status code and never raises, never accepts an unsigned submission, and the
decoders and validators raise only their declared errors.

Linux only (Atheris ships no macOS wheel); CI runs it on Python 3.12.
"""

import json
import random
import sys

import atheris

with atheris.instrument_imports():
    from presidio_ai.evidence import generate_ed25519_keypair
    from presidio_ai.fl.secure_agg import SecureAggregationSession
    from presidio_ai.fl.transport import RoundCoordinator, TransportError, decode_submission
    from presidio_ai.numeric import is_decimal_string
    from presidio_ai.provenance import ParentError, normalize_parents
    from presidio_ai.sanitize import ValidationError, validate_silo_id

PARTIES = ["A", "B", "C"]
TRUST = {p: generate_ed25519_keypair()[1] for p in [*PARTIES, "coord"]}
SESSION = SecureAggregationSession(PARTIES, dim=2, threshold=2, rng=random.Random(7))  # noqa: S311
COORD = RoundCoordinator(SESSION, round_id="r1", identity_trust=TRUST, coordinator_id="coord")


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text

    for call in (COORD.submit, COORD.close, COORD.read):
        status, body = call(payload)
        assert isinstance(status, int) and isinstance(body, dict)
    # No fuzz input carries a valid signature, so nothing is ever accepted.
    assert not COORD.received and COORD.aggregate is None

    try:
        decode_submission(payload, expected_dim=2)
    except TransportError:
        pass
    try:
        validate_silo_id(text)
    except ValidationError:
        pass
    try:
        normalize_parents(payload if isinstance(payload, list) else [text])
    except ParentError:
        pass
    assert isinstance(is_decimal_string(payload), bool)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
