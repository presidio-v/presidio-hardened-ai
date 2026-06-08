"""Federated learning (P3 / v0.5.0): train across silos without centralising data.

Each silo trains locally with the DP-SGD reference trainer starting from the broadcast
global model; a coordinator combines the updates by FedAvg. Raw data never leaves the
silo — the coordinator sees only model updates — and per-client differential privacy
composes across rounds. A ``SecureSumAggregator`` demonstrates secure aggregation: the
server recovers only the *combined* update, not any individual silo's.
"""

from __future__ import annotations

from presidio_ai.fl.aggregation import Aggregator, FedAvgAggregator, SecureSumAggregator
from presidio_ai.fl.commit import (
    MODP2048_GROUP,
    CommitmentError,
    FeldmanSharing,
    SchnorrGroup,
    feldman_reconstruct,
    feldman_split,
    feldman_verify_share,
    pedersen_add,
    pedersen_commit,
    pedersen_sum,
    pedersen_verify,
)
from presidio_ai.fl.consortium import (
    ConsortiumError,
    ConsortiumRoundResult,
    run_consortium_round,
)
from presidio_ai.fl.coordinator import (
    FederatedClient,
    FederatedResult,
    federated_train,
)
from presidio_ai.fl.governance import SiloGovernance, charge_federated
from presidio_ai.fl.keyagreement import (
    KeyAgreementError,
    SignedDHKey,
    derive_pairwise_seed,
    establish_pairwise_seeds,
    generate_x25519_keypair,
    sign_dh_public_key,
    verify_dh_public_key,
)
from presidio_ai.fl.secure_agg import (
    SecureAggregationSession,
    dequantize,
    quantize,
    shamir_reconstruct,
    shamir_split,
)
from presidio_ai.fl.transport import (
    MaskedSubmission,
    TransportError,
    decode_submission,
    encode_submission,
)

__all__ = [
    "Aggregator",
    "FedAvgAggregator",
    "SecureSumAggregator",
    "FederatedClient",
    "FederatedResult",
    "federated_train",
    "SiloGovernance",
    "charge_federated",
    "run_consortium_round",
    "ConsortiumRoundResult",
    "ConsortiumError",
    "generate_x25519_keypair",
    "sign_dh_public_key",
    "verify_dh_public_key",
    "derive_pairwise_seed",
    "establish_pairwise_seeds",
    "SignedDHKey",
    "KeyAgreementError",
    "encode_submission",
    "decode_submission",
    "MaskedSubmission",
    "TransportError",
    "SchnorrGroup",
    "MODP2048_GROUP",
    "CommitmentError",
    "pedersen_commit",
    "pedersen_verify",
    "pedersen_add",
    "pedersen_sum",
    "feldman_split",
    "feldman_verify_share",
    "feldman_reconstruct",
    "FeldmanSharing",
    "SecureAggregationSession",
    "shamir_split",
    "shamir_reconstruct",
    "quantize",
    "dequantize",
]
