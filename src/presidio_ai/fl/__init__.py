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
    PartyMisbehavior,
    RetryRoundResult,
    SecureConsortiumResult,
    run_consortium_round,
    run_consortium_round_with_retry,
    run_secure_consortium_round,
    sign_survivor_set,
    verify_survivor_set,
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
from presidio_ai.fl.proof_backend import (
    ModpBackend,
    ProofBackend,
    backend_name,
    get_backend,
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
from presidio_ai.fl.zk import (
    BoundedNormProof,
    L2BoundedProof,
    ProofError,
    RangeProof,
    SquareProof,
    prove_bounded,
    prove_l2_bounded,
    prove_range,
    prove_square,
    verify_bounded,
    verify_l2_bounded,
    verify_range,
    verify_square,
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
    "run_secure_consortium_round",
    "SecureConsortiumResult",
    "sign_survivor_set",
    "verify_survivor_set",
    "PartyMisbehavior",
    "run_consortium_round_with_retry",
    "RetryRoundResult",
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
    "prove_range",
    "verify_range",
    "prove_bounded",
    "verify_bounded",
    "RangeProof",
    "BoundedNormProof",
    "ProofError",
    "prove_l2_bounded",
    "verify_l2_bounded",
    "L2BoundedProof",
    "prove_square",
    "verify_square",
    "SquareProof",
    "ProofBackend",
    "ModpBackend",
    "get_backend",
    "backend_name",
    "SecureAggregationSession",
    "shamir_split",
    "shamir_reconstruct",
    "quantize",
    "dequantize",
]
