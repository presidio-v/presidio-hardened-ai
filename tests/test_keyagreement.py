"""Tests for authenticated pairwise key agreement (P4 / [mpc] lane).

Uses the cryptography library (the [crypto]/[mpc] extra, present in the dev lane).
"""

from __future__ import annotations

import random

import pytest

from presidio_ai.evidence import generate_ed25519_keypair
from presidio_ai.fl.keyagreement import (
    KeyAgreementError,
    SignedDHKey,
    derive_pairwise_seed,
    establish_pairwise_seeds,
    generate_x25519_keypair,
    sign_dh_public_key,
    verify_dh_public_key,
)
from presidio_ai.fl.secure_agg import PRIME, SecureAggregationSession


def test_derived_seed_is_symmetric_and_in_field():
    a_priv, a_pub = generate_x25519_keypair()
    b_priv, b_pub = generate_x25519_keypair()
    seed_ab = derive_pairwise_seed(
        my_private_hex=a_priv, their_public_hex=b_pub, my_id="A", their_id="B", session_id="r1"
    )
    seed_ba = derive_pairwise_seed(
        my_private_hex=b_priv, their_public_hex=a_pub, my_id="B", their_id="A", session_id="r1"
    )
    assert seed_ab == seed_ba
    assert 0 <= seed_ab < PRIME


def test_session_id_domain_separates_seeds():
    a_priv, _ = generate_x25519_keypair()
    _, b_pub = generate_x25519_keypair()
    s1 = derive_pairwise_seed(
        my_private_hex=a_priv, their_public_hex=b_pub, my_id="A", their_id="B", session_id="r1"
    )
    s2 = derive_pairwise_seed(
        my_private_hex=a_priv, their_public_hex=b_pub, my_id="A", their_id="B", session_id="r2"
    )
    assert s1 != s2


def test_dh_key_authentication_roundtrip():
    priv, pub = generate_x25519_keypair()
    id_priv, id_pub = generate_ed25519_keypair()
    sig = sign_dh_public_key(pub, party_id="A", ed25519_private_hex=id_priv)
    assert verify_dh_public_key(pub, party_id="A", signature_hex=sig, ed25519_public_hex=id_pub)
    # Wrong party id, tampered key, or wrong identity all fail closed.
    assert not verify_dh_public_key(pub, party_id="B", signature_hex=sig, ed25519_public_hex=id_pub)
    other_priv, _ = generate_x25519_keypair()
    assert not verify_dh_public_key(
        other_priv, party_id="A", signature_hex=sig, ed25519_public_hex=id_pub
    )


def _identity(parties):
    return {p: generate_ed25519_keypair() for p in parties}  # p -> (priv, pub)


def test_establish_pairwise_seeds_authenticates_all_peers():
    parties = ["A", "B", "C"]
    ids = _identity(parties)
    dh = {p: generate_x25519_keypair() for p in parties}  # p -> (priv, pub)
    trust = {p: ids[p][1] for p in parties}
    signed = {
        p: SignedDHKey(
            p, dh[p][1], sign_dh_public_key(dh[p][1], party_id=p, ed25519_private_hex=ids[p][0])
        )
        for p in parties
    }
    seeds_a = establish_pairwise_seeds(
        my_id="A",
        my_private_hex=dh["A"][0],
        peer_keys={p: signed[p] for p in parties if p != "A"},
        identity_trust=trust,
        session_id="r1",
    )
    seeds_b = establish_pairwise_seeds(
        my_id="B",
        my_private_hex=dh["B"][0],
        peer_keys={p: signed[p] for p in parties if p != "B"},
        identity_trust=trust,
        session_id="r1",
    )
    # A and B agree on their shared pairwise seed.
    assert seeds_a["B"] == seeds_b["A"]
    assert set(seeds_a) == {"B", "C"}


def test_establish_rejects_unauthenticated_key():
    parties = ["A", "B"]
    ids = _identity(parties)
    dh = {p: generate_x25519_keypair() for p in parties}
    trust = {p: ids[p][1] for p in parties}
    # B's DH key signed by the WRONG identity (a MITM coordinator's key).
    mitm_priv, _ = generate_ed25519_keypair()
    forged = SignedDHKey(
        "B", dh["B"][1], sign_dh_public_key(dh["B"][1], party_id="B", ed25519_private_hex=mitm_priv)
    )
    with pytest.raises(KeyAgreementError, match="authentication failed"):
        establish_pairwise_seeds(
            my_id="A",
            my_private_hex=dh["A"][0],
            peer_keys={"B": forged},
            identity_trust=trust,
            session_id="r1",
        )


def test_establish_rejects_unknown_peer_identity():
    a_priv, a_pub = generate_x25519_keypair()
    b_priv, b_pub = generate_x25519_keypair()
    id_priv, _ = generate_ed25519_keypair()
    signed_b = SignedDHKey(
        "B", b_pub, sign_dh_public_key(b_pub, party_id="B", ed25519_private_hex=id_priv)
    )
    with pytest.raises(KeyAgreementError, match="no identity key"):
        establish_pairwise_seeds(
            my_id="A",
            my_private_hex=a_priv,
            peer_keys={"B": signed_b},
            identity_trust={},
            session_id="r1",
        )


def test_agreed_seeds_make_masks_cancel():
    # End-to-end: real DH seeds drive set_pairwise_seed; aggregation still cancels.
    parties = ["A", "B", "C"]
    ids = _identity(parties)
    dh = {p: generate_x25519_keypair() for p in parties}
    trust = {p: ids[p][1] for p in parties}
    signed = {
        p: SignedDHKey(
            p, dh[p][1], sign_dh_public_key(dh[p][1], party_id=p, ed25519_private_hex=ids[p][0])
        )
        for p in parties
    }
    seeds = {
        me: establish_pairwise_seeds(
            my_id=me,
            my_private_hex=dh[me][0],
            peer_keys={p: signed[p] for p in parties if p != me},
            identity_trust=trust,
            session_id="r1",
        )
        for me in parties
    }
    sess = SecureAggregationSession(
        parties,
        dim=2,
        threshold=2,
        rng=random.Random(1),  # noqa: S311 - test fixture
    )
    for i, a in enumerate(parties):
        for b in parties[i + 1 :]:
            assert seeds[a][b] == seeds[b][a]  # both ends agree
            sess.set_pairwise_seed(a, b, seeds[a][b])
    qvecs = {p: [10 * (i + 1), 20 * (i + 1)] for i, p in enumerate(parties)}
    masked = {p: sess.mask_field(p, qvecs[p]) for p in parties}
    recovered = sess.aggregate_field(masked)
    expected = [sum(qvecs[p][k] for p in parties) % PRIME for k in range(2)]
    assert recovered == expected
