"""Authenticated pairwise key agreement for secure aggregation (P4 / [mpc] lane).

The secure-aggregation core (:mod:`presidio_ai.fl.secure_agg`) needs every pair of
parties to share a high-entropy seed that *only* those two parties know — that is
what makes their pairwise masks cancel while remaining secret from the coordinator.
This module derives those seeds without any trusted dealer:

* **X25519 Diffie–Hellman.** Each party publishes an ephemeral X25519 public key;
  any pair derives a shared secret from one side's private key and the other's
  public key. Neither the coordinator nor a non-member can compute it.
* **HKDF-SHA256 → field element.** The raw shared secret is run through HKDF with
  an *order-independent* ``info`` (the sorted pair of party ids + a session id), so
  both endpoints derive the **same** field-element seed. Binding the session id
  domain-separates seeds across rounds (no cross-round reuse).
* **Ed25519 authentication, fail-closed.** A party's X25519 public key is only
  accepted if it carries a valid Ed25519 signature from that party's long-term
  identity key (looked up in a local trust store, exactly like evidence signers).
  An unsigned, mis-signed, or unknown key is rejected — defeating a coordinator
  that tries to MITM the exchange by substituting its own DH keys.

This is the verifiable core of the ``[mpc]`` lane and is unit-tested with the
``cryptography`` library (the ``[crypto]``/``[mpc]`` extra). The network transport
that moves these public keys and the masked vectors between hosts is the thin,
lazily-imported layer in :mod:`presidio_ai.fl.transport`; the trust model is the
same whether seeds are exchanged in-process or over the wire.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from presidio_ai.evidence import sign_ed25519, verify_ed25519
from presidio_ai.fl.secure_agg import PRIME
from presidio_ai.hashing import sha256_hex


class KeyAgreementError(RuntimeError):
    """Raised on a failed or unauthenticated key-agreement step (fail-closed)."""


def _require_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: F401
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "key agreement needs the optional extra: pip install 'presidio-hardened-ai[mpc]'"
        ) from exc
    return x25519, HKDF, hashes, serialization


def generate_x25519_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex) for an ephemeral X25519 keypair."""
    x25519, _, _, _ = _require_crypto()
    sk = x25519.X25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


# A DH public key is authenticated by signing the SHA-256 of its hex under the
# party's Ed25519 identity key, reusing the evidence-signing message format
# (content_hash = sha256 of the pubkey hex, signer = party id).
def _dh_key_hash(public_key_hex: str) -> str:
    return sha256_hex({"x25519_pub": public_key_hex})


def sign_dh_public_key(public_key_hex: str, *, party_id: str, ed25519_private_hex: str) -> str:
    """Sign a party's X25519 public key under its Ed25519 identity key."""
    return sign_ed25519(_dh_key_hash(public_key_hex), party_id, ed25519_private_hex)


def verify_dh_public_key(
    public_key_hex: str, *, party_id: str, signature_hex: str, ed25519_public_hex: str
) -> bool:
    """Verify a party's X25519 public key against its Ed25519 identity (fail-closed)."""
    return verify_ed25519(_dh_key_hash(public_key_hex), party_id, signature_hex, ed25519_public_hex)


@dataclass(frozen=True)
class SignedDHKey:
    """A party's ephemeral X25519 public key plus its Ed25519 identity signature."""

    party_id: str
    public_key_hex: str
    signature_hex: str

    def to_dict(self) -> dict[str, str]:
        return {
            "party_id": self.party_id,
            "public_key_hex": self.public_key_hex,
            "signature_hex": self.signature_hex,
        }


def _pair_info(a: str, b: str, session_id: str) -> bytes:
    """Order-independent HKDF info: both endpoints derive the same seed."""
    lo, hi = sorted((a, b))
    return f"presidio-hardened-ai/secure-agg/{session_id}/{lo}|{hi}".encode()


def derive_pairwise_seed(
    *,
    my_private_hex: str,
    their_public_hex: str,
    my_id: str,
    their_id: str,
    session_id: str,
    prime: int = PRIME,
) -> int:
    """Derive the shared pairwise seed (a field element) for one pair of parties.

    Symmetric: ``derive_pairwise_seed(A->B) == derive_pairwise_seed(B->A)`` because
    X25519 is symmetric and the HKDF ``info`` is order-independent.
    """
    x25519, HKDF, hashes, _ = _require_crypto()
    sk = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_private_hex))
    pk = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(their_public_hex))
    shared = sk.exchange(pk)
    # 32 bytes of HKDF output -> 256-bit integer -> reduce mod prime. Bias against a
    # 61-bit prime is <= 2**-195, cryptographically negligible.
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_pair_info(my_id, their_id, session_id),
    ).derive(shared)
    return int.from_bytes(okm, "big") % prime


def establish_pairwise_seeds(
    *,
    my_id: str,
    my_private_hex: str,
    peer_keys: Mapping[str, SignedDHKey],
    identity_trust: Mapping[str, str],
    session_id: str,
    prime: int = PRIME,
) -> dict[str, int]:
    """Authenticate every peer's DH key and derive my pairwise seed with each.

    ``peer_keys`` maps peer id -> its :class:`SignedDHKey`; ``identity_trust`` maps
    peer id -> its Ed25519 identity public key (hex). Any peer whose DH key fails
    authentication aborts the whole step (fail-closed) — a coordinator cannot slip
    in its own DH key for a party it does not hold the identity key for.
    """
    seeds: dict[str, int] = {}
    for peer_id, signed in peer_keys.items():
        if peer_id == my_id:
            continue
        if signed.party_id != peer_id:
            raise KeyAgreementError(f"DH key for '{peer_id}' is labelled '{signed.party_id}'")
        identity = identity_trust.get(peer_id)
        if identity is None:
            raise KeyAgreementError(f"no identity key in trust store for peer '{peer_id}'")
        if not verify_dh_public_key(
            signed.public_key_hex,
            party_id=peer_id,
            signature_hex=signed.signature_hex,
            ed25519_public_hex=identity,
        ):
            raise KeyAgreementError(f"DH key authentication failed for peer '{peer_id}'")
        seeds[peer_id] = derive_pairwise_seed(
            my_private_hex=my_private_hex,
            their_public_hex=signed.public_key_hex,
            my_id=my_id,
            their_id=peer_id,
            session_id=session_id,
            prime=prime,
        )
    return seeds
