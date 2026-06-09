"""Commitments and verifiable secret sharing for malicious-security (P4, ADR-0002).

ADR-0001's secure aggregation assumes an *honest-but-curious* coordinator and a
collusion bound on parties. ADR-0002 hardens this to a *malicious* setting — a
coordinator or parties that **deviate** from the protocol — with security-with-abort.
This module provides the two cryptographic primitives that hardening rests on, both
over a prime-order group where the discrete log is hard:

* **Pedersen commitments** ``C(m, r) = g^m · h^r mod p`` — perfectly hiding, binding
  under discrete log. Crucially **additively homomorphic**: ``C(m1,r1)·C(m2,r2) =
  C(m1+m2, r1+r2)``, so the product of per-party input commitments is a commitment to
  the *sum*. A party can therefore check the coordinator's returned aggregate against
  the public commitments and abort on a false aggregate.
* **Feldman verifiable secret sharing** — Shamir sharing plus public commitments
  ``g^{a_i}`` to the sharing-polynomial coefficients. Each shareholder verifies its
  share against the commitments (``g^share == Π C_i^{x^i}``) and rejects an inconsistent
  share, so a malicious dealer cannot hand different shareholders incompatible shares.

The group. Operations live in the prime-order-``q`` subgroup of quadratic residues mod
a safe prime ``p = 2q + 1``. The production default (:data:`MODP2048_GROUP`) is the
RFC 3526 2048-bit MODP safe prime (a vetted, nothing-up-my-sleeve modulus; its primality
and that of ``q = (p-1)/2`` are re-checked in the test suite). The second Pedersen
generator ``h`` is derived by hashing to the subgroup, so ``log_g h`` is unknown to
everyone — no trusted setup. The group is a parameter, so the verifiable core can be
exercised with a small safe prime for fast, exact tests.

Scope. This is the verifiable, pure-Python core (``pow`` over big ints — no new binary
dependency). It composes with the field-quantised masking of :mod:`presidio_ai.fl.
secure_agg`: the secret-sharing *exponent* field is ``Z_q`` here (a DL-hard prime),
while the additive masking stays in its own field — only the seed-sharing migrates.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass


class CommitmentError(RuntimeError):
    """Raised on an invalid commitment, share, or group parameter (fail-closed)."""


@dataclass(frozen=True)
class SchnorrGroup:
    """A prime-order-``q`` subgroup of ``Z_p^*`` with generators ``g`` and ``h``.

    ``p = 2q + 1`` is a safe prime; the subgroup is the quadratic residues mod ``p``
    (order ``q``). ``g`` and ``h`` are generators of that subgroup with unknown mutual
    discrete log (``h`` is hashed to the subgroup).
    """

    p: int
    q: int
    g: int
    h: int

    def __post_init__(self) -> None:
        if self.p != 2 * self.q + 1:
            raise CommitmentError("group requires a safe prime p = 2q + 1")
        for name, gen in (("g", self.g), ("h", self.h)):
            if not 1 < gen < self.p:
                raise CommitmentError(f"generator {name} out of range")
            if pow(gen, self.q, self.p) != 1:
                raise CommitmentError(f"generator {name} is not in the order-q subgroup")

    def normalize(self, exponent: int) -> int:
        """Reduce an exponent into ``Z_q``."""
        return exponent % self.q


def hash_to_subgroup(p: int, label: bytes) -> int:
    """Deterministically derive a subgroup element (a QR mod ``p``) from ``label``.

    Squaring maps into the quadratic-residue subgroup; the counter skips the trivial
    elements 0 and 1. Used for the second Pedersen generator, so ``log_g h`` is unknown.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        candidate = pow(int.from_bytes(digest, "big") % p, 2, p)
        if candidate > 1:
            return candidate
        counter += 1


def _modp2048() -> SchnorrGroup:
    # RFC 3526 group 14 (2048-bit MODP): a safe prime p; q = (p-1)/2 is prime.
    # g = 2^2 = 4 is a quadratic residue, hence a generator of the order-q subgroup.
    p = int(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
        16,
    )
    q = (p - 1) // 2
    return SchnorrGroup(p=p, q=q, g=4, h=hash_to_subgroup(p, b"presidio-hardened-ai/pedersen-h"))


#: Production default group (RFC 3526 MODP-2048). Primality is re-verified in tests.
MODP2048_GROUP = _modp2048()


def random_scalar(group: SchnorrGroup) -> int:
    """A uniform nonzero element of ``Z_q`` from a CSPRNG (commitment randomness)."""
    return 1 + secrets.randbelow(group.q - 1)


def pedersen_commit(value: int, randomness: int, group: SchnorrGroup = MODP2048_GROUP) -> int:
    """Pedersen commitment ``g^value · h^randomness mod p`` (exponents taken mod q)."""
    g_m = pow(group.g, value % group.q, group.p)
    h_r = pow(group.h, randomness % group.q, group.p)
    return (g_m * h_r) % group.p


def pedersen_verify(
    commitment: int, value: int, randomness: int, group: SchnorrGroup = MODP2048_GROUP
) -> bool:
    """Verify a Pedersen commitment opening (fail-closed)."""
    return commitment == pedersen_commit(value, randomness, group)


def pedersen_add(c1: int, c2: int, group: SchnorrGroup = MODP2048_GROUP) -> int:
    """Homomorphically combine two commitments: ``C(m1+m2, r1+r2)``."""
    return (c1 * c2) % group.p


def pedersen_sum(commitments: Sequence[int], group: SchnorrGroup = MODP2048_GROUP) -> int:
    """Product of commitments = commitment to the sum of the committed values."""
    acc = 1
    for c in commitments:
        acc = (acc * c) % group.p
    return acc


def _eval_poly(coeffs: Sequence[int], x: int, modulus: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % modulus
    return acc


def _lagrange_at_zero(shares: Mapping[int, int], modulus: int) -> int:
    xs = list(shares)
    secret = 0
    for i, xi in enumerate(xs):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = (num * (-xj)) % modulus
            den = (den * (xi - xj)) % modulus
        secret = (secret + shares[xi] * num * pow(den, modulus - 2, modulus)) % modulus
    return secret


@dataclass(frozen=True)
class FeldmanSharing:
    """The output of a Feldman VSS deal: shares plus public coefficient commitments."""

    shares: dict[int, int]  # x -> share in Z_q
    commitments: list[int]  # g^{a_0}, g^{a_1}, ... mod p (a_0 = secret)


def feldman_split(
    secret: int,
    threshold: int,
    n_shares: int,
    *,
    group: SchnorrGroup = MODP2048_GROUP,
    rng=None,
) -> FeldmanSharing:
    """Verifiably share ``secret`` (a ``Z_q`` element): Shamir shares + ``g^{a_i}``.

    Any ``threshold`` shares reconstruct the secret, and every share is checkable
    against the public commitments via :func:`feldman_verify_share`.
    """
    if not 1 <= threshold <= n_shares:
        raise CommitmentError("require 1 <= threshold <= n_shares")
    if not 0 <= secret < group.q:
        raise CommitmentError("secret must be a Z_q element in [0, q)")
    draw = (
        (lambda: 1 + rng.randrange(group.q - 1))
        if rng is not None
        else (lambda: random_scalar(group))
    )
    coeffs = [secret] + [draw() for _ in range(threshold - 1)]
    shares = {x: _eval_poly(coeffs, x, group.q) for x in range(1, n_shares + 1)}
    commitments = [pow(group.g, a, group.p) for a in coeffs]
    return FeldmanSharing(shares=shares, commitments=commitments)


def feldman_verify_share(
    x: int, share: int, commitments: Sequence[int], *, group: SchnorrGroup = MODP2048_GROUP
) -> bool:
    """Check ``g^share == Π_i commitments[i]^{x^i} mod p`` (fail-closed)."""
    lhs = pow(group.g, share % group.q, group.p)
    rhs = 1
    x_pow = 1  # x^i mod q
    for c in commitments:
        rhs = (rhs * pow(c, x_pow, group.p)) % group.p
        x_pow = (x_pow * x) % group.q
    return lhs == rhs


def feldman_reconstruct(shares: Mapping[int, int], *, group: SchnorrGroup = MODP2048_GROUP) -> int:
    """Reconstruct the shared secret via Lagrange interpolation at 0 over ``Z_q``."""
    if not shares:
        raise CommitmentError("need at least one share to reconstruct")
    return _lagrange_at_zero(shares, group.q)


def robust_reconstruct(
    shares: Mapping[int, int],
    commitments: Sequence[int],
    *,
    threshold: int,
    group: SchnorrGroup = MODP2048_GROUP,
) -> int:
    """Reconstruct a Feldman-shared secret, tolerating invalid/missing shares (ADR-0006).

    Verifies each share against the public coefficient ``commitments``, discards the invalid
    ones (malicious or corrupted), and Lagrange-interpolates the secret from any ``threshold``
    of the valid shares. Delivers the correct secret as long as at least ``threshold`` valid
    shares are present (with Feldman VSS this is robust *detection*, so an honest majority
    ``n >= 2t+1`` suffices). Fails closed if fewer than ``threshold`` valid shares remain.
    """
    if threshold < 1:
        raise CommitmentError("threshold must be >= 1")
    valid = {
        x: y for x, y in shares.items() if feldman_verify_share(x, y, commitments, group=group)
    }
    if len(valid) < threshold:
        raise CommitmentError(
            f"only {len(valid)} valid shares (< threshold {threshold}); cannot reconstruct"
        )
    quorum = dict(list(valid.items())[:threshold])
    return feldman_reconstruct(quorum, group=group)
