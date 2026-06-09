"""Zero-knowledge bounded-norm input validation (P4, ADR-0003).

ADR-0002 stopped a *deviating* coordinator or party; this module closes the remaining
gap — a party submitting a **well-formed but out-of-norm** update to dominate/poison the
aggregate. Because secure aggregation hides individual updates, the bound must be proven
in **zero knowledge**: a party proves its committed update lies within a norm bound
without revealing it. The proven bound is meant to equal the DP **clip sensitivity**, so
the proof turns the accountant's "the client clipped" *assumption* into an enforced fact —
the per-client ``(epsilon, delta)`` becomes sound against a *malicious* client.

What is implemented: a transparent (no trusted setup) **Pedersen bit-decomposition range
proof** over the prime-order MODP-2048 group from :mod:`presidio_ai.fl.commit`:

* **Bit OR-proof** (Chaum–Pedersen / CDS): prove a Pedersen commitment opens to 0 or 1,
  without revealing which, via a Fiat–Shamir-compiled OR of two discrete-log proofs.
* **Range proof**: to prove a committed ``v`` lies in ``[0, 2^bits)``, commit to its bits,
  OR-prove each is a bit, and check ``Π C_i^{2^i} == C`` — which binds the bits (and the
  randomness) to the original commitment, so the verifier learns only "in range".
* **L∞ bound** (:func:`prove_bounded`/:func:`verify_bounded`): prove every coordinate of a
  committed vector lies in ``[-B, B]`` by range-proving the shifted commitment
  ``C_k · g^B`` in ``[0, 2^bits)``.

The Fiat–Shamir transcript binds the group, the commitment, the bound, and **all** bit
commitments, so a proof cannot be replayed onto a different commitment (no weak-FS).

**Scope / deviation from ADR-0003 (read me).** ADR-0003 recommended *Bulletproofs over
Ristretto255*. Neither is available here: this libsodium build exposes no Ristretto255
(only cofactor-8 ed25519, unsafe raw), and there is no vetted *Python* Bulletproofs
library. Rather than ship unverified curve/Bulletproofs code, this v1 uses a textbook,
fully-tested range proof over the already-vetted prime-order MODP group. The construction
gives the **same guarantee** (transparent ZK range proof, no trusted setup); it is ``O(n)``
in proof size rather than Bulletproofs' ``O(log n)``. The Ristretto255 migration + the
logarithmic inner-product compression remain the documented performance follow-up (a
different libsodium build or a Rust-FFI dependency behind the ``[zk]`` extra).
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass

from presidio_ai.fl.commit import (
    MODP2048_GROUP,
    SchnorrGroup,
    pedersen_commit,
)


class ProofError(RuntimeError):
    """Raised on a malformed bounded-norm proof or out-of-range witness (fail-closed)."""


def _enc(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(raw).to_bytes(4, "big") + raw


def _challenge(group: SchnorrGroup, *values: int) -> int:
    """Fiat–Shamir challenge in Z_q from a domain-separated transcript."""
    h = hashlib.sha256(b"presidio-hardened-ai/zk/v1")
    for v in (group.p, group.q, group.g, group.h, *values):
        h.update(_enc(v))
    return int.from_bytes(h.digest(), "big") % group.q


@dataclass(frozen=True)
class BitProof:
    """A Fiat–Shamir OR-proof that a Pedersen commitment opens to 0 or 1."""

    a0: int
    a1: int
    e0: int
    e1: int
    z0: int
    z1: int


def _rand_scalar(group: SchnorrGroup, rng) -> int:
    return rng.randrange(group.q) if rng is not None else secrets.randbelow(group.q)


def prove_bit(
    commitment: int,
    bit: int,
    randomness: int,
    *,
    group: SchnorrGroup,
    prefix: int,
    index: int,
    rng=None,
) -> BitProof:
    """OR-prove that ``commitment = g^bit · h^randomness`` with ``bit in {0,1}``."""
    if bit not in (0, 1):
        raise ProofError("bit must be 0 or 1")
    p, q, g, h = group.p, group.q, group.g, group.h
    c0 = commitment  # == h^r  iff bit == 0
    c1 = (commitment * pow(g, p - 2, p)) % p  # commitment / g == h^r  iff bit == 1
    cs = (c0, c1)

    k = _rand_scalar(group, rng)  # real-branch nonce
    e_fake = _rand_scalar(group, rng)
    z_fake = _rand_scalar(group, rng)
    a_real = pow(h, k, p)
    a_fake = (pow(h, z_fake, p) * pow(cs[1 - bit], (-e_fake) % q, p)) % p

    a = [a_real, a_fake] if bit == 0 else [a_fake, a_real]
    e = _challenge(group, prefix, index, commitment, a[0], a[1])
    e_real = (e - e_fake) % q
    z_real = (k + e_real * randomness) % q

    if bit == 0:
        return BitProof(a0=a[0], a1=a[1], e0=e_real, e1=e_fake, z0=z_real, z1=z_fake)
    return BitProof(a0=a[0], a1=a[1], e0=e_fake, e1=e_real, z0=z_fake, z1=z_real)


def verify_bit(
    commitment: int, proof: BitProof, *, group: SchnorrGroup, prefix: int, index: int
) -> bool:
    """Verify a bit OR-proof (fail-closed)."""
    p, q, g, h = group.p, group.q, group.g, group.h
    c0 = commitment
    c1 = (commitment * pow(g, p - 2, p)) % p
    e = _challenge(group, prefix, index, commitment, proof.a0, proof.a1)
    if (proof.e0 + proof.e1) % q != e:
        return False
    ok0 = pow(h, proof.z0, p) == (proof.a0 * pow(c0, proof.e0, p)) % p
    ok1 = pow(h, proof.z1, p) == (proof.a1 * pow(c1, proof.e1, p)) % p
    return ok0 and ok1


@dataclass(frozen=True)
class RangeProof:
    """A proof that a Pedersen commitment opens to a value in ``[0, 2^bits)``."""

    bits: int
    bit_commitments: list[int]
    bit_proofs: list[BitProof]


def prove_range(
    value: int,
    randomness: int,
    *,
    bits: int,
    group: SchnorrGroup = MODP2048_GROUP,
    rng=None,
    domain: int = 0,
) -> RangeProof:
    """Prove ``commitment = g^value · h^randomness`` opens to a value in ``[0, 2^bits)``."""
    if bits < 1:
        raise ProofError("bits must be >= 1")
    if not 0 <= value < (1 << bits):
        raise ProofError(f"value {value} not in [0, 2^{bits})")
    q = group.q
    commitment = pedersen_commit(value, randomness, group)
    # Bit randomness whose 2^i-weighted sum equals the commitment's randomness, so that
    # Π C_i^{2^i} == C ties the bit commitments back to the original commitment.
    r_bits = [_rand_scalar(group, rng) for _ in range(bits - 1)]
    weighted = sum((1 << i) * r_bits[i] for i in range(bits - 1)) % q
    inv_top = pow(pow(2, bits - 1, q), q - 2, q)
    r_bits.append(((randomness - weighted) % q) * inv_top % q)
    bit_vals = [(value >> i) & 1 for i in range(bits)]
    bit_commitments = [pedersen_commit(bit_vals[i], r_bits[i], group) for i in range(bits)]
    prefix = _challenge(group, domain, commitment, bits, *bit_commitments)
    bit_proofs = [
        prove_bit(
            bit_commitments[i],
            bit_vals[i],
            r_bits[i],
            group=group,
            prefix=prefix,
            index=i,
            rng=rng,
        )
        for i in range(bits)
    ]
    return RangeProof(bits=bits, bit_commitments=bit_commitments, bit_proofs=bit_proofs)


def verify_range(
    commitment: int, proof: RangeProof, *, group: SchnorrGroup = MODP2048_GROUP, domain: int = 0
) -> bool:
    """Verify a range proof against ``commitment`` (fail-closed)."""
    p, q = group.p, group.q
    n = proof.bits
    if n < 1 or len(proof.bit_commitments) != n or len(proof.bit_proofs) != n:
        return False
    prefix = _challenge(group, domain, commitment, n, *proof.bit_commitments)
    # Bind the bits (and randomness) to the original commitment.
    product = 1
    for i, ci in enumerate(proof.bit_commitments):
        product = (product * pow(ci, (1 << i) % q, p)) % p
    if product != commitment % p:
        return False
    return all(
        verify_bit(
            proof.bit_commitments[i], proof.bit_proofs[i], group=group, prefix=prefix, index=i
        )
        for i in range(n)
    )


@dataclass(frozen=True)
class BoundedNormProof:
    """A proof that every coordinate of a committed vector lies in ``[-bound, bound]``."""

    bound: int
    bits: int
    coordinate_proofs: list[RangeProof]


def prove_bounded(
    values: Sequence[int],
    randomness: Sequence[int],
    *,
    bound: int,
    group: SchnorrGroup = MODP2048_GROUP,
    rng=None,
    domain: int = 0,
) -> BoundedNormProof:
    """Prove each committed coordinate ``u_k in [-bound, bound]`` (L∞), in zero knowledge.

    Each coordinate is proven by range-proving the shifted value ``u_k + bound`` in
    ``[0, 2^bits)`` against the shifted commitment ``C_k · g^bound``. ``bound`` is intended
    to be the DP clip sensitivity (in the same fixed-point units as the committed values),
    so a valid proof enforces the sensitivity the accountant assumes.
    """
    if bound < 1:
        raise ProofError("bound must be >= 1")
    if len(values) != len(randomness):
        raise ProofError("values and randomness must have equal length")
    bits = (2 * bound).bit_length()
    proofs: list[RangeProof] = []
    for u, r in zip(values, randomness, strict=True):
        if not -bound <= u <= bound:
            raise ProofError(f"coordinate {u} is outside [-{bound}, {bound}]")
        proofs.append(prove_range(u + bound, r, bits=bits, group=group, rng=rng, domain=domain))
    return BoundedNormProof(bound=bound, bits=bits, coordinate_proofs=proofs)


def verify_bounded(
    commitments: Sequence[int],
    proof: BoundedNormProof,
    *,
    group: SchnorrGroup = MODP2048_GROUP,
    domain: int = 0,
) -> bool:
    """Verify an L∞ bounded-norm proof against per-coordinate commitments (fail-closed)."""
    if proof.bound < 1 or proof.bits != (2 * proof.bound).bit_length():
        return False
    if len(commitments) != len(proof.coordinate_proofs):
        return False
    g_bound = pow(group.g, proof.bound % group.q, group.p)
    for commitment, range_proof in zip(commitments, proof.coordinate_proofs, strict=True):
        if range_proof.bits != proof.bits:
            return False
        shifted = (commitment * g_bound) % group.p
        if not verify_range(shifted, range_proof, group=group, domain=domain):
            return False
    return True


# --- L2 bounded-norm (ADR-0005): commit-squares construction ---------------


@dataclass(frozen=True)
class SquareProof:
    """A Σ-proof that ``C_y`` commits to the square of the value in ``C_x``."""

    t1: int
    t2: int
    z_x: int
    z_rx: int
    z_r: int


def prove_square(
    value: int,
    blinding_x: int,
    blinding_y: int,
    *,
    group: SchnorrGroup,
    prefix: int,
    rng=None,
) -> tuple[int, SquareProof]:
    """Prove ``C_y`` commits to ``value²`` where ``C_x = g^{value} h^{blinding_x}``.

    Uses ``C_y = C_x^value · h^{blinding_y - value·blinding_x}`` (an AND of openings sharing
    the witness ``value``); returns ``(C_y, proof)``.
    """
    p, q, g, h = group.p, group.q, group.g, group.h
    x = value % q
    c_x = pedersen_commit(value, blinding_x, group)
    c_y = pedersen_commit((x * x) % q, blinding_y, group)
    r_prime = (blinding_y - x * blinding_x) % q
    k_x = _rand_scalar(group, rng)
    k_rx = _rand_scalar(group, rng)
    k_r = _rand_scalar(group, rng)
    t1 = (pow(g, k_x, p) * pow(h, k_rx, p)) % p
    t2 = (pow(c_x, k_x, p) * pow(h, k_r, p)) % p
    e = _challenge(group, prefix, c_x, c_y, t1, t2)
    return c_y, SquareProof(
        t1=t1,
        t2=t2,
        z_x=(k_x + e * x) % q,
        z_rx=(k_rx + e * blinding_x) % q,
        z_r=(k_r + e * r_prime) % q,
    )


def verify_square(
    c_x: int, c_y: int, proof: SquareProof, *, group: SchnorrGroup, prefix: int
) -> bool:
    """Verify a square-correctness proof (fail-closed)."""
    p, g, h = group.p, group.g, group.h
    e = _challenge(group, prefix, c_x, c_y, proof.t1, proof.t2)
    lhs1 = (pow(g, proof.z_x, p) * pow(h, proof.z_rx, p)) % p
    ok1 = lhs1 == (proof.t1 * pow(c_x, e, p)) % p
    lhs2 = (pow(c_x, proof.z_x, p) * pow(h, proof.z_r, p)) % p
    ok2 = lhs2 == (proof.t2 * pow(c_y, e, p)) % p
    return ok1 and ok2


@dataclass(frozen=True)
class L2BoundedProof:
    """A proof that a committed vector has ``Σ x_k² ≤ bound²`` (L2 norm ≤ bound)."""

    bound: int
    bits: int
    square_commitments: list[int]
    square_proofs: list[SquareProof]
    range_sum: RangeProof  # S = Σ x_k² ∈ [0, 2^bits)
    range_diff: RangeProof  # bound² − S ∈ [0, 2^bits)  ⇒  S ≤ bound²


def prove_l2_bounded(
    values: Sequence[int],
    blindings: Sequence[int],
    *,
    bound: int,
    group: SchnorrGroup = MODP2048_GROUP,
    rng=None,
) -> L2BoundedProof:
    """Prove ``‖values‖₂ ≤ bound`` for a committed vector, in zero knowledge.

    ``blindings`` are the blindings of the *existing* per-coordinate commitments
    ``C_x_k = g^{x_k} h^{r_k}``. Commits each square, proves correctness, and range-proves
    the homomorphic squared-norm ``S = Σ x_k²`` lies in ``[0, bound²]``.
    """
    if bound < 1:
        raise ProofError("bound must be >= 1")
    if len(values) != len(blindings):
        raise ProofError("values and blindings must have equal length")
    q = group.q
    m = bound * bound
    if not m < q:
        raise ProofError("bound² must fit the field (choose smaller bound or fixed-point scale)")
    prefix = _challenge(
        group,
        bound,
        *[pedersen_commit(v, r, group) for v, r in zip(values, blindings, strict=True)],
    )
    square_commitments: list[int] = []
    square_proofs: list[SquareProof] = []
    sq_blindings: list[int] = []
    for v, r in zip(values, blindings, strict=True):
        rb = _rand_scalar(group, rng)
        sq_blindings.append(rb)
        c_y, sp = prove_square(v, r, rb, group=group, prefix=prefix, rng=rng)
        square_commitments.append(c_y)
        square_proofs.append(sp)
    s_val = sum((v % q) * (v % q) for v in values) % q
    s_blind = sum(sq_blindings) % q
    if s_val > m:
        raise ProofError("squared norm exceeds bound² (L2 norm out of bound)")
    bits = m.bit_length()
    range_sum = prove_range(s_val, s_blind, bits=bits, group=group, rng=rng)
    range_diff = prove_range((m - s_val) % q, (-s_blind) % q, bits=bits, group=group, rng=rng)
    return L2BoundedProof(
        bound=bound,
        bits=bits,
        square_commitments=square_commitments,
        square_proofs=square_proofs,
        range_sum=range_sum,
        range_diff=range_diff,
    )


def verify_l2_bounded(
    commitments: Sequence[int],
    proof: L2BoundedProof,
    *,
    bound: int,
    group: SchnorrGroup = MODP2048_GROUP,
) -> bool:
    """Verify an L2 bounded-norm proof against per-coordinate commitments (fail-closed)."""
    p, q, g = group.p, group.q, group.g
    if proof.bound != bound:
        return False
    m = bound * bound
    if m >= q or proof.bits != m.bit_length():
        return False
    n = len(commitments)
    if len(proof.square_commitments) != n or len(proof.square_proofs) != n:
        return False
    prefix = _challenge(group, bound, *commitments)
    for c_x, c_y, sp in zip(
        commitments, proof.square_commitments, proof.square_proofs, strict=True
    ):
        if not verify_square(c_x, c_y, sp, group=group, prefix=prefix):
            return False
    # S = Σ x_k² is the homomorphic sum of the square commitments.
    s_commit = 1
    for c_y in proof.square_commitments:
        s_commit = (s_commit * c_y) % p
    if proof.range_sum.bits != proof.bits or proof.range_diff.bits != proof.bits:
        return False
    if not verify_range(s_commit, proof.range_sum, group=group):
        return False
    # C_diff = g^{bound²} · S_commit^{-1} commits to (bound² − S); range-proving it ≥ 0
    # establishes S ≤ bound².
    c_diff = (pow(g, m % q, p) * pow(s_commit, p - 2, p)) % p
    return verify_range(c_diff, proof.range_diff, group=group)


# --- Cross-commitment equality (ADR-0006 item 4): bind a Pedersen commitment to a
# Feldman commitment of the same value, so a bounded-norm proof over the Pedersen
# commitment constrains the value that was VSS-shared for GOD aggregation. -----------


@dataclass(frozen=True)
class EqualityProof:
    """A Schnorr proof that ``c_ped`` and ``c_fel`` commit the same value."""

    t: int
    z: int


def prove_commitment_equality(
    c_ped: int,
    c_fel: int,
    blinding: int,
    *,
    group: SchnorrGroup,
    prefix: int,
    rng=None,
) -> EqualityProof:
    """Prove ``c_ped = g^s h^blinding`` and ``c_fel = g^s`` commit the same ``s``.

    Their quotient ``c_ped · c_fel^{-1} = h^blinding`` is a pure power of ``h`` iff the
    ``g``-exponents match; this is a Schnorr proof of knowledge of ``blinding`` for it.
    """
    p, q, h = group.p, group.q, group.h
    d = (c_ped * pow(c_fel, p - 2, p)) % p
    k = _rand_scalar(group, rng)
    t = pow(h, k, p)
    e = _challenge(group, prefix, c_ped, c_fel, d, t)
    return EqualityProof(t=t, z=(k + e * blinding) % q)


def verify_commitment_equality(
    c_ped: int, c_fel: int, proof: EqualityProof, *, group: SchnorrGroup, prefix: int
) -> bool:
    """Verify a commitment-equality proof (fail-closed)."""
    p, h = group.p, group.h
    d = (c_ped * pow(c_fel, p - 2, p)) % p
    e = _challenge(group, prefix, c_ped, c_fel, d, proof.t)
    return pow(h, proof.z, p) == (proof.t * pow(d, e, p)) % p


# --- Whole-consortium aggregation: one bounded-norm proof object over all parties,
# cross-bound under a single Fiat-Shamir transcript (ADR-0004/0006 aggregation). ----


@dataclass(frozen=True)
class AggregatedBoundedProof:
    """One round-level bounded-norm proof covering every party, cross-bound by ``domain``."""

    bound: int
    party_order: list[str]
    proofs: dict[str, BoundedNormProof]


def _batch_domain(bound: int, party_commitments, party_order, group: SchnorrGroup) -> int:
    flat = [c for p in party_order for c in party_commitments[p]]
    return _challenge(group, bound, *flat)


def prove_bounded_batch(
    party_values: dict,
    party_blindings: dict,
    *,
    bound: int,
    group: SchnorrGroup = MODP2048_GROUP,
    rng=None,
) -> AggregatedBoundedProof:
    """Prove the L∞ bound for *every* party as one cross-bound proof object.

    Each party's per-coordinate proof is computed under a shared ``domain`` that hashes
    **all** parties' input commitments, so a proof cannot be replayed onto a different
    party's commitments and the batch verifies as a unit.
    """
    order = [str(p) for p in party_values]
    commitments = {
        str(p): [
            pedersen_commit(v, r, group)
            for v, r in zip(party_values[p], party_blindings[p], strict=True)
        ]
        for p in party_values
    }
    domain = _batch_domain(bound, commitments, order, group)
    proofs = {
        str(p): prove_bounded(
            party_values[p], party_blindings[p], bound=bound, group=group, rng=rng, domain=domain
        )
        for p in party_values
    }
    return AggregatedBoundedProof(bound=bound, party_order=order, proofs=proofs)


def verify_bounded_batch(
    party_commitments: dict,
    proof: AggregatedBoundedProof,
    *,
    bound: int,
    group: SchnorrGroup = MODP2048_GROUP,
) -> bool:
    """Verify an aggregated bounded-norm proof (fail-closed; binds the whole batch)."""
    if proof.bound != bound:
        return False
    keyed = {str(p): c for p, c in party_commitments.items()}
    if set(keyed) != set(proof.party_order):
        return False
    domain = _batch_domain(bound, keyed, proof.party_order, group)
    for p in proof.party_order:
        pf = proof.proofs[p]
        if pf.bound != bound or not verify_bounded(keyed[p], pf, group=group, domain=domain):
            return False
    return True
