//! Ristretto255 + Bulletproofs bounded-norm proofs (ADR-0004), exposed to Python via PyO3.
//!
//! This is the audited-crypto, `O(log n)` performance backend for the bounded-norm input
//! validation specified in ADR-0003. It wraps the dalek `bulletproofs` + `curve25519-dalek`
//! crates and presents the same logical operations as the pure-Python MODP fallback:
//! Pedersen commitments (with a homomorphic sum) and an aggregated L∞ range proof.
//!
//! Conventions matching the Python `ProofBackend` interface:
//!   * commitments are 32-byte compressed Ristretto points;
//!   * blindings arrive as 32 little-endian bytes, reduced mod the group order;
//!   * a value `u` is committed as `u·B + r·B_blinding` (signed `u`, two's-complement into
//!     the scalar field), so the same commitment is range-provable and homomorphically
//!     summable — identical semantics to the MODP backend;
//!   * an L∞ bound `B` is proven from both sides: `u + B ∈ [0, 2^n)` against
//!     `C_u + B·B_basepoint` and `B − u ∈ [0, 2^n)` against `B·B_basepoint − C_u`
//!     (mirroring the MODP `C·g^B` and `g^B·C^{-1}`). The two openings sum to `2B` and
//!     `2^{n+1}` is far below the group order, so together they force `u ∈ [-B, B]`; one
//!     side alone would admit `u` up to `2^n − 1 − B`, and `n` is rounded up to 8/16/32/64.
//!
//! The two backends are NOT byte-compatible; CI cross-validates decision equivalence only.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

const TRANSCRIPT_LABEL: &[u8] = b"presidio-hardened-ai/zk/bulletproofs/v2";

fn scalar_from_le(bytes: &[u8]) -> PyResult<Scalar> {
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(
            "blinding must be 32 little-endian bytes",
        ));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    Ok(Scalar::from_bytes_mod_order(b))
}

fn scalar_from_i64(value: i64) -> Scalar {
    if value >= 0 {
        Scalar::from(value as u64)
    } else {
        -Scalar::from((-value) as u64)
    }
}

fn point_from_bytes(bytes: &[u8]) -> PyResult<RistrettoPoint> {
    let compressed = CompressedRistretto::from_slice(bytes)
        .map_err(|_| PyValueError::new_err("commitment must be 32 bytes"))?;
    compressed
        .decompress()
        .ok_or_else(|| PyValueError::new_err("invalid Ristretto commitment"))
}

/// Largest supported bound: `2·bound` must fit a 64-bit range proof and `bound` an `i64`.
const MAX_BOUND: u64 = 1 << 62;

/// dalek requires a power-of-two aggregation size and n in {8,16,32,64}.
fn range_bits(bound: u64) -> PyResult<usize> {
    if bound > MAX_BOUND {
        return Err(PyValueError::new_err(
            "bound too large for a 64-bit range proof",
        ));
    }
    // need 2^n > 2*bound (each side's shifted value lives in [0, 2*bound]).
    let need = (2 * bound + 1).next_power_of_two().trailing_zeros() as usize;
    for &n in &[8usize, 16, 32, 64] {
        if n >= need {
            return Ok(n);
        }
    }
    Err(PyValueError::new_err(
        "bound too large for a 64-bit range proof",
    ))
}

#[pyfunction]
fn pedersen_commit(py: Python<'_>, value: i64, blinding: &[u8]) -> PyResult<Py<PyAny>> {
    let pc = PedersenGens::default();
    let r = scalar_from_le(blinding)?;
    let point = pc.commit(scalar_from_i64(value), r).compress();
    Ok(PyBytes::new(py, point.as_bytes()).into_any().unbind())
}

#[pyfunction]
fn pedersen_add(py: Python<'_>, a: &[u8], b: &[u8]) -> PyResult<Py<PyAny>> {
    let sum = (point_from_bytes(a)? + point_from_bytes(b)?).compress();
    Ok(PyBytes::new(py, sum.as_bytes()).into_any().unbind())
}

#[pyfunction]
fn pedersen_sum(py: Python<'_>, commitments: Vec<Vec<u8>>) -> PyResult<Py<PyAny>> {
    let mut acc = RistrettoPoint::identity();
    for c in &commitments {
        acc += point_from_bytes(c)?;
    }
    Ok(PyBytes::new(py, acc.compress().as_bytes())
        .into_any()
        .unbind())
}

/// Transcript bound to the statement: the L∞ bound and the vector length, so a proof made
/// for one bound or length cannot be checked against another.
fn bound_transcript(bound: u64, len: usize) -> Transcript {
    let mut t = Transcript::new(TRANSCRIPT_LABEL);
    t.append_u64(b"bound", bound);
    t.append_u64(b"len", len as u64);
    t
}

fn padded_pow2(mut values: Vec<u64>, mut blindings: Vec<Scalar>) -> (Vec<u64>, Vec<Scalar>) {
    let target = values.len().max(1).next_power_of_two();
    while values.len() < target {
        values.push(0);
        blindings.push(Scalar::ZERO);
    }
    (values, blindings)
}

#[pyfunction]
fn prove_bounded(
    py: Python<'_>,
    values: Vec<i64>,
    blindings: Vec<Vec<u8>>,
    bound: u64,
) -> PyResult<Py<PyAny>> {
    if values.len() != blindings.len() {
        return Err(PyValueError::new_err(
            "values and blindings must have equal length",
        ));
    }
    let n = range_bits(bound)?;
    let b = bound as i64; // range_bits capped bound at 2^62
    let mut lower: Vec<u64> = Vec::with_capacity(2 * values.len());
    let mut upper: Vec<u64> = Vec::with_capacity(values.len());
    for &u in &values {
        if u < -b || u > b {
            return Err(PyValueError::new_err("a value is outside [-bound, bound]"));
        }
        lower.push((u + b) as u64);
        upper.push((b - u) as u64);
    }
    let mut scalars: Vec<Scalar> = Vec::with_capacity(2 * blindings.len());
    for bl in &blindings {
        scalars.push(scalar_from_le(bl)?);
    }
    let negated: Vec<Scalar> = scalars.iter().map(|r| -r).collect();
    // Layout: [u_k + B for all k] ++ [B - u_k for all k], then identity padding.
    lower.extend(upper);
    scalars.extend(negated);
    let (shifted, scalars) = padded_pow2(lower, scalars);
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(64, shifted.len());
    let mut transcript = bound_transcript(bound, values.len());
    let (proof, _commitments) =
        RangeProof::prove_multiple(&bp, &pc, &mut transcript, &shifted, &scalars, n)
            .map_err(|e| PyValueError::new_err(format!("prove failed: {e:?}")))?;
    Ok(PyBytes::new(py, &proof.to_bytes()).into_any().unbind())
}

#[pyfunction]
fn verify_bounded(commitments: Vec<Vec<u8>>, proof: &[u8], bound: u64) -> PyResult<bool> {
    let n = match range_bits(bound) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    let pc = PedersenGens::default();
    // shift = bound·B_basepoint. Same layout as the prover: commitments to (u+bound), then to (bound-u), then
    // identity padding (the prover pads with value 0 and blinding 0, i.e. the identity).
    let shift = pc.B * scalar_from_i64(bound as i64);
    let mut points: Vec<RistrettoPoint> = Vec::with_capacity(commitments.len());
    for c in &commitments {
        match point_from_bytes(c) {
            Ok(p) => points.push(p),
            Err(_) => return Ok(false),
        }
    }
    let mut shifted: Vec<CompressedRistretto> = Vec::with_capacity(2 * points.len());
    shifted.extend(points.iter().map(|p| (p + shift).compress()));
    shifted.extend(points.iter().map(|p| (shift - p).compress()));
    let target = shifted.len().max(1).next_power_of_two();
    let identity = RistrettoPoint::identity().compress();
    while shifted.len() < target {
        shifted.push(identity);
    }
    let proof = match RangeProof::from_bytes(proof) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let mut transcript = bound_transcript(bound, points.len());
    Ok(proof
        .verify_multiple(
            &BulletproofGens::new(64, shifted.len()),
            &pc,
            &mut transcript,
            &shifted,
            n,
        )
        .is_ok())
}

#[pyfunction]
fn point_mul(py: Python<'_>, point: &[u8], scalar_le: &[u8]) -> PyResult<Py<PyAny>> {
    let p = point_from_bytes(point)?;
    let s = scalar_from_le(scalar_le)?;
    Ok(PyBytes::new(py, (p * s).compress().as_bytes())
        .into_any()
        .unbind())
}

#[pyfunction]
fn pedersen_commit_scalar(
    py: Python<'_>,
    value_le: &[u8],
    blinding_le: &[u8],
) -> PyResult<Py<PyAny>> {
    // value*B + blinding*B_blinding, with both as full scalars (for Sigma-protocol terms
    // whose exponents are challenge-sized, not i64).
    let pc = PedersenGens::default();
    let v = scalar_from_le(value_le)?;
    let r = scalar_from_le(blinding_le)?;
    Ok(
        PyBytes::new(py, (pc.B * v + pc.B_blinding * r).compress().as_bytes())
            .into_any()
            .unbind(),
    )
}

#[pymodule]
fn presidio_ai_zk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__backend_name__", "ristretto255-bulletproofs")?;
    m.add_function(wrap_pyfunction!(pedersen_commit, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_add, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_sum, m)?)?;
    m.add_function(wrap_pyfunction!(prove_bounded, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bounded, m)?)?;
    m.add_function(wrap_pyfunction!(point_mul, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_commit_scalar, m)?)?;
    Ok(())
}
