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
//!   * an L∞ bound `B` is proven by range-proving the shifted value `u + B ∈ [0, 2^n)`
//!     against the shifted commitment `C_u + B·B_basepoint` (mirroring the MODP `C·g^B`).
//!
//! The two backends are NOT byte-compatible; CI cross-validates decision equivalence only.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

const TRANSCRIPT_LABEL: &[u8] = b"presidio-hardened-ai/zk/bulletproofs/v1";

fn scalar_from_le(bytes: &[u8]) -> PyResult<Scalar> {
    if bytes.len() != 32 {
        return Err(PyValueError::new_err("blinding must be 32 little-endian bytes"));
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

fn point_from_bytes(bytes: &[u8]) -> PyResult<curve25519_dalek::ristretto::RistrettoPoint> {
    if bytes.len() != 32 {
        return Err(PyValueError::new_err("commitment must be 32 bytes"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| PyValueError::new_err("invalid Ristretto commitment"))
}

/// dalek requires a power-of-two aggregation size and n in {8,16,32,64}.
fn range_bits(bound: u64) -> PyResult<usize> {
    // need 2^n > 2*bound (shifted value lives in [0, 2*bound]).
    let need = (2 * bound + 1).next_power_of_two().trailing_zeros() as usize;
    for &n in &[8usize, 16, 32, 64] {
        if n >= need {
            return Ok(n);
        }
    }
    Err(PyValueError::new_err("bound too large for a 64-bit range proof"))
}

#[pyfunction]
fn pedersen_commit(py: Python<'_>, value: i64, blinding: &[u8]) -> PyResult<PyObject> {
    let pc = PedersenGens::default();
    let r = scalar_from_le(blinding)?;
    let point = pc.commit(scalar_from_i64(value), r).compress();
    Ok(PyBytes::new_bound(py, point.as_bytes()).into())
}

#[pyfunction]
fn pedersen_add(py: Python<'_>, a: &[u8], b: &[u8]) -> PyResult<PyObject> {
    let sum = (point_from_bytes(a)? + point_from_bytes(b)?).compress();
    Ok(PyBytes::new_bound(py, sum.as_bytes()).into())
}

#[pyfunction]
fn pedersen_sum(py: Python<'_>, commitments: Vec<Vec<u8>>) -> PyResult<PyObject> {
    let mut acc = curve25519_dalek::ristretto::RistrettoPoint::default();
    for c in &commitments {
        acc += point_from_bytes(c)?;
    }
    Ok(PyBytes::new_bound(py, acc.compress().as_bytes()).into())
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
) -> PyResult<PyObject> {
    if values.len() != blindings.len() {
        return Err(PyValueError::new_err("values and blindings must have equal length"));
    }
    let n = range_bits(bound)?;
    let mut shifted: Vec<u64> = Vec::with_capacity(values.len());
    for &u in &values {
        if u < -(bound as i64) || u > bound as i64 {
            return Err(PyValueError::new_err("a value is outside [-bound, bound]"));
        }
        shifted.push((u + bound as i64) as u64);
    }
    let mut scalars: Vec<Scalar> = Vec::with_capacity(blindings.len());
    for b in &blindings {
        scalars.push(scalar_from_le(b)?);
    }
    let (shifted, scalars) = padded_pow2(shifted, scalars);
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(64, shifted.len());
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    let (proof, _commitments) =
        RangeProof::prove_multiple(&bp, &pc, &mut transcript, &shifted, &scalars, n)
            .map_err(|e| PyValueError::new_err(format!("prove failed: {e:?}")))?;
    Ok(PyBytes::new_bound(py, &proof.to_bytes()).into())
}

#[pyfunction]
fn verify_bounded(
    commitments: Vec<Vec<u8>>,
    proof: &[u8],
    bound: u64,
) -> PyResult<bool> {
    let n = match range_bits(bound) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    let pc = PedersenGens::default();
    let shift = scalar_from_i64(bound as i64) * pc.B; // bound·B_basepoint
    // Shift each commitment-to-u into commitment-to-(u+bound), padding to a power of two
    // with commitments to 0 (the prover padded with zero values + zero blindings).
    let mut shifted: Vec<CompressedRistretto> = Vec::new();
    for c in &commitments {
        let p = match point_from_bytes(c) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        shifted.push((p + shift).compress());
    }
    let zero_shift = shift.compress(); // commitment to value 0 shifted by bound
    while shifted.len() < shifted.len().max(1).next_power_of_two() {
        shifted.push(zero_shift);
    }
    let proof = match RangeProof::from_bytes(proof) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    Ok(proof
        .verify_multiple(&BulletproofGens::new(64, shifted.len()), &pc, &mut transcript, &shifted, n)
        .is_ok())
}

#[pymodule]
fn presidio_ai_zk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__backend_name__", "ristretto255-bulletproofs")?;
    m.add_function(wrap_pyfunction!(pedersen_commit, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_add, m)?)?;
    m.add_function(wrap_pyfunction!(pedersen_sum, m)?)?;
    m.add_function(wrap_pyfunction!(prove_bounded, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bounded, m)?)?;
    Ok(())
}
