//! Symmetric J-MiPOD costs from the TIFS model, without side information.
//!
//! This implements the non-side-informed objective of Cogranne, Giboulot and Bas,
//! DOI 10.1109/TIFS.2021.3111713, with the variance estimator of Sedighi, Cogranne
//! and Fridrich, DOI 10.1109/TIFS.2015.2486744. No embedding or JPEG I/O is done.
//!
//! A tiled statistics pass computes the Fisher information; the payload solver uses a Hermite
//! table of the ternary entropy and Newton's method on `ln λ` with a bisection fallback, finished
//! by exact passes that hold the payload to `1e-9` relative.
//!
//! Corrections to the printed TIFS formulas:
//! - Eq. (24): `P_perp = I - H (H^T H)^-1 H^T`.
//! - Covariance for a forward-DCT matrix `D` is `D Sigma D^T`.
//! - Eqs. (50)-(53): use the orthonormal JPEG DCT-II normalization.
//! - Eq. (29): `f(beta) = beta / log2(1 / beta - 2)`.
//!
//! Working images use bounded overlapping tiles; only blocks next to selected positions are
//! decoded in the second pass. A first, global pass estimates Wiener noise even when only a
//! subset of coefficients is selected. Results use `f64`; their order matches the caller's
//! positions, and a permutation of the positions gives the same bits. Single-threaded.

pub(crate) mod probability;
#[cfg(test)]
mod reference;
pub(crate) mod sampling;
pub(crate) mod statistics;

use crate::algorithm::model::{CostError, CostModel, Costs, DctPlane, Permitted};
use probability::{Output, View};
use sampling::Selection;

/// Symmetric J-MiPOD for luminance coefficients without side information.
#[derive(Clone, Copy, Debug, Default)]
pub struct JMiPod;

impl CostModel for JMiPod {
    fn costs(
        &self,
        plane: &DctPlane,
        positions: &[usize],
        permitted: &[Permitted],
        payload_bits: f64,
    ) -> Result<Costs, CostError> {
        let (plus, _, mut spare) = run(plane, positions, permitted, payload_bits, Output::Cost)?;
        // The log-FI buffer is no longer needed: reuse it for the second direction.
        spare.copy_from_slice(&plus);
        Ok(Costs { plus, minus: spare })
    }
}

/// Returns per-direction change probabilities and the TIFS Lagrange multiplier.
///
/// `beta[i]` is the probability of each of `+1` and `-1`, not their sum. A wet
/// position has zero probability. The multiplier satisfies
/// `beta / log2(1 / beta - 2) = lambda / smoothed_fisher` before the `1e-300` floor, and the
/// probabilities carry `payload_bits` within `1e-9 · max(payload_bits, 1)` bits.
/// Zero payload returns `lambda = 0` and the finite-cost floor `beta = 1e-300`
/// for `Both`. Empty capacity, invalid/non-finite payloads and payloads at or above
/// ternary capacity return [`CostError::Payload`]. One-direction policies return
/// [`CostError::Unsupported`]; invalid dimensions and positions use the shared errors.
///
/// Additional memory is about 16 bytes per position (plus 4 when the positions are not
/// ascending) plus bounded tile buffers.
pub fn change_probabilities(
    plane: &DctPlane,
    positions: &[usize],
    permitted: &[Permitted],
    payload_bits: f64,
) -> Result<(Vec<f64>, f64), CostError> {
    let (beta, lambda, _) = run(plane, positions, permitted, payload_bits, Output::Beta)?;
    Ok((beta, lambda))
}

/// Smoothed Fisher information `FI~ = Δ⁴ Σ w σ⁻⁴` (TIFS eq. 26–27) of each position.
///
/// The variance and smoothing stage on its own, for models that weight it further, such as
/// the side-informed variant (`FI · (1 − 2|e|)⁴`). Errors are those of
/// [`change_probabilities`] for the plane and the positions.
pub fn fisher_information(plane: &DctPlane, positions: &[usize]) -> Result<Vec<f64>, CostError> {
    let permitted = vec![Permitted::Both; positions.len()];
    let selection = Selection::new(plane, positions, &permitted)?;
    Ok(statistics::fisher_information(plane, &selection))
}

/// Validates, estimates FI, solves `λ` and writes `output` per position. Returns the output,
/// `λ`, and the freed log-FI buffer (same length) for reuse.
fn run(
    plane: &DctPlane,
    positions: &[usize],
    permitted: &[Permitted],
    payload_bits: f64,
    output: Output,
) -> Result<(Vec<f64>, f64, Vec<f64>), CostError> {
    let selection = Selection::new(plane, positions, permitted)?;
    probability::validate_payload(selection.capacity(), payload_bits)?;
    if payload_bits == 0.0 {
        let floor = match output {
            Output::Beta => probability::MIN_BETA,
            Output::Cost => probability::RHO_MAX,
        };
        let wet = match output {
            Output::Beta => 0.0,
            Output::Cost => f64::INFINITY,
        };
        let out: Vec<f64> = permitted
            .iter()
            .map(|p| if *p == Permitted::Both { floor } else { wet })
            .collect();
        let spare = vec![0.0; out.len()];
        return Ok((out, 0.0, spare));
    }
    // Zero marks a wet position (smoothed FI is always positive); its log is NEG_INFINITY.
    let mut ln_fi = statistics::fisher_information(plane, &selection);
    for value in &mut ln_fi {
        *value = value.ln();
    }
    let mut out = vec![0.0; ln_fi.len()];
    let view = View {
        values: &ln_fi,
        order: selection.order(),
    };
    let ln_lambda = probability::solve(view, payload_bits, &mut out, output)?;
    Ok((out, ln_lambda.exp(), ln_fi))
}

#[cfg(test)]
mod tests;
