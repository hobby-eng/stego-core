//! Symmetric J-MiPOD costs (Cogranne, Giboulot, Bas, TIFS 2021, without side information), with
//! Sedighi et al.'s variance estimator. The printed formulas have typos; the corrections used here
//! are listed in docs/TECHNICAL.md. Works in bounded tiles and gives the same bits for any order
//! of positions.

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

/// Per-direction change probabilities (`beta[i]` is each of +1 and −1, not their sum) and the
/// Lagrange multiplier. Wet positions get zero; the payload is met within
/// `1e-9 · max(payload_bits, 1)` bits. Errors: empty capacity, a bad payload, one-direction policies
/// and invalid shapes. Uses about 16 bytes per position plus tile buffers.
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
