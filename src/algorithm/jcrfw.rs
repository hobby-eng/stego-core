//! J-CRFW and J-CRF costs (Pan, Ni, Liu, Su, Huang, "Efficient JPEG image steganography using
//! pairwise conditional random field model", Signal Processing 221:109493, 2024), written from
//! the paper; no author code exists publicly. A research prototype next to J-UNIWARD and J-MiPOD.
//!
//! The model is J-MiPOD's Gaussian model of the quantized coefficients extended with the
//! correlation `ϱ` between the same mode of horizontally and vertically neighbouring blocks.
//! Detectability is the energy of a pairwise CRF (eq. 11, 16, 22, 24): per coefficient
//! `β²/σ⁴`, per edge `[β_i²/σ_i⁴ + β_j²/σ_j⁴ + 2ϱ²β_iβ_j/(σ_i²σ_j²)] / (1 − ϱ²)²`, with `σ²` in
//! quantization steps. Minimizing it at payload `Σ H3(β) = R` gives (eq. 27–29)
//! `β_i · FI_i = λ · log2(1/β_i − 2)` with the effective information
//! `FI_i = w_u [w_b/σ_i⁴ + Σ_j w_ij/(σ_i⁴(1−ϱ²)²) + Σ_j w_ij ϱ²/(σ_i²σ_j²(1−ϱ²)²) · β_j/β_i]`
//! over the existing neighbours `j` (the common factor 2 is dropped; it only rescales `λ`).
//! The last term couples neighbours, so the paper iterates: start with `β_j/β_i = 1` (0 for a
//! neighbour that cannot change), solve as J-MiPOD does, update the ratios, repeat. Each update
//! lowers the energy at the payload (a majorization step). The paper reports that three updates
//! usually suffice; by default we update until the `β` map moves by less than 1e-6 of its total
//! (about a dozen updates on photos, at most 60) and [`JCrfw::with_iterations`] sets a fixed
//! count. Updates before the last use the entropy table only; the last one is exact.
//!
//! J-CRF has all weights 1. J-CRFW (Sec. 4.2) weights each block by its summed S-UNIWARD
//! costs, each edge by the mean of its two blocks and the last zigzag modes by 5 (`weights.rs`).
//! Costs are `ρ = ln(1/β − 2)` (eq. 30), as in J-MiPOD.
//!
//! Tiles and sparse decoding are shared with J-MiPOD; the S-UNIWARD weights follow the
//! convention of the reference code and conseal; the frozen-ratio updates use J-MiPOD's payload
//! solver. The window arithmetic sums the residual directly, costs stay finite and exact where
//! `β` underflows, and [`Solution`] reports diagnostics (energy, the residual of the original
//! optimality condition). An exact coordinate solver of every position is not used: with the
//! same weights it moved the `β` map of photos by at most 5e-6 of its total, at 2 to 30 times
//! the CPU time.
//!
//! Choices the paper leaves open, all ours: pixels decoded without rounding or +128, as in
//! J-MiPOD here; an edge exists only between blocks inside the image; a neighbour that is not
//! selected or is wet has `β = 0`; the stopping rule above; [`FrequencyProfile::Auto`].

#[cfg(test)]
mod reference;
mod statistics;
mod weights;

use std::f64::consts::LN_2;

use crate::algorithm::jmipod::probability::{self, Output, View};
use crate::algorithm::jmipod::sampling::{Selection, Sum};
use crate::algorithm::model::{BLOCK, CostError, CostModel, Costs, DctPlane, Permitted};

/// Updates of the coupled solve at most, the exact one included.
const MAX_ITERATIONS: usize = 60;
/// Convergence: the `β` map moves by at most this share of `Σ β` in one update.
const CONVERGED: f64 = 1e-6;

/// Which zigzag modes J-CRFW weighs by 5.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FrequencyProfile {
    /// The number of heavy modes follows the IJG quality estimated from the quantization
    /// table: the paper's 16 at quality 75 and 3 at 95, linear between and beyond, within
    /// `0..=16`. Our extension for other qualities.
    #[default]
    Auto,
    /// The paper's quality-75 profile: the last 16 zigzag modes.
    Paper75,
    /// The paper's quality-95 profile: the last 3 zigzag modes.
    Paper95,
    /// No heavy modes.
    Uniform,
}

impl FrequencyProfile {
    /// Number of heavy modes for a quantization table.
    fn heavy_modes(self, quant: &[u16; BLOCK]) -> usize {
        match self {
            Self::Auto => weights::heavy_modes(quant),
            Self::Paper75 => 16,
            Self::Paper95 => 3,
            Self::Uniform => 0,
        }
    }
}

/// J-CRFW (the default, [`JCrfw::new`]) or J-CRF ([`JCrfw::unweighted`]).
#[derive(Clone, Copy, Debug)]
pub struct JCrfw {
    weighted: bool,
    profile: FrequencyProfile,
    iterations: Option<usize>,
}

impl Default for JCrfw {
    fn default() -> Self {
        Self::new(FrequencyProfile::Auto)
    }
}

/// Probabilities, costs and diagnostics of one solve.
#[derive(Clone, Debug)]
pub struct Solution {
    /// Probability of each of `+1` and `−1` per position, in caller order; 0 for wet positions.
    /// A permitted position whose cost exceeds about 745 has `β` rounded to 0 too.
    pub beta: Vec<f64>,
    /// Cost `ρ = ln(1/β − 2)` per position, solved directly, so finite where `β` underflows;
    /// infinite for wet positions.
    pub rho: Vec<f64>,
    /// The multiplier of `β_i · FI_i = λ · log2(1/β_i − 2)`.
    pub lambda: f64,
    /// Updates of the `β` map, the exact one included.
    pub iterations: usize,
    /// Whether the last table update moved the map by at most 1e-6 of its total; false for a
    /// single update.
    pub converged: bool,
    /// Payload of the returned probabilities, `Σ H3(β)` in bits.
    pub entropy_bits: f64,
    /// CRF energy of the returned probabilities in the units of `λ`, each edge once.
    pub energy: f64,
    /// Mean relative residual of the optimality condition at the returned `β`, weighted by
    /// `β`: the share of the change probability that is not yet stationary.
    pub kkt_residual: f64,
    /// Largest relative residual of the optimality condition over the permitted positions.
    /// Coefficients with tiny `β` and strong coupling settle slowest and dominate it.
    pub kkt_max: f64,
}

impl JCrfw {
    /// J-CRFW with the paper's block, edge and mode weights.
    pub fn new(profile: FrequencyProfile) -> Self {
        Self {
            weighted: true,
            profile,
            iterations: None,
        }
    }

    /// Plain J-CRF: all weights 1.
    pub fn unweighted() -> Self {
        Self {
            weighted: false,
            profile: FrequencyProfile::Uniform,
            iterations: None,
        }
    }

    /// Exactly `count` updates of the `β` map (at least one) instead of updating until it
    /// settles. The paper uses three.
    #[must_use]
    pub fn with_iterations(mut self, count: usize) -> Self {
        self.iterations = Some(count.max(1));
        self
    }

    /// Change probabilities, costs and diagnostics per position.
    ///
    /// The payload is held to `1e-9 · max(R, 1)` bits; in the rare case that the exact passes
    /// run out first, to `max(1 bit, 1e-6 R)` (J-MiPOD's requirement 4.6), and
    /// [`Solution::entropy_bits`] shows the value reached.
    ///
    /// Errors: [`CostError::Shape`] or [`CostError::Quantization`] for an invalid plane,
    /// [`CostError::Permission`] for mismatched, out-of-range or repeated positions,
    /// [`CostError::Unsupported`] for one-direction permissions, [`CostError::Payload`] for a
    /// payload that is not finite, negative or at least the ternary capacity of the permitted
    /// positions. Zero payload returns `λ = 0`, `β = 1e-300` and `ρ ≈ 690.8` for permitted
    /// positions, as J-MiPOD does.
    ///
    /// Working memory is about 24 bytes per position plus the per-block terms and bounded tiles.
    pub fn change_probabilities(
        &self,
        plane: &DctPlane,
        positions: &[usize],
        permitted: &[Permitted],
        payload_bits: f64,
    ) -> Result<Solution, CostError> {
        let selection = Selection::new(plane, positions, permitted)?;
        probability::validate_payload(selection.capacity(), payload_bits)?;
        if payload_bits == 0.0 {
            return Ok(zero_payload(permitted));
        }
        let coupling = Coupling::new(self, plane, positions, &selection);
        coupling.solve(payload_bits, self.iterations)
    }
}

impl CostModel for JCrfw {
    fn costs(
        &self,
        plane: &DctPlane,
        positions: &[usize],
        permitted: &[Permitted],
        payload_bits: f64,
    ) -> Result<Costs, CostError> {
        let plus = self
            .change_probabilities(plane, positions, permitted, payload_bits)?
            .rho;
        let minus = plus.clone();
        Ok(Costs { plus, minus })
    }
}

/// The solution at zero payload: every permitted position at J-MiPOD's floor.
fn zero_payload(permitted: &[Permitted]) -> Solution {
    let both = |p: &Permitted| *p == Permitted::Both;
    let beta: Vec<f64> = permitted
        .iter()
        .map(|p| if both(p) { probability::MIN_BETA } else { 0.0 })
        .collect();
    let rho = permitted
        .iter()
        .map(|p| {
            if both(p) {
                probability::RHO_MAX
            } else {
                f64::INFINITY
            }
        })
        .collect();
    let mut bits = Sum::new();
    for (&b, p) in beta.iter().zip(permitted) {
        if both(p) {
            bits.add(ternary_bits(b, probability::RHO_MAX));
        }
    }
    Solution {
        beta,
        rho,
        lambda: 0.0,
        iterations: 0,
        converged: true,
        entropy_bits: bits.value(),
        energy: 0.0,
        kkt_residual: 0.0,
        kkt_max: 0.0,
    }
}

/// `H3(β)` in bits from `β` and `ρ = ln(1/β − 2)`, without cancellation at either end.
fn ternary_bits(beta: f64, rho: f64) -> f64 {
    (2.0 * beta * rho + (2.0 * (-rho).exp()).ln_1p()) / LN_2
}

/// Everything the effective Fisher information of a position needs.
struct Coupling<'a> {
    plane: &'a DctPlane,
    positions: &'a [usize],
    selection: &'a Selection<'a>,
    /// Variance in quantization steps per position.
    variance: Vec<f64>,
    /// Per block: its own weight plus `Σ w_e/(1 − ϱ_e²)²` over its edges (the uncoupled factor
    /// of `1/σ⁴`), and per edge to the right and down `w_e ϱ²/(1 − ϱ²)²` (the coupled factor).
    blocks: Vec<BlockTerms>,
    /// The mode weights and their logarithms.
    mode_weight: [f64; BLOCK],
    ln_mode_weight: [f64; BLOCK],
}

/// Iteration-independent factors of one block.
#[derive(Clone, Copy, Default)]
struct BlockTerms {
    uncoupled: f64,
    right: f64,
    down: f64,
}

/// Diagnostics of a solution (see [`Solution`]).
struct Diagnostics {
    entropy_bits: f64,
    energy: f64,
    kkt_residual: f64,
    kkt_max: f64,
}

impl<'a> Coupling<'a> {
    fn new(
        model: &JCrfw,
        plane: &'a DctPlane,
        positions: &'a [usize],
        selection: &'a Selection<'a>,
    ) -> Self {
        let statistics = statistics::model(plane, selection);
        let (wide, high) = (plane.blocks_wide, plane.blocks_high);
        let mut needed = vec![false; wide * high];
        for (index, &position) in positions.iter().enumerate() {
            if selection.permission(index) == Permitted::Both {
                let block = position / BLOCK;
                needed[block] = true;
                for (nx, ny) in statistics::cross(block % wide, block / wide, plane)
                    .into_iter()
                    .flatten()
                {
                    needed[ny * wide + nx] = true;
                }
            }
        }
        let (block_weight, mode_weight) = if model.weighted {
            (
                weights::block_weights(plane, &needed),
                weights::mode_weights(model.profile.heavy_modes(&plane.quant)),
            )
        } else {
            (vec![1.0; wide * high], [1.0; BLOCK])
        };
        let edge = |a: usize, b: usize, rho: f64| -> (f64, f64) {
            let rho = if rho.is_nan() { 0.0 } else { rho };
            let squared = rho * rho;
            let damp = (1.0 - squared) * (1.0 - squared);
            let weight = 0.5 * (block_weight[a] + block_weight[b]);
            (weight / damp, weight * squared / damp)
        };
        let mut blocks = vec![BlockTerms::default(); wide * high];
        for block in (0..wide * high).filter(|&b| needed[b]) {
            blocks[block].uncoupled += block_weight[block];
            let (bx, by) = (block % wide, block / wide);
            if bx + 1 < wide && needed[block + 1] {
                let (u, q) = edge(block, block + 1, statistics.right[block]);
                blocks[block].uncoupled += u;
                blocks[block + 1].uncoupled += u;
                blocks[block].right = q;
            }
            if by + 1 < high && needed[block + wide] {
                let (u, q) = edge(block, block + wide, statistics.down[block]);
                blocks[block].uncoupled += u;
                blocks[block + wide].uncoupled += u;
                blocks[block].down = q;
            }
        }
        Self {
            plane,
            positions,
            selection,
            variance: statistics.variance,
            blocks,
            mode_weight,
            ln_mode_weight: mode_weight.map(f64::ln),
        }
    }

    /// The two parts of `FI_i β_i / w_u` at position `index`: the uncoupled factor
    /// `A_i = w_b/σ⁴ + Σ w_ij/(σ⁴(1−ϱ²)²)` and the coupled sum `Σ_j c_ij x_j` with
    /// `c_ij = w_ij ϱ²/(σ_i²σ_j²(1−ϱ²)²)` and `x_j = β_j`, or 1 when `first`.
    fn terms(&self, index: usize, beta: &[f64], first: bool) -> (f64, f64) {
        let position = self.positions[index];
        let (block, mode) = (position / BLOCK, position % BLOCK);
        let wide = self.plane.blocks_wide;
        let (bx, by) = (block % wide, block / wide);
        let variance = self.variance[index];
        let uncoupled = self.blocks[block].uncoupled / (variance * variance);
        // Edges: (neighbour block, coupled factor of the edge).
        let edges = [
            (bx > 0).then(|| (block - 1, self.blocks[block - 1].right)),
            (bx + 1 < wide).then(|| (block + 1, self.blocks[block].right)),
            (by > 0).then(|| (block - wide, self.blocks[block - wide].down)),
            (by + 1 < self.plane.blocks_high).then(|| (block + wide, self.blocks[block].down)),
        ];
        let mut coupled = 0.0;
        for (other, factor) in edges.into_iter().flatten() {
            if factor == 0.0 {
                continue;
            }
            let Some(j) = self.selection.index_of(other * BLOCK + mode) else {
                continue;
            };
            if self.selection.permission(j) == Permitted::Both {
                let x = if first { 1.0 } else { beta[j] };
                coupled += factor * x / (variance * self.variance[j]);
            }
        }
        (uncoupled, coupled)
    }

    /// `ln FI` of position `index` with the ratios `β_j/β_i` of `beta` (1 when `first`).
    fn ln_information(&self, index: usize, beta: &[f64], first: bool) -> f64 {
        let (uncoupled, coupled) = self.terms(index, beta, first);
        let scale = self.ln_mode_weight[self.positions[index] % BLOCK];
        if first {
            scale + (uncoupled + coupled).ln()
        } else {
            // FI = w_u (A + Σ c_j β_j / β_i), formed without dividing by a tiny β_i.
            scale + uncoupled.mul_add(beta[index], coupled).ln() - beta[index].ln()
        }
    }

    /// Recomputes `ln FI` of every permitted position from `β` (ratio 1 when `first`).
    fn refresh(&self, beta: &[f64], first: bool, ln_fi: &mut [f64]) {
        for (index, value) in ln_fi.iter_mut().enumerate() {
            *value = if self.selection.permission(index) == Permitted::Both {
                self.ln_information(index, beta, first)
            } else {
                f64::NEG_INFINITY
            };
        }
    }

    fn view<'v>(&'v self, ln_fi: &'v [f64]) -> View<'v> {
        View {
            values: ln_fi,
            order: self.selection.order(),
        }
    }

    /// The coupled updates and the solution.
    ///
    /// Every update but the last solves `λ` and `β` from the entropy table only; it stops once
    /// the map moves by less than `CONVERGED` of its total, or after `fixed − 1` updates. The
    /// last update refreshes `FI` and runs the exact solver. The costs are then solved once
    /// more without the cap of the payload search (`final_cost`), and `β` follows from them.
    fn solve(&self, payload: f64, fixed: Option<usize>) -> Result<Solution, CostError> {
        let n = self.positions.len();
        let mut ln_fi = vec![f64::NEG_INFINITY; n];
        let mut beta = vec![0.0; n];
        let table_limit = fixed.map_or(MAX_ITERATIONS, |count| count.max(1)) - 1;
        let (mut updates, mut converged) = (0, false);
        while updates < table_limit {
            self.refresh(&beta, updates == 0, &mut ln_fi);
            let view = self.view(&ln_fi);
            let ln_lambda = probability::table_lambda(view, payload)?;
            let (moved, total) = probability::table_beta(view, ln_lambda, &mut beta);
            updates += 1;
            converged = updates > 1 && moved <= CONVERGED * total;
            if converged && fixed.is_none() {
                break;
            }
        }
        self.refresh(&beta, updates == 0, &mut ln_fi);
        let ln_lambda = probability::solve(self.view(&ln_fi), payload, &mut beta, Output::Beta)?;
        // The ln FI buffer becomes the costs; all of them are read from the same β first, so
        // the order of the positions does not matter.
        let mut rho = ln_fi;
        for (index, value) in rho.iter_mut().enumerate() {
            *value = self.final_cost(index, *value, &beta, ln_lambda);
        }
        for (value, b) in rho.iter().zip(beta.iter_mut()) {
            if value.is_finite() {
                *b = probability::beta((-*value).exp());
            }
        }
        let lambda = ln_lambda.exp();
        let diagnostics = self.diagnostics(&beta, &rho, lambda);
        Ok(Solution {
            beta,
            rho,
            lambda,
            iterations: updates + 1,
            converged,
            entropy_bits: diagnostics.entropy_bits,
            energy: diagnostics.energy,
            kkt_residual: diagnostics.kkt_residual,
            kkt_max: diagnostics.kkt_max,
        })
    }

    /// The cost of position `index` from its `ln FI` at the last update.
    ///
    /// Below the floor's cost this is the exact solver's `ρ` again. At or above it, the payload
    /// search kept `β` at the floor 1e-300 and `FI` divided the coupled sum by that floor, so
    /// the cost solves the optimality condition with the neighbours' final `β` instead:
    /// `λρ/ln 2 = w_u (A β(ρ) + C)`, i.e. `ρ = s + a β(ρ)` with `s = ln 2 · w_u C/λ` and
    /// `a = ln 2 · w_u A/λ` (a coordinate solve). Its root lies between
    /// `max(s, ρ_A)` and `s + ρ_A`, where `ρ_A` is the cost without the coupled sum.
    fn final_cost(&self, index: usize, ln_fi: f64, beta: &[f64], ln_lambda: f64) -> f64 {
        let rho = probability::uncapped_cost(ln_fi, ln_lambda);
        if rho < probability::RHO_MAX || !rho.is_finite() {
            return rho;
        }
        let (uncoupled, coupled) = self.terms(index, beta, false);
        if coupled == 0.0 {
            return rho;
        }
        let ln_weight = self.ln_mode_weight[self.positions[index] % BLOCK];
        let ln_a = LN_2.ln() + ln_weight + uncoupled.ln() - ln_lambda;
        let shift = (LN_2.ln() + ln_weight + coupled.ln() - ln_lambda).exp();
        if !shift.is_finite() {
            // Beyond f64, at payloads near 1e-280 bits: the largest finite cost.
            return f64::MAX;
        }
        let alone = probability::uncapped_cost(ln_weight + uncoupled.ln(), ln_lambda);
        let (mut low, mut high) = (shift.max(alone), shift + alone);
        let mut rho = high;
        for _ in 0..MAX_ITERATIONS {
            if high <= low {
                break;
            }
            let e = (-rho).exp();
            // a β(ρ) in logarithms: `a` alone can overflow.
            let pull = (ln_a - rho - (2.0 * e).ln_1p()).exp();
            let miss = rho - shift - pull;
            if miss > 0.0 {
                high = rho;
            } else {
                low = rho;
            }
            let slope = pull.mul_add(1.0 - 2.0 * probability::beta(e), 1.0);
            let mut next = rho - miss / slope;
            if !(next > low && next < high) {
                next = 0.5 * (low + high);
            }
            if (next - rho).abs() <= f64::EPSILON * rho {
                return next;
            }
            rho = next;
        }
        rho
    }

    /// Payload, energy and the residual of `β_i FI_i = λ ρ_i / ln 2` at the returned `β`,
    /// summed in ascending position order.
    fn diagnostics(&self, beta: &[f64], rho: &[f64], lambda: f64) -> Diagnostics {
        let (mut bits, mut energy) = (Sum::new(), Sum::new());
        let (mut weighted, mut mass, mut worst) = (Sum::new(), Sum::new(), 0.0_f64);
        let order = self.selection.order();
        for rank in 0..self.positions.len() {
            let index = order.map_or(rank, |o| o[rank] as usize);
            if self.selection.permission(index) != Permitted::Both {
                continue;
            }
            let (uncoupled, coupled) = self.terms(index, beta, false);
            let weight = self.mode_weight[self.positions[index] % BLOCK];
            let left = weight * uncoupled.mul_add(beta[index], coupled);
            let right = lambda * rho[index] / LN_2;
            let scale = left.max(right);
            let residual = if scale > 0.0 {
                (left - right).abs() / scale
            } else {
                0.0
            };
            bits.add(ternary_bits(beta[index], rho[index]));
            energy.add(beta[index] * left);
            weighted.add(beta[index] * residual);
            mass.add(beta[index]);
            worst = worst.max(residual);
        }
        Diagnostics {
            entropy_bits: bits.value(),
            energy: energy.value(),
            kkt_residual: weighted.value() / mass.value(),
            kkt_max: worst,
        }
    }
}

#[cfg(test)]
mod tests;
