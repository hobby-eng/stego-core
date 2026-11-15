//! Change probabilities (TIFS eq. 28–34) and the search for the Lagrange multiplier. The condition
//! is solved in the form `ρ (2 + e^ρ) = ln 2 · FI / λ`, which has no cancellation and lets Newton's
//! method converge from any start. A tabulated pass finds `λ`, then exact passes hold the payload.
//! Sums run in position order, so reordering the positions gives the same bits.

use std::f64::consts::LN_2;
use std::sync::OnceLock;

use crate::algorithm::model::CostError;

/// Smallest change probability of a permitted coefficient; keeps every cost finite.
pub(crate) const MIN_BETA: f64 = 1e-300;

/// `ln(1/MIN_BETA − 2)`, the cost of a coefficient at the floor.
pub(crate) const RHO_MAX: f64 = 690.775_527_898_213_7;

/// Payload accuracy of the result: `|Σ H3 − R| ≤ TOLERANCE · max(R, 1)` bits.
pub(crate) const TOLERANCE: f64 = 1e-9;

/// The table search stops at a quarter of [`TOLERANCE`]; the exact pass then checks.
const TABLE_TOLERANCE: f64 = 0.25 * TOLERANCE;

/// Requirement 4.6, `max(1 bit, 1e-6 · R)`: accepted only if the exact passes run out.
const REQUIRED: f64 = 1e-6;

/// Below `k = ln a` of −40, `ρ = a/3` is exact in `f64` (relative error `a/9`).
const SMALL_K: f64 = -40.0;

/// Table nodes per unit of `k`.
const NODES_PER_UNIT: f64 = 64.0;

/// A Newton step below this ends the iteration: with `g″/2g′ ≤ 1` the remaining error is at
/// most the step squared, below 1e-16 relative in `ρ`.
const NEWTON_DONE: f64 = 1e-8;

/// Cap on Newton iterations for `ρ`; from the table start one or two are taken.
const MAX_NEWTON: usize = 60;

/// Largest step of `ln λ` per iteration (a factor `e^50` in `λ`).
const MAX_STEP: f64 = 50.0;

/// Table iterations: Newton plus bisection fallback.
const MAX_OUTER: usize = 200;

/// Exact passes after the table search.
const MAX_EXACT: usize = 8;

/// `|ln λ|` beyond which every `β` is at the floor or at `1/3`.
const LN_LAMBDA_LIMIT: f64 = 2000.0;

/// Size of the subsample used to find a starting `λ` before the full passes.
const SAMPLE: usize = 1 << 16;

/// The subsample's stride is coprime with this (64 · 63), so that over all coefficients of a
/// plane, with DC or without it, the subsample visits every mode.
const MODE_PERIODS: usize = 64 * 63;

/// The subsample only gives the start: its sampling error is about 0.4%.
const SAMPLE_TOLERANCE: f64 = 1e-3;

/// Below this `k` the starting `ρ` comes from `ρ(3 + ρ) = a`, above from `ρ = k − ln k`.
const START_SWITCH: f64 = 1.5;

/// What the exact pass writes for each position.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Output {
    /// The change probability `β`; 0 for wet positions.
    Beta,
    /// The cost `ρ = ln(1/β − 2)`; infinity for wet positions.
    Cost,
}

/// Log Fisher information per position (`NEG_INFINITY` = wet), read in ascending position order.
#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    pub(crate) values: &'a [f64],
    /// Indexes into `values` in ascending position order; `None` when already ascending.
    pub(crate) order: Option<&'a [u32]>,
}

impl View<'_> {
    fn index(&self, rank: usize) -> usize {
        self.order.map_or(rank, |order| order[rank] as usize)
    }
}

/// Fails with [`CostError::Payload`] unless capacity > 0 and `0 ≤ payload < capacity · log2 3`.
pub(crate) fn validate_payload(capacity: usize, payload: f64) -> Result<(), CostError> {
    if capacity == 0
        || !payload.is_finite()
        || payload < 0.0
        || payload >= capacity as f64 * 3.0f64.log2()
    {
        return Err(CostError::Payload);
    }
    Ok(())
}

/// Solves `ln λ` for `payload > 0` bits over the finite entries of `view` and writes `out`
/// (indexed like `view.values`). Returns `ln λ`, or [`CostError::Payload`] if the search fails.
pub(crate) fn solve(
    view: View<'_>,
    payload: f64,
    out: &mut [f64],
    output: Output,
) -> Result<f64, CostError> {
    let start = table_search(view, payload)?;
    exact(view, payload, start, out, output)
}

/// `ln λ` for `payload > 0` bits from the table alone (no exact pass), for models that iterate
/// and only need the exact result at the end.
pub(crate) fn table_lambda(view: View<'_>, payload: f64) -> Result<f64, CostError> {
    table_search(view, payload)
}

/// Writes `β` from the tabulated cost at `ln λ` (Hermite, relative error about 1e-9) into `out`
/// and returns `(Σ |β_new − β_old|, Σ β_new)` for a convergence test.
pub(crate) fn table_beta(view: View<'_>, ln_lambda: f64, out: &mut [f64]) -> (f64, f64) {
    let table = table();
    let (mut moved, mut total) = (Sum::default(), Sum::default());
    for rank in 0..view.values.len() {
        let index = view.index(rank);
        let ln_fi = view.values[index];
        let next = if ln_fi == f64::NEG_INFINITY {
            0.0
        } else {
            beta((-table.rho(log_ratio(ln_fi, ln_lambda))).exp())
        };
        moved.add((next - out[index]).abs());
        total.add(next);
        out[index] = next;
    }
    (moved.value(), total.value())
}

/// The cost `ρ` at `ln FI` and `ln λ` without the cap at [`RHO_MAX`]: beyond the table,
/// Newton's method from `ρ = k − ln k`. Infinity for a wet position (`ln FI = −∞`).
///
/// For models that report costs where `β` underflows: there the capped cost of the payload
/// search is flat at [`RHO_MAX`], while this one keeps growing with `FI/λ`.
pub(crate) fn uncapped_cost(ln_fi: f64, ln_lambda: f64) -> f64 {
    if ln_fi == f64::NEG_INFINITY {
        return f64::INFINITY;
    }
    let k = log_ratio(ln_fi, ln_lambda);
    let table = table();
    if k < SMALL_K {
        k.exp() / 3.0
    } else if k < table.top {
        let (a, b, t) = table.locate(k);
        let (start, _) = hermite(t, table.width, a.rho, a.rho_slope, b.rho, b.rho_slope);
        newton(k, start).0
    } else {
        newton(k, k - k.ln()).0
    }
}

/// `k = ln a = ln(ln 2 · FI / λ)` from `ln FI` and `ln λ`.
fn log_ratio(ln_fi: f64, ln_lambda: f64) -> f64 {
    LN_2.ln() + ln_fi - ln_lambda
}

/// Change probability `β = 1/(2 + e^ρ)` from `e^−ρ`.
pub(crate) fn beta(e: f64) -> f64 {
    e / (1.0 + 2.0 * e)
}

/// The cost `ρ` solving `ρ (2 + e^ρ) = e^k`, capped at [`RHO_MAX`], with `e^−ρ` and whether
/// the cap applied.
fn cost(k: f64) -> (f64, f64, bool) {
    table().cost(k)
}

/// Newton's method for `ρ (2 + e^ρ) = e^k` on `u = ln ρ`, from `start > 0`, without the cap.
///
/// `g(u) = u + ρ + ln(1 + 2e^−ρ) − k` is increasing and convex with `g′ ≥ 1`: from the right
/// of the root the iterates decrease monotonically, from the left one step lands on the right.
fn newton(k: f64, start: f64) -> (f64, f64) {
    let (mut u, mut rho) = (start.ln(), start);
    let mut e = (-rho).exp();
    for _ in 0..MAX_NEWTON {
        let g = u + rho + (2.0 * e).ln_1p() - k;
        let step = g / (1.0 + rho / (1.0 + 2.0 * e));
        u -= step;
        rho = u.exp();
        e = (-rho).exp();
        if step.abs() <= NEWTON_DONE {
            break;
        }
    }
    (rho, e)
}

/// `ρ`, `H3` in bits and their derivatives in `k` at one point.
#[derive(Clone, Copy)]
struct Node {
    rho: f64,
    rho_slope: f64,
    bits: f64,
    bits_slope: f64,
}

impl Node {
    /// Exact values from `ρ` and `e^−ρ`: `dρ/dk = ρ/(1 + ρ(1 − 2β))`, `dH3/dρ = −2ρβ(1 − 2β)`.
    fn new(rho: f64, e: f64) -> Self {
        let keep = 1.0 / (1.0 + 2.0 * e);
        let beta = e * keep;
        let rho_slope = rho / rho.mul_add(keep, 1.0);
        Self {
            rho,
            rho_slope,
            bits: (2.0 * beta * rho + (2.0 * e).ln_1p()) / LN_2,
            bits_slope: -2.0 * rho * beta * keep * rho_slope / LN_2,
        }
    }

    /// Exact values at `k` from an analytic start.
    fn at(k: f64) -> Self {
        let start = if k <= START_SWITCH {
            // ρ(3 + ρ) = a, the expansion of e^ρ to first order.
            let a = k.exp();
            2.0 * a / (3.0 + 4.0f64.mul_add(a, 9.0).sqrt())
        } else {
            // ρ e^ρ ≈ a.
            k - k.ln()
        };
        let (rho, e) = newton(k, start);
        Self::new(rho, e)
    }
}

/// Cubic Hermite value and derivative on `[0, 1]` scaled to an interval of width `width`.
fn hermite(t: f64, width: f64, y0: f64, m0: f64, y1: f64, m1: f64) -> (f64, f64) {
    let (t2, t3) = (t * t, t * t * t);
    let value = (2.0 * t3 - 3.0 * t2 + 1.0) * y0
        + (t3 - 2.0 * t2 + t) * width * m0
        + (3.0 * t2 - 2.0 * t3) * y1
        + (t3 - t2) * width * m1;
    let slope = (6.0 * t2 - 6.0 * t) * (y0 - y1) / width
        + (3.0 * t2 - 4.0 * t + 1.0) * m0
        + (3.0 * t2 - 2.0 * t) * m1;
    (value, slope)
}

/// Nodes of `ρ(k)` and `H3(k)` from `k = −40` to the floor's `k`, evenly spaced.
struct Table {
    width: f64,
    /// `k` from which `ρ` is capped at [`RHO_MAX`].
    top: f64,
    nodes: Vec<Node>,
    floor: Node,
}

/// The table, built once per process (about 47,000 nodes).
fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(Table::new)
}

impl Table {
    fn new() -> Self {
        let floor = Node::new(RHO_MAX, (-RHO_MAX).exp());
        let top = RHO_MAX.ln() + RHO_MAX + (2.0 * (-RHO_MAX).exp()).ln_1p();
        let count = ((top - SMALL_K) * NODES_PER_UNIT).ceil();
        let width = (top - SMALL_K) / count;
        let nodes = (0..=count as usize)
            .map(|i| Node::at(SMALL_K + i as f64 * width))
            .collect();
        Self {
            width,
            top,
            nodes,
            floor,
        }
    }

    /// The interval of `k` inside the table and the position in it.
    fn locate(&self, k: f64) -> (Node, Node, f64) {
        let x = (k - SMALL_K) / self.width;
        let i = (x as usize).min(self.nodes.len() - 2);
        (self.nodes[i], self.nodes[i + 1], x - i as f64)
    }

    /// Exact `(ρ, e^−ρ, capped)`: Newton from the tabulated `ρ`.
    fn cost(&self, k: f64) -> (f64, f64, bool) {
        if k < SMALL_K {
            let rho = k.exp() / 3.0;
            return (rho, (-rho).exp(), false);
        }
        if k >= self.top {
            return (RHO_MAX, (-RHO_MAX).exp(), true);
        }
        let (a, b, t) = self.locate(k);
        let (start, _) = hermite(t, self.width, a.rho, a.rho_slope, b.rho, b.rho_slope);
        let (rho, e) = newton(k, start);
        if rho >= RHO_MAX {
            (RHO_MAX, (-RHO_MAX).exp(), true)
        } else {
            (rho, e, false)
        }
    }

    /// `ρ` interpolated from the table (no Newton step), capped at [`RHO_MAX`].
    fn rho(&self, k: f64) -> f64 {
        if k < SMALL_K {
            return k.exp() / 3.0;
        }
        if k >= self.top {
            return RHO_MAX;
        }
        let (a, b, t) = self.locate(k);
        hermite(t, self.width, a.rho, a.rho_slope, b.rho, b.rho_slope)
            .0
            .min(RHO_MAX)
    }

    /// `H3` in bits and `dH3/dk`, interpolated.
    fn bits(&self, k: f64) -> (f64, f64) {
        if k < SMALL_K {
            let rho = k.exp() / 3.0;
            let node = Node::new(rho, (-rho).exp());
            return (node.bits, node.bits_slope);
        }
        if k >= self.top {
            return (self.floor.bits, 0.0);
        }
        let (a, b, t) = self.locate(k);
        hermite(t, self.width, a.bits, a.bits_slope, b.bits, b.bits_slope)
    }
}

/// Neumaier-compensated sum.
#[derive(Default)]
struct Sum {
    total: f64,
    correction: f64,
}

impl Sum {
    fn add(&mut self, value: f64) {
        let next = self.total + value;
        self.correction += if self.total.abs() >= value.abs() {
            (self.total - next) + value
        } else {
            (value - next) + self.total
        };
        self.total = next;
    }

    fn value(&self) -> f64 {
        self.total + self.correction
    }
}

/// Table payload in bits of every `stride`-th position and its derivative in `ln λ`.
fn table_payload(view: View<'_>, stride: usize, ln_lambda: f64) -> (f64, f64) {
    let table = table();
    let (mut bits, mut slope) = (Sum::default(), Sum::default());
    for rank in (0..view.values.len()).step_by(stride) {
        let ln_fi = view.values[view.index(rank)];
        if ln_fi == f64::NEG_INFINITY {
            continue;
        }
        let (b, d) = table.bits(log_ratio(ln_fi, ln_lambda));
        bits.add(b);
        // k = ln(ln 2 · FI) − ln λ, so dH3/d ln λ = −dH3/dk.
        slope.add(-d);
    }
    (bits.value(), slope.value())
}

/// `ln λ` from the table: a start on a subsample, then the full set.
fn table_search(view: View<'_>, payload: f64) -> Result<f64, CostError> {
    let n = view.values.len();
    let (mut mean, mut count) = (Sum::default(), 0_usize);
    for rank in 0..n {
        let ln_fi = view.values[view.index(rank)];
        if ln_fi != f64::NEG_INFINITY {
            mean.add(ln_fi);
            count += 1;
        }
    }
    // ln λ at which the coefficient of mean ln FI has a = 1.
    let mut start = LN_2.ln() + mean.value() / count.max(1) as f64;
    if n / SAMPLE >= 2 {
        let mut stride = n / SAMPLE;
        while gcd(stride, MODE_PERIODS) != 1 {
            stride += 1;
        }
        let share = n.div_ceil(stride) as f64 / n as f64;
        let target = payload * share;
        if let Ok(ln_lambda) = search(view, stride, target, start, SAMPLE_TOLERANCE * target) {
            start = ln_lambda;
        }
    }
    search(view, 1, payload, start, TABLE_TOLERANCE * payload.max(1.0))
}

/// Greatest common divisor.
fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Newton step on `ln P(ln λ) = ln target`, kept within `MAX_STEP` and inside `(low, high)`.
fn next_ln_lambda(ln_lambda: f64, bits: f64, slope: f64, target: f64, bracket: (f64, f64)) -> f64 {
    let (low, high) = bracket;
    let miss = bits - target;
    let mut next = ln_lambda - (bits.ln() - target.ln()) * bits / slope;
    if !next.is_finite() {
        next = ln_lambda + if miss < 0.0 { MAX_STEP } else { -MAX_STEP };
    }
    next = next.clamp(ln_lambda - MAX_STEP, ln_lambda + MAX_STEP);
    if next <= low || next >= high {
        next = 0.5 * (low + high);
    }
    next
}

/// Solves `P(ln λ) = target` with the table over every `stride`-th position.
fn search(
    view: View<'_>,
    stride: usize,
    target: f64,
    mut ln_lambda: f64,
    tolerance: f64,
) -> Result<f64, CostError> {
    let mut bracket = (f64::NEG_INFINITY, f64::INFINITY);
    for _ in 0..MAX_OUTER {
        let (bits, slope) = table_payload(view, stride, ln_lambda);
        let miss = bits - target;
        if miss.abs() <= tolerance {
            return Ok(ln_lambda);
        }
        // The payload grows with λ.
        if miss < 0.0 {
            bracket.0 = ln_lambda;
        } else {
            bracket.1 = ln_lambda;
        }
        let next = next_ln_lambda(ln_lambda, bits, slope, target, bracket);
        if next == ln_lambda || !next.is_finite() || next.abs() > LN_LAMBDA_LIMIT {
            break;
        }
        ln_lambda = next;
    }
    Err(CostError::Payload)
}

/// One exact pass at `ln λ`: writes `out`, returns the exact payload and its slope in `ln λ`.
fn exact_pass(view: View<'_>, ln_lambda: f64, out: &mut [f64], output: Output) -> (f64, f64) {
    let (mut bits, mut slope) = (Sum::default(), Sum::default());
    for rank in 0..view.values.len() {
        let index = view.index(rank);
        let ln_fi = view.values[index];
        if ln_fi == f64::NEG_INFINITY {
            out[index] = match output {
                Output::Beta => 0.0,
                Output::Cost => f64::INFINITY,
            };
            continue;
        }
        let (rho, e, capped) = cost(log_ratio(ln_fi, ln_lambda));
        let node = Node::new(rho, e);
        bits.add(node.bits);
        if !capped {
            slope.add(-node.bits_slope);
        }
        out[index] = match output {
            Output::Beta => beta(e),
            Output::Cost => rho,
        };
    }
    (bits.value(), slope.value())
}

/// Exact passes from the table's `ln λ` until the exact payload is within `TOLERANCE`.
fn exact(
    view: View<'_>,
    payload: f64,
    mut ln_lambda: f64,
    out: &mut [f64],
    output: Output,
) -> Result<f64, CostError> {
    let tolerance = TOLERANCE * payload.max(1.0);
    let mut bracket = (f64::NEG_INFINITY, f64::INFINITY);
    let (mut evaluated, mut miss) = (ln_lambda, f64::INFINITY);
    for _ in 0..MAX_EXACT {
        let (bits, slope) = exact_pass(view, ln_lambda, out, output);
        (evaluated, miss) = (ln_lambda, bits - payload);
        if miss.abs() <= tolerance {
            return Ok(ln_lambda);
        }
        if miss < 0.0 {
            bracket.0 = ln_lambda;
        } else {
            bracket.1 = ln_lambda;
        }
        let next = next_ln_lambda(ln_lambda, bits, slope, payload, bracket);
        if next == ln_lambda || !next.is_finite() || next.abs() > LN_LAMBDA_LIMIT {
            break;
        }
        ln_lambda = next;
    }
    // `out` holds the last evaluated λ; keep it if it still meets requirement 4.6.
    if miss.abs() <= (REQUIRED * payload).max(1.0) {
        return Ok(evaluated);
    }
    Err(CostError::Payload)
}

#[cfg(test)]
mod tests;
