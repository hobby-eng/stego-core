//! Syndrome-trellis codes (Filler, Judas, Fridrich, TIFS 2011). The binary coder hides bits in the
//! parities of cover elements at minimum cost. The ternary coder makes ±1 changes by embedding
//! first into the second bit and then into the last one (Algorithm 1 of the paper); the other order
//! fails on mostly wet covers.

use crate::algorithm::model::Costs;

/// Constraint height of the trellis.
pub const HEIGHT: usize = 10;
/// Message bits per trellis segment in the current product format.
pub const SEGMENT_BITS: usize = 128;
/// Relative sizes of the first layer tried in turn when a layer cannot be embedded.
const SPLITS: [f64; 7] = [1.0, 1.02, 0.98, 1.05, 0.95, 1.1, 0.9];

/// Why the coder could not embed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StcError {
    /// More message bits than the cover can carry.
    Capacity,
    /// No assignment of the changeable elements produces the message (too many wet elements).
    Infeasible,
    /// Inputs have mismatched lengths, a zero segment, or invalid costs.
    Input,
}

/// Deterministic matrix columns for research runs. The product derives them from the record key.
pub fn columns(count: usize, height: usize, seed: u64) -> Vec<u32> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mask = (1_u32 << height) - 1;
    (0..count)
        .map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            ((z as u32) & mask) | 1 | (1 << (height - 1))
        })
        .collect()
}

/// One past the last column of message bit `k` when `n` columns carry `m` bits.
fn bit_end(k: usize, n: usize, m: usize) -> usize {
    ((k as u128 + 1) * n as u128 / m as u128) as usize
}

/// Embeds `message` into the parities `cover` (0 or 1 each) at minimum total `costs`.
///
/// `f64::INFINITY` marks an element that must keep its parity; negative costs are allowed.
/// Returns the stego parities.
pub fn binary_embed(
    cover: &[u8],
    costs: &[f64],
    message: &[u8],
    columns: &[u32],
    height: usize,
    segment: usize,
) -> Result<Vec<u8>, StcError> {
    binary_embed_with(cover, costs, message, columns, height, segment, 1)
}

/// [`binary_embed`] with the segments solved on up to `workers` threads, a number the host
/// chooses (1 runs everything in the calling thread). The output does not depend on it.
pub fn binary_embed_with(
    cover: &[u8],
    costs: &[f64],
    message: &[u8],
    columns: &[u32],
    height: usize,
    segment: usize,
    workers: usize,
) -> Result<Vec<u8>, StcError> {
    let (n, m) = (cover.len(), message.len());
    if cover.len() != costs.len()
        || columns.len() < n
        || !(1..=16).contains(&height)
        || segment == 0
        || costs.iter().any(|c| c.is_nan())
    {
        return Err(StcError::Input);
    }
    if m > n {
        return Err(StcError::Capacity);
    }
    // Each segment is a trellis of its own: the bits it carries and the columns they own.
    let mut jobs = Vec::new();
    let mut first = 0;
    for bits in message.chunks(segment) {
        let start = if first == 0 {
            0
        } else {
            bit_end(first - 1, n, m)
        };
        let ends: Vec<usize> = (first..first + bits.len())
            .map(|k| bit_end(k, n, m) - start)
            .collect();
        let span = start..start + ends.last().copied().unwrap_or(0);
        jobs.push((span, bits, ends));
        first += bits.len();
    }
    let solve = |(span, bits, ends): &(std::ops::Range<usize>, &[u8], Vec<usize>)| {
        viterbi(
            &cover[span.clone()],
            &costs[span.clone()],
            bits,
            ends,
            &columns[span.clone()],
            height,
        )
    };
    let chosen = run_segments(&jobs, &solve, workers)?;
    let mut stego = cover.to_vec();
    for ((span, _, _), part) in jobs.iter().zip(chosen) {
        stego[span.clone()].copy_from_slice(&part);
    }
    Ok(stego)
}

/// Solves the segments, on every core where the platform has threads. Each result depends only
/// on its own segment, so the order of work never changes the output.
fn run_segments<J: Sync>(
    jobs: &[J],
    solve: &(dyn Fn(&J) -> Result<Vec<u8>, StcError> + Sync),
    workers: usize,
) -> Result<Vec<Vec<u8>>, StcError> {
    parallel_map(jobs, solve, workers).into_iter().collect()
}

/// `f` of every job, in the jobs' order, on up to `workers` threads the host allows. A thread
/// the system refuses leaves its jobs to the calling thread, so a refusal only slows the work.
#[cfg(not(target_arch = "wasm32"))]
#[allow(
    clippy::disallowed_methods,
    reason = "the one place that starts threads, as many as the host allows"
)]
fn parallel_map<J: Sync, R: Send>(
    jobs: &[J],
    f: &(dyn Fn(&J) -> R + Sync),
    workers: usize,
) -> Vec<R> {
    if workers < 2 || jobs.len() < 2 {
        return jobs.iter().map(f).collect();
    }
    let per = jobs.len().div_ceil(workers.min(jobs.len()));
    std::thread::scope(|scope| {
        let spawned: Vec<_> = jobs
            .chunks(per)
            .map(|chunk| {
                let job = move || chunk.iter().map(f).collect::<Vec<R>>();
                (
                    chunk,
                    std::thread::Builder::new().spawn_scoped(scope, job).ok(),
                )
            })
            .collect();
        spawned
            .into_iter()
            .flat_map(|(chunk, handle)| match handle {
                // A panic in a worker is a defect of this module; it is passed on unchanged.
                Some(h) => h
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                None => chunk.iter().map(f).collect(),
            })
            .collect()
    })
}

/// `f` of every job, one after another: a browser module has no threads.
#[cfg(target_arch = "wasm32")]
fn parallel_map<J: Sync, R: Send>(
    jobs: &[J],
    f: &(dyn Fn(&J) -> R + Sync),
    _workers: usize,
) -> Vec<R> {
    jobs.iter().map(f).collect()
}

/// Elements summed by one worker; fixed, so that the sum is the same on every machine.
const SUM_CHUNK: usize = 1 << 16;

/// `Σ part(i)` over `0..n`, summed per fixed chunk and then chunk by chunk in order: the same
/// number however many cores run it.
fn chunked_sum(n: usize, part: &(dyn Fn(usize) -> f64 + Sync), workers: usize) -> f64 {
    let chunks: Vec<std::ops::Range<usize>> = (0..n.div_ceil(SUM_CHUNK))
        .map(|c| c * SUM_CHUNK..((c + 1) * SUM_CHUNK).min(n))
        .collect();
    parallel_map(
        &chunks,
        &|range: &std::ops::Range<usize>| range.clone().map(part).sum::<f64>(),
        workers,
    )
    .iter()
    .sum()
}

/// Columns between two stored cost vectors of the trellis.
const CHECKPOINT: usize = 4096;

/// One column of the trellis: every state's cheapest way in, with or without this column, and
/// which one won when `decisions` is given.
fn step(
    cost: &mut Vec<f64>,
    next: &mut Vec<f64>,
    (x, rho, column): (u8, f64, u32),
    decisions: Option<&mut [u64]>,
) {
    let states = cost.len();
    let column = column as usize & (states - 1);
    // y = 0 keeps the state, y = 1 adds the column; either pays rho when it differs from x.
    let (pay_zero, pay_one) = if x & 1 == 1 { (rho, 0.0) } else { (0.0, rho) };
    let mut decisions = decisions;
    for (index, chunk) in next.chunks_mut(64).enumerate() {
        let mut packed = 0_u64;
        for (offset, slot) in chunk.iter_mut().enumerate() {
            let t = index * 64 + offset;
            let zero = cost[t] + pay_zero;
            let one = cost[t ^ column] + pay_one;
            let take = one < zero;
            *slot = if take { one } else { zero };
            packed |= u64::from(take) << offset;
        }
        if let Some(words) = decisions.as_deref_mut() {
            words[index] = packed;
        }
    }
    std::mem::swap(cost, next);
}

/// The end of message bit `bit`: only the states whose low bit is that bit go on, shifted.
fn shift(cost: &mut Vec<f64>, next: &mut Vec<f64>, bit: u8) {
    let states = cost.len();
    let parity = usize::from(bit & 1);
    for t in 0..states / 2 {
        next[t] = cost[(t << 1) | parity];
    }
    next[states / 2..].fill(f64::INFINITY);
    std::mem::swap(cost, next);
}

/// Minimum-cost parities for one segment; `ends[k]` is one past the last column of bit `k`.
///
/// The forward pass keeps the cost vector every [`CHECKPOINT`] columns instead of every column's
/// decisions; the way back recomputes one block of decisions at a time from its checkpoint, with
/// the same arithmetic, so it finds the same path in about two bytes per column.
fn viterbi(
    cover: &[u8],
    costs: &[f64],
    bits: &[u8],
    ends: &[usize],
    columns: &[u32],
    height: usize,
) -> Result<Vec<u8>, StcError> {
    let states = 1_usize << height;
    let words = states.div_ceil(64);
    let len = cover.len();
    let mut cost = vec![f64::INFINITY; states];
    cost[0] = 0.0;
    let mut next = vec![f64::INFINITY; states];
    let mut checkpoints: Vec<(Vec<f64>, usize)> = Vec::with_capacity(len.div_ceil(CHECKPOINT));
    let mut bit = 0;
    for j in 0..len {
        if j % CHECKPOINT == 0 {
            checkpoints.push((cost.clone(), bit));
        }
        step(&mut cost, &mut next, (cover[j], costs[j], columns[j]), None);
        if bit < ends.len() && j + 1 == ends[bit] {
            shift(&mut cost, &mut next, bits[bit]);
            bit += 1;
        }
    }
    let (mut state, best) =
        cost.iter().enumerate().fold(
            (0, f64::INFINITY),
            |acc, (t, &c)| if c < acc.1 { (t, c) } else { acc },
        );
    if !best.is_finite() {
        return Err(StcError::Infeasible);
    }
    let mut out = vec![0_u8; len];
    let mut decisions = vec![0_u64; CHECKPOINT.min(len) * words];
    let mut back = bits.len();
    for (block, (saved, saved_bit)) in checkpoints.iter().enumerate().rev() {
        let start = block * CHECKPOINT;
        let end = (start + CHECKPOINT).min(len);
        let (mut c, mut b) = (saved.clone(), *saved_bit);
        for j in start..end {
            let row = &mut decisions[(j - start) * words..][..words];
            step(
                &mut c,
                &mut next,
                (cover[j], costs[j], columns[j]),
                Some(row),
            );
            if b < ends.len() && j + 1 == ends[b] {
                shift(&mut c, &mut next, bits[b]);
                b += 1;
            }
        }
        // `decisions` stores whether y = 1 was chosen on the best way into each state.
        for j in (start..end).rev() {
            if back > 0 && j + 1 == ends[back - 1] {
                back -= 1;
                state = (state << 1) | usize::from(bits[back] & 1);
            }
            let took = (decisions[(j - start) * words + state / 64] >> (state % 64)) & 1 == 1;
            out[j] = u8::from(took);
            if took {
                state ^= columns[j] as usize & (states - 1);
            }
        }
    }
    Ok(out)
}

/// Reads `length` message bits from stego parities. The reader must use the same `length`,
/// `segment` and number of elements as the writer.
pub fn binary_extract(
    stego: &[u8],
    length: usize,
    columns: &[u32],
    height: usize,
    segment: usize,
) -> Vec<u8> {
    let (n, mask) = (stego.len(), (1_usize << height) - 1);
    let segment = segment.max(1);
    let mut message = Vec::with_capacity(length.min(n));
    let mut state = 0_usize;
    let mut start = 0;
    for k in 0..length.min(n) {
        if k % segment == 0 {
            state = 0;
        }
        let end = bit_end(k, n, length);
        for j in start..end {
            if stego[j] & 1 == 1 {
                state ^= columns[j] as usize & mask;
            }
        }
        message.push((state & 1) as u8);
        state >>= 1;
        start = end;
    }
    message
}

/// XOR prefixes of the columns of the odd elements: `prefix[j]` is the XOR of
/// `columns[i] & mask` over every `i < j` whose `bits[i]` is odd. One pass serves every message
/// length that [`prefix_extract`] then reads.
#[must_use]
pub fn column_prefix(bits: &[u8], columns: &[u32], height: usize) -> Vec<u16> {
    // Heights stop at 16 (the trellis refuses more), which a u16 prefix holds.
    let height = height.clamp(1, 16);
    // Heights stop at 16, so a masked column fits `u16`.
    let mask = ((1_u32 << height) - 1) as u16;
    let mut prefix = Vec::with_capacity(bits.len() + 1);
    let mut state = 0_u16;
    prefix.push(state);
    for (&bit, &column) in bits.iter().zip(columns) {
        if bit & 1 == 1 {
            state ^= column as u16 & mask;
        }
        prefix.push(state);
    }
    prefix
}

/// [`binary_extract`] from the XOR prefixes of [`column_prefix`]: bit `k` is the XOR, over the
/// `height` bits before it in its segment, of bit `k − k'` of the XOR of bit `k'`'s columns. Costs
/// `O(length · height)` instead of a pass over every element; gives the same bits.
#[must_use]
pub fn prefix_extract(prefix: &[u16], length: usize, height: usize, segment: usize) -> Vec<u8> {
    let height = height.clamp(1, 16);
    let n = prefix.len().saturating_sub(1);
    let segment = segment.max(1);
    let count = length.min(n);
    if count == 0 {
        return Vec::new();
    }
    // The XOR of each bit's columns, its column range found step by step: bit k ends at
    // ⌊(k + 1) n / length⌋ = (k + 1) q + ⌊(k + 1) r / length⌋ with q, r = n / length, n mod length.
    let (quotient, remainder) = (n / length, n % length);
    let mut spans = Vec::with_capacity(count);
    let (mut start, mut extra, mut carried) = (0, 0, 0);
    for k in 0..count {
        carried += remainder;
        if carried >= length {
            carried -= length;
            extra += 1;
        }
        let end = (k + 1) * quotient + extra;
        spans.push(prefix[end] ^ prefix[start]);
        start = end;
    }
    (0..count)
        .map(|k| {
            let reach = (k % segment + 1).min(height);
            let bit = (0..reach).fold(0_u16, |acc, d| acc ^ ((spans[k - d] >> d) & 1));
            // A single bit.
            bit as u8
        })
        .collect()
}

/// Least significant bit of a coefficient value, for negative values too.
pub fn lsb(value: i32) -> u8 {
    value.rem_euclid(2) as u8
}

/// Second bit of a coefficient value: `⌊value / 2⌋ mod 2`.
pub fn second_bit(value: i32) -> u8 {
    value.div_euclid(2).rem_euclid(2) as u8
}

/// Result of a ternary embedding.
#[derive(Clone, Debug)]
pub struct Ternary {
    /// Stego values, one per cover element.
    pub stego: Vec<i32>,
    /// Message bits in the second-bit layer and in the LSB layer. A reader needs both.
    pub layer_bits: [usize; 2],
    /// Number of changed elements.
    pub changes: usize,
    /// Sum of the costs of the actual changes.
    pub distortion: f64,
    /// Lagrange multiplier of the optimal change distribution that set the layer split.
    pub lambda: f64,
}

/// Per-element quantities of the optimal distribution that both layers use.
struct Element {
    /// Cost of flipping the second bit: `ln((1 − q)/q)`, `q` its flip probability.
    second_cost: f64,
    /// Flip probability of the second bit.
    second_probability: f64,
}

/// The direction (+1 or −1) that changes the second bit of `x`.
const fn toward(x: i32) -> i32 {
    if x.rem_euclid(2) == 0 { -1 } else { 1 }
}

/// The cost of the change that keeps the second bit of `x` and flips its LSB.
const fn away_cost(x: i32, plus: f64, minus: f64) -> f64 {
    if toward(x) == 1 { minus } else { plus }
}

fn element(x: i32, plus: f64, minus: f64, lambda: f64) -> Element {
    let toward = toward(x);
    let (rho_toward, rho_away) = if toward == 1 {
        (plus, minus)
    } else {
        (minus, plus)
    };
    let [up, down] = change_probabilities(lambda, plus, minus);
    let second_probability = if toward == 1 { up } else { down };
    // ln((1 − q)/q) with q = e^{−λρt} / (1 + e^{−λρt} + e^{−λρa}) equals λρt + ln(1 + e^{−λρa}).
    let away = if rho_away.is_finite() {
        (-lambda * rho_away).exp()
    } else {
        0.0
    };
    let second_cost = lambda * rho_toward + away.ln_1p();
    Element {
        second_cost,
        second_probability,
    }
}

/// Embeds `message` (one bit per byte) with ±1 changes of `cover` values at minimum cost.
///
/// `costs.plus[i]` and `costs.minus[i]` are the costs of `cover[i] + 1` and `cover[i] − 1`;
/// `f64::INFINITY` forbids a direction. Columns are generated from `seed`.
pub fn ternary_embed(
    cover: &[i32],
    costs: &Costs,
    message: &[u8],
    seed: u64,
    segment: usize,
) -> Result<Ternary, StcError> {
    let n = cover.len();
    if costs.plus.len() != n
        || costs.minus.len() != n
        || segment == 0
        || costs
            .plus
            .iter()
            .chain(&costs.minus)
            .any(|c| c.is_nan() || *c < 0.0)
    {
        return Err(StcError::Input);
    }
    if message.is_empty() {
        return Ok(Ternary {
            stego: cover.to_vec(),
            layer_bits: [0, 0],
            changes: 0,
            distortion: 0.0,
            lambda: 0.0,
        });
    }
    let lambda = solve_lambda(costs, message.len() as f64)?;
    let elements: Vec<Element> = cover
        .iter()
        .zip(costs.plus.iter().zip(&costs.minus))
        .map(|(&x, (&p, &m))| element(x, p, m, lambda))
        .collect();
    let expected: f64 = elements
        .iter()
        .map(|e| entropy2(e.second_probability))
        .sum();
    let second_costs: Vec<f64> = elements.iter().map(|e| e.second_cost).collect();
    drop(elements);
    let mut last = StcError::Infeasible;
    for share in SPLITS {
        let first = ((expected * share).round() as usize).min(message.len());
        match layered(
            cover,
            costs,
            second_costs.clone(),
            message,
            (first, seed, segment),
            1,
        ) {
            Ok(mut result) => {
                result.lambda = lambda;
                return Ok(result);
            }
            Err(StcError::Infeasible) => last = StcError::Infeasible,
            Err(other) => last = other,
        }
    }
    Err(last)
}

/// Ternary embedding with a layer split the reader can compute without the sender: `first`
/// message bits go into the second-bit layer and the rest into the LSB layer. Unlike
/// [`ternary_embed`], it never tries another split, so a split that does not fit is refused.
pub fn ternary_embed_split(
    cover: &[i32],
    costs: &Costs,
    message: &[u8],
    seed: u64,
    segment: usize,
    first: usize,
) -> Result<Ternary, StcError> {
    ternary_embed_split_with(cover, costs, message, seed, (segment, first), 1)
}

/// [`ternary_embed_split`] on up to `workers` threads the host allows; `(segment, first)` as
/// there. The output does not depend on the number of threads.
pub fn ternary_embed_split_with(
    cover: &[i32],
    costs: &Costs,
    message: &[u8],
    seed: u64,
    (segment, first): (usize, usize),
    workers: usize,
) -> Result<Ternary, StcError> {
    let n = cover.len();
    if costs.plus.len() != n
        || costs.minus.len() != n
        || segment == 0
        || first > message.len()
        || costs
            .plus
            .iter()
            .chain(&costs.minus)
            .any(|c| c.is_nan() || *c < 0.0)
    {
        return Err(StcError::Input);
    }
    let lambda = solve_lambda_with(costs, message.len() as f64, workers)?;
    let second_costs: Vec<f64> = cover
        .iter()
        .zip(costs.plus.iter().zip(&costs.minus))
        .map(|(&x, (&p, &m))| element(x, p, m, lambda).second_cost)
        .collect();
    let mut result = layered(
        cover,
        costs,
        second_costs,
        message,
        (first, seed, segment),
        workers,
    )?;
    result.lambda = lambda;
    Ok(result)
}

/// One attempt: `first` bits into the second-bit layer, the rest into the LSB layer.
fn layered(
    cover: &[i32],
    costs: &Costs,
    second_costs: Vec<f64>,
    message: &[u8],
    (first, seed, segment): (usize, u64, usize),
    workers: usize,
) -> Result<Ternary, StcError> {
    let n = cover.len();
    let seconds: Vec<u8> = cover.iter().map(|&x| second_bit(x)).collect();
    let chosen = binary_embed_with(
        &seconds,
        &second_costs,
        &message[..first],
        &columns(n, HEIGHT, seed ^ 2),
        HEIGHT,
        segment,
        workers,
    )?;
    // The second-bit costs are done with; the parity layer's buffers take their place.
    drop(second_costs);
    // Where the second bit flipped, the value is x + toward and its LSB is fixed.
    let mut parities = Vec::with_capacity(n);
    let mut lsb_costs = Vec::with_capacity(n);
    for i in 0..n {
        let flipped = chosen[i] != seconds[i];
        parities.push(lsb(cover[i]) ^ u8::from(flipped));
        lsb_costs.push(if flipped {
            f64::INFINITY
        } else {
            away_cost(cover[i], costs.plus[i], costs.minus[i])
        });
    }
    let parities_out = binary_embed_with(
        &parities,
        &lsb_costs,
        &message[first..],
        &columns(n, HEIGHT, seed ^ 1),
        HEIGHT,
        segment,
        workers,
    )?;
    let stego: Vec<i32> = (0..n)
        .map(|i| {
            if chosen[i] != seconds[i] {
                cover[i] + toward(cover[i])
            } else if parities_out[i] != parities[i] {
                cover[i] - toward(cover[i])
            } else {
                cover[i]
            }
        })
        .collect();
    let mut changes = 0;
    let mut distortion = 0.0;
    for (i, (s, c)) in stego.iter().zip(cover).enumerate() {
        match s - c {
            1 => distortion += costs.plus[i],
            -1 => distortion += costs.minus[i],
            _ => continue,
        }
        changes += 1;
    }
    Ok(Ternary {
        stego,
        layer_bits: [first, message.len() - first],
        changes,
        distortion,
        lambda: 0.0,
    })
}

/// Reads a ternary message given the layer split.
pub fn ternary_extract(
    stego: &[i32],
    layer_bits: [usize; 2],
    seed: u64,
    segment: usize,
) -> Vec<u8> {
    let n = stego.len();
    let seconds: Vec<u8> = stego.iter().map(|&y| second_bit(y)).collect();
    let parities: Vec<u8> = stego.iter().map(|&y| lsb(y)).collect();
    let mut message = binary_extract(
        &seconds,
        layer_bits[0],
        &columns(n, HEIGHT, seed ^ 2),
        HEIGHT,
        segment,
    );
    message.extend(binary_extract(
        &parities,
        layer_bits[1],
        &columns(n, HEIGHT, seed ^ 1),
        HEIGHT,
        segment,
    ));
    message
}

/// Optimal per-direction change probabilities `[P(+1), P(−1)]` at multiplier `lambda`.
pub fn change_probabilities(lambda: f64, plus: f64, minus: f64) -> [f64; 2] {
    let up = if plus.is_finite() {
        (-lambda * plus).exp()
    } else {
        0.0
    };
    let down = if minus.is_finite() {
        (-lambda * minus).exp()
    } else {
        0.0
    };
    let total = 1.0 + up + down;
    [up / total, down / total]
}

/// Ternary entropy in bits of an element with the given direction probabilities.
fn entropy3([up, down]: [f64; 2]) -> f64 {
    let stay = 1.0 - up - down;
    [up, down, stay]
        .iter()
        .filter(|p| **p > 0.0)
        .map(|p| -p * p.log2())
        .sum()
}

/// Binary entropy in bits.
fn entropy2(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        0.0
    } else {
        -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
    }
}

/// Finds λ near `guess` to relative precision `tolerance` (a cheaper search for repeated solves
/// over slowly changing costs); falls back to [`solve_lambda`] when `guess` is not usable.
pub fn solve_lambda_near(
    costs: &Costs,
    bits: f64,
    guess: f64,
    tolerance: f64,
) -> Result<f64, StcError> {
    if !(guess.is_finite() && guess > 0.0) {
        return solve_lambda(costs, bits);
    }
    let payload = |lambda: f64| -> f64 {
        costs
            .plus
            .iter()
            .zip(&costs.minus)
            .map(|(&p, &m)| entropy3(change_probabilities(lambda, p, m)))
            .sum()
    };
    let (mut low, mut high) = (guess, guess);
    while payload(low) <= bits {
        low *= 0.5;
        if low < 1e-300 {
            return Err(StcError::Capacity);
        }
    }
    while payload(high) > bits {
        high *= 2.0;
        if high > 1e300 {
            return Err(StcError::Capacity);
        }
    }
    while high - low > high * tolerance {
        let mid = 0.5 * (low + high);
        if payload(mid) > bits {
            low = mid;
        } else {
            high = mid;
        }
    }
    Ok(high)
}

/// Finds λ so that the optimal change distribution carries `bits` bits.
pub fn solve_lambda(costs: &Costs, bits: f64) -> Result<f64, StcError> {
    solve_lambda_with(costs, bits, 1)
}

/// [`solve_lambda`] with the sums on up to `workers` threads; the result does not depend on it.
pub fn solve_lambda_with(costs: &Costs, bits: f64, workers: usize) -> Result<f64, StcError> {
    let n = costs.plus.len().min(costs.minus.len());
    let payload = |lambda: f64| -> f64 {
        chunked_sum(
            n,
            &|i| entropy3(change_probabilities(lambda, costs.plus[i], costs.minus[i])),
            workers,
        )
    };
    if payload(0.0) <= bits {
        return Err(StcError::Capacity);
    }
    let (mut low, mut high) = (0.0_f64, 1.0_f64);
    while payload(high) > bits {
        high *= 2.0;
        if high > 1e300 {
            return Err(StcError::Capacity);
        }
    }
    for _ in 0..200 {
        let mid = 0.5 * (low + high);
        if payload(mid) > bits {
            low = mid;
        } else {
            high = mid;
        }
        // λ only weighs the costs against each other, and the reader never needs it.
        if high - low <= high * 1e-9 {
            break;
        }
    }
    Ok(high)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "test code")]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 11
        }
        fn unit(&mut self) -> f64 {
            (self.next() as f64) / ((1_u64 << 53) as f64)
        }
        fn bits(&mut self, count: usize) -> Vec<u8> {
            (0..count).map(|_| (self.next() & 1) as u8).collect()
        }
    }

    #[test]
    fn binary_round_trip_with_uneven_widths_and_segments() {
        let mut rng = Rng(1);
        for (n, m, segment) in [
            (1_000, 300, 128),
            (2_345, 300, 128),
            (777, 700, 128),
            (5_000, 300, usize::MAX),
            (300, 300, 7),
        ] {
            let message = rng.bits(m);
            let cover = rng.bits(n);
            let costs: Vec<f64> = (0..n).map(|_| rng.unit() + 0.01).collect();
            let cols = columns(n, HEIGHT, 5);
            let stego = binary_embed(&cover, &costs, &message, &cols, HEIGHT, segment).unwrap();
            assert_eq!(
                binary_extract(&stego, m, &cols, HEIGHT, segment),
                message,
                "{n} {m}"
            );
        }
    }

    #[test]
    fn binary_matches_exhaustive_minimum() {
        let mut rng = Rng(9);
        let height = 3;
        for round in 0..60 {
            let (n, bits) = (10 + round % 3, 3);
            let message = rng.bits(bits);
            let cover = rng.bits(n);
            let costs: Vec<f64> = (0..n)
                .map(|_| {
                    if rng.next().is_multiple_of(5) {
                        f64::INFINITY
                    } else {
                        rng.unit() - 0.2
                    }
                })
                .collect();
            let cols = columns(n, height, rng.next());
            let segment = if round % 2 == 0 { usize::MAX } else { 2 };
            let mut best = f64::INFINITY;
            for pattern in 0_u32..(1 << n) {
                let stego: Vec<u8> = (0..n)
                    .map(|j| cover[j] ^ ((pattern >> j) & 1) as u8)
                    .collect();
                if binary_extract(&stego, bits, &cols, height, segment) == message {
                    let cost: f64 = (0..n)
                        .filter(|j| (pattern >> j) & 1 == 1)
                        .map(|j| costs[j])
                        .sum();
                    best = best.min(cost);
                }
            }
            match binary_embed(&cover, &costs, &message, &cols, height, segment) {
                Ok(stego) => {
                    assert_eq!(
                        binary_extract(&stego, bits, &cols, height, segment),
                        message
                    );
                    let cost: f64 = (0..n)
                        .filter(|&j| stego[j] != cover[j])
                        .map(|j| costs[j])
                        .sum();
                    assert!((cost - best).abs() < 1e-9, "{cost} vs {best}");
                }
                Err(StcError::Infeasible) => assert!(best.is_infinite()),
                Err(other) => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn value_bits_identify_the_change() {
        for x in -9..=9 {
            let bits = |y: i32| (lsb(y), second_bit(y));
            assert_ne!(bits(x - 1), bits(x));
            assert_ne!(bits(x + 1), bits(x));
            assert_ne!(bits(x - 1), bits(x + 1));
            let toward = toward(x);
            assert_ne!(second_bit(x + toward), second_bit(x));
            assert_eq!(second_bit(x - toward), second_bit(x));
        }
    }

    fn case(rng: &mut Rng, n: usize, wet: bool) -> (Vec<i32>, Costs) {
        let cover: Vec<i32> = (0..n).map(|_| (rng.next() % 41) as i32 - 20).collect();
        let mut plus = Vec::with_capacity(n);
        let mut minus = Vec::with_capacity(n);
        for _ in 0..n {
            let base = 0.1 + 10.0 * rng.unit().powi(3);
            let skew = 0.5 + rng.unit();
            let kind = if wet { rng.next() % 10 } else { 9 };
            plus.push(if kind == 0 || kind == 2 {
                f64::INFINITY
            } else {
                base
            });
            minus.push(if kind == 1 || kind == 2 {
                f64::INFINITY
            } else {
                base * skew
            });
        }
        (cover, Costs { plus, minus })
    }

    /// Expected distortion of the optimal change distribution carrying `bits` bits.
    fn bound(costs: &Costs, bits: usize) -> f64 {
        let lambda = solve_lambda(costs, bits as f64).unwrap();
        costs
            .plus
            .iter()
            .zip(&costs.minus)
            .map(|(&p, &m)| {
                let [up, down] = change_probabilities(lambda, p, m);
                (if up > 0.0 { up * p } else { 0.0 }) + if down > 0.0 { down * m } else { 0.0 }
            })
            .sum()
    }

    #[test]
    fn ternary_round_trip_changes_only_by_one() {
        let mut rng = Rng(42);
        for (n, bits, wet, segment) in [
            (20_000, 300, false, SEGMENT_BITS),
            (20_000, 4_000, true, SEGMENT_BITS),
            (5_000, 4_000, true, usize::MAX),
        ] {
            let (cover, costs) = case(&mut rng, n, wet);
            let message = rng.bits(bits);
            let result = ternary_embed(&cover, &costs, &message, 77, segment).unwrap();
            assert_eq!(
                ternary_extract(&result.stego, result.layer_bits, 77, segment),
                message
            );
            assert!(result.layer_bits.iter().all(|&b| b > 0));
            for (i, (s, c)) in result.stego.iter().zip(&cover).enumerate() {
                match s - c {
                    0 => {}
                    1 => assert!(costs.plus[i].is_finite()),
                    -1 => assert!(costs.minus[i].is_finite()),
                    _ => panic!("change larger than one"),
                }
            }
        }
    }

    #[test]
    fn ternary_stays_close_to_the_bound() {
        let mut rng = Rng(5);
        let (cover, costs) = case(&mut rng, 30_000, false);
        for rate in [0.05, 0.2, 0.5] {
            let bits = (rate * cover.len() as f64) as usize;
            let message = rng.bits(bits);
            let result = ternary_embed(&cover, &costs, &message, 3, usize::MAX).unwrap();
            let loss = result.distortion / bound(&costs, bits);
            // h = 10 loses about 8-15 % on the binary constant profile (TIFS 2011, Fig. 8-9).
            assert!((1.0..1.25).contains(&loss), "rate {rate}: {loss}");
        }
    }

    #[test]
    fn capacity_and_input_errors() {
        let costs = Costs {
            plus: vec![1.0; 10],
            minus: vec![1.0; 10],
        };
        assert_eq!(
            ternary_embed(&[0; 10], &costs, &[1; 20], 1, 128).unwrap_err(),
            StcError::Capacity
        );
        let bad = Costs {
            plus: vec![f64::NAN; 10],
            minus: vec![1.0; 10],
        };
        assert_eq!(
            ternary_embed(&[0; 10], &bad, &[1; 2], 1, 128).unwrap_err(),
            StcError::Input
        );
        assert_eq!(
            ternary_embed(&[0; 10], &costs, &[1; 2], 1, 0).unwrap_err(),
            StcError::Input
        );
    }

    #[test]
    fn prefix_reading_gives_the_bits_of_a_full_pass_for_every_length() {
        let mut rng = Rng(0x5eed);
        for (n, height, segment) in [
            (1, 10, 128),
            (97, 10, 128),
            (5000, 10, 128),
            (4096, 7, 5),
            (777, 16, 3),
        ] {
            let bits: Vec<u8> = (0..n).map(|_| (rng.next() & 1) as u8).collect();
            let cols = columns(n, height, rng.next());
            let prefix = column_prefix(&bits, &cols, height);
            for length in [0, 1, 2, 3, 63, 128, 129, 300, n / 2, n, n + 5] {
                assert_eq!(
                    prefix_extract(&prefix, length, height, segment),
                    binary_extract(&bits, length, &cols, height, segment),
                    "n {n} height {height} segment {segment} length {length}"
                );
            }
        }
    }
}
