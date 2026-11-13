//! J-CRFW weights (Pan et al. 2024, Sec. 4.2).
//!
//! - Block weight `w_b`: the sum over the block's 64 pixels of S-UNIWARD costs of the decompressed
//!   image (Holub, Fridrich, Denemark 2014: Daubechies-8 directional residuals `W_k = K_k * X`,
//!   `ρ_x = Σ_k Σ_y |K_k(y − x)| / (σ + |W_k(y)|)` with `σ = 1`), so smooth blocks weigh more.
//!   As in the reference S-UNIWARD (and conseal, checked to 1e-9), the residual is a convolution
//!   and the image is extended by half-sample symmetric reflection, residuals in the margin
//!   included. (The first version used a correlation, i.e. mirrored filters; fixed 2026-11-10.)
//! - Join weight of an edge: the mean of its two block weights.
//! - Mode weight: 5 for the last `n` modes in zigzag order, 1 for the rest. The paper gives
//!   `n = 16` at quality 75 and `n = 3` at quality 95; between and beyond we interpolate linearly
//!   in the IJG quality estimated from the table and clamp to `0..=16` (our choice).

use crate::algorithm::jmipod::sampling::{BlockRect, Dct, SIDE, TILE_BLOCKS};
use crate::algorithm::model::{BLOCK, DctPlane};

const TAPS: usize = 16;
/// S-UNIWARD's stabilizing constant in the spatial domain.
const SIGMA: f64 = 1.0;
/// Pixels of context per side: residuals need 15, their impact another 15.
pub(crate) const HALO: usize = 32;
/// Weight of the heavy (last zigzag) modes.
pub(crate) const HEAVY: f64 = 5.0;

/// Daubechies-8 decomposition low-pass filter (the same constants as `juniward.rs`).
const LOW: [f64; TAPS] = [
    -0.000_117_476_784_124_769_53,
    0.000_675_449_406_450_569_3,
    -0.000_391_740_373_376_947_05,
    -0.004_870_352_993_451_574,
    0.008_746_094_047_405_777,
    0.013_981_027_917_398_282,
    -0.044_088_253_930_794_755,
    -0.017_369_301_001_807_547,
    0.128_747_426_620_478_47,
    0.000_472_484_573_913_282_8,
    -0.284_015_542_961_546_9,
    -0.015_829_105_256_349_306,
    0.585_354_683_654_206_7,
    0.675_630_736_297_289_8,
    0.312_871_590_914_299_95,
    0.054_415_842_243_104_01,
];

/// JPEG zigzag order: natural index (`u * 8 + v`) of the k-th zigzag mode.
const ZIGZAG: [usize; BLOCK] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// IJG standard luminance table, natural order.
const IJG: [u16; BLOCK] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];

/// The IJG quality (1–100) whose scaled luminance table is closest to `quant` (sum of absolute
/// differences; the lowest quality wins a tie).
pub(crate) fn ijg_quality(quant: &[u16; BLOCK]) -> u32 {
    let mut best = (u64::MAX, 1);
    for quality in 1..=100_u32 {
        let scale = if quality < 50 {
            5000 / quality
        } else {
            200 - 2 * quality
        };
        let error: u64 = IJG
            .iter()
            .zip(quant)
            .map(|(&t, &q)| {
                let scaled = ((u32::from(t) * scale + 50) / 100).clamp(1, 255);
                u64::from(scaled.abs_diff(u32::from(q)))
            })
            .sum();
        if error < best.0 {
            best = (error, quality);
        }
    }
    best.1
}

/// Number of heavy modes for a quantization table: 16 at quality 75, 3 at 95, linear, clamped.
pub(crate) fn heavy_modes(quant: &[u16; BLOCK]) -> usize {
    let quality = f64::from(ijg_quality(quant));
    (16.0 + (quality - 75.0) * (3.0 - 16.0) / 20.0)
        .round()
        .clamp(0.0, 16.0) as usize
}

/// Mode weights in natural order: [`HEAVY`] for the last `heavy` zigzag modes, 1 elsewhere.
pub(crate) fn mode_weights(heavy: usize) -> [f64; BLOCK] {
    let mut weights = [1.0; BLOCK];
    for &mode in &ZIGZAG[BLOCK - heavy.min(BLOCK)..] {
        weights[mode] = HEAVY;
    }
    weights
}

/// Half-sample symmetric reflection of a coordinate into `0..len`.
fn reflect(coordinate: isize, len: usize) -> usize {
    let period = 2 * len as isize;
    let value = coordinate.rem_euclid(period);
    if value < len as isize {
        value as usize
    } else {
        (period - 1 - value) as usize
    }
}

/// S-UNIWARD block weights for the blocks marked in `needed` (block index order); other entries
/// stay NaN.
pub(crate) fn block_weights(plane: &DctPlane, needed: &[bool]) -> Vec<f64> {
    let dct = Dct::new();
    let mut weights = vec![f64::NAN; needed.len()];
    for y in (0..plane.blocks_high).step_by(TILE_BLOCKS) {
        for x in (0..plane.blocks_wide).step_by(TILE_BLOCKS) {
            let tile = BlockRect::tile(plane, x, y, TILE_BLOCKS);
            let any = (tile.y..tile.y + tile.height).any(|by| {
                (tile.x..tile.x + tile.width).any(|bx| needed[by * plane.blocks_wide + bx])
            });
            if any {
                tile_weights(plane, &dct, tile, &mut weights);
            }
        }
    }
    weights
}

/// Pixels of `rows × columns` starting at image coordinates (`left`, `top`), reflected at the
/// image border; only blocks touched by the window are decoded.
fn window_pixels(
    plane: &DctPlane,
    dct: &Dct,
    left: isize,
    top: isize,
    columns: usize,
    rows: usize,
) -> Vec<f64> {
    let (full_w, full_h) = (plane.blocks_wide * SIDE, plane.blocks_high * SIDE);
    let xs: Vec<usize> = (0..columns)
        .map(|c| reflect(left + c as isize, full_w))
        .collect();
    let ys: Vec<usize> = (0..rows)
        .map(|r| reflect(top + r as isize, full_h))
        .collect();
    let mut cache: std::collections::HashMap<usize, [f64; BLOCK]> =
        std::collections::HashMap::new();
    let mut out = vec![0.0; columns * rows];
    for (r, &py) in ys.iter().enumerate() {
        for (c, &px) in xs.iter().enumerate() {
            let block = (py / SIDE) * plane.blocks_wide + px / SIDE;
            let pixels = cache.entry(block).or_insert_with(|| {
                let start = block * BLOCK;
                dct.inverse(&plane.coefficients[start..start + BLOCK], &plane.quant)
            });
            out[r * columns + c] = pixels[(py % SIDE) * SIDE + px % SIDE];
        }
    }
    out
}

/// Separable correlation `out[y][x] = Σ_s Σ_t fv[s] fh[t] in[y + s][x + t]` (valid part).
fn correlate(
    input: &[f64],
    columns: usize,
    rows: usize,
    fv: &[f64; TAPS],
    fh: &[f64; TAPS],
) -> (Vec<f64>, usize, usize) {
    let (out_c, out_r) = (columns - TAPS + 1, rows - TAPS + 1);
    let mut horizontal = vec![0.0; out_c * rows];
    for y in 0..rows {
        let line = &input[y * columns..][..columns];
        for x in 0..out_c {
            horizontal[y * out_c + x] = fh.iter().zip(&line[x..]).map(|(f, v)| f * v).sum();
        }
    }
    let mut out = vec![0.0; out_c * out_r];
    for y in 0..out_r {
        for x in 0..out_c {
            out[y * out_c + x] = fv
                .iter()
                .enumerate()
                .map(|(s, f)| f * horizontal[(y + s) * out_c + x])
                .sum();
        }
    }
    (out, out_c, out_r)
}

/// S-UNIWARD costs of the `(columns − 2·HALO) × (rows − 2·HALO)` pixels inside a window that
/// carries [`HALO`] pixels of reflected context on every side.
///
/// Residuals are convolutions, `W(y) = Σ_s K(s) X(y + 15 − s)` (the orientation of the
/// reference code's `conv2`; checked against conseal), and the cost of a pixel sums
/// `|K| / (σ + |W|)` over every residual it touches, including those in the reflected margin.
pub(crate) fn window_costs(pixels: &[f64], columns: usize, rows: usize) -> Vec<f64> {
    let high: [f64; TAPS] =
        std::array::from_fn(|i| LOW[TAPS - 1 - i] * if i % 2 == 0 { -1.0 } else { 1.0 });
    let reverse = |f: &[f64; TAPS]| -> [f64; TAPS] { std::array::from_fn(|i| f[TAPS - 1 - i]) };
    let (width, height) = (columns - 2 * HALO, rows - 2 * HALO);
    let mut cost = vec![0.0; width * height];
    // Bands (vertical, horizontal): LH, HL, HH.
    for (fv, fh) in [(&LOW, &high), (&high, &LOW), (&high, &high)] {
        // Correlation with the reversed filters is the convolution; W at window offset y uses
        // pixels y..=y+15.
        let (residual, rc, rr) = correlate(pixels, columns, rows, &reverse(fv), &reverse(fh));
        let reciprocal: Vec<f64> = residual.iter().map(|w| 1.0 / (SIGMA + w.abs())).collect();
        // Pixel p enters W(y) with K(y + 15 − p), so its cost is the correlation of the
        // reciprocal with |K| starting at p − 15.
        let (impact, ic, _) = correlate(&reciprocal, rc, rr, &fv.map(f64::abs), &fh.map(f64::abs));
        let offset = HALO - (TAPS - 1);
        for y in 0..height {
            for x in 0..width {
                cost[y * width + x] += impact[(y + offset) * ic + x + offset];
            }
        }
    }
    cost
}

/// Block weights of one tile from a window with [`HALO`] pixels of context.
fn tile_weights(plane: &DctPlane, dct: &Dct, tile: BlockRect, weights: &mut [f64]) {
    let (width, height) = (tile.width * SIDE, tile.height * SIDE);
    let (columns, rows) = (width + 2 * HALO, height + 2 * HALO);
    let left = (tile.x * SIDE) as isize - HALO as isize;
    let top = (tile.y * SIDE) as isize - HALO as isize;
    let pixels = window_pixels(plane, dct, left, top, columns, rows);
    let cost = window_costs(&pixels, columns, rows);
    for by in 0..tile.height {
        for bx in 0..tile.width {
            let mut sum = 0.0;
            for y in 0..SIDE {
                for x in 0..SIDE {
                    sum += cost[(by * SIDE + y) * width + bx * SIDE + x];
                }
            }
            weights[(tile.y + by) * plane.blocks_wide + tile.x + bx] = sum;
        }
    }
}
