//! J-UNIWARD costs (Holub, Fridrich, Denemark 2014) for ±1 changes: the change of three
//! Daubechies-8 wavelet residuals, each divided by `σ + |residual|` with `σ = 2⁻⁶`. Residual
//! changes per frequency are precomputed once; cover residuals are computed in 512-pixel tiles.

use crate::algorithm::model::{BLOCK, CostError, CostModel, Costs, DctPlane, Permitted};

const SIDE: usize = 8;
const TILE: usize = 512;
const HALO: usize = 16;
const TAPS: usize = 16;
const IMPACT: usize = SIDE + TAPS - 1;
const SIGMA: f64 = 1.0 / 64.0;
/// Daubechies-8 decomposition low-pass filter.
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

/// The J-UNIWARD cost model. Stateless; costs do not depend on the payload.
#[derive(Clone, Copy, Debug, Default)]
pub struct JUniward;

impl CostModel for JUniward {
    fn costs(
        &self,
        plane: &DctPlane,
        positions: &[usize],
        permitted: &[Permitted],
        _payload_bits: f64,
    ) -> Result<Costs, CostError> {
        check_positions(plane, positions, permitted)?;
        let distortion = distortions(plane, positions);
        let mut plus = Vec::with_capacity(positions.len());
        let mut minus = Vec::with_capacity(positions.len());
        for (cost, rule) in distortion.iter().zip(permitted) {
            let (p, m) = match rule {
                Permitted::None => (f64::INFINITY, f64::INFINITY),
                Permitted::Plus => (*cost, f64::INFINITY),
                Permitted::Minus => (f64::INFINITY, *cost),
                Permitted::Both => (*cost, *cost),
            };
            plus.push(p);
            minus.push(m);
        }
        Ok(Costs { plus, minus })
    }
}

/// Validates the plane, that positions are in range and distinct, and the permission count.
pub fn check_positions(
    plane: &DctPlane,
    positions: &[usize],
    permitted: &[Permitted],
) -> Result<(), CostError> {
    plane.validate()?;
    if permitted.len() != positions.len() {
        return Err(CostError::Permission);
    }
    let mut sorted = positions.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1])
        || sorted
            .last()
            .is_some_and(|&p| p >= plane.coefficients.len())
    {
        return Err(CostError::Permission);
    }
    Ok(())
}

/// J-UNIWARD distortion of a unit change at each position (positions already validated).
pub fn distortions(plane: &DctPlane, positions: &[usize]) -> Vec<f64> {
    let filters = Filters::new();
    let width = plane.blocks_wide * SIDE;
    let tiles_x = width.div_ceil(TILE);
    let mut order: Vec<(usize, usize)> = positions
        .iter()
        .enumerate()
        .map(|(index, &position)| {
            let block = position / BLOCK;
            let x = (block % plane.blocks_wide) * SIDE;
            let y = (block / plane.blocks_wide) * SIDE;
            ((y / TILE) * tiles_x + x / TILE, index)
        })
        .collect();
    order.sort_unstable();
    let mut out = vec![0.0; positions.len()];
    let mut start = 0;
    while start < order.len() {
        let tile = order[start].0;
        let end = start
            + order[start..]
                .iter()
                .take_while(|(t, _)| *t == tile)
                .count();
        let residuals = Residuals::new(
            plane,
            &filters,
            (tile % tiles_x) * TILE,
            (tile / tiles_x) * TILE,
        );
        for &(_, index) in &order[start..end] {
            out[index] = residuals.cost(plane, &filters, positions[index]);
        }
        start = end;
    }
    out
}

/// The 1-D DCT basis and the absolute filter responses to each basis vector.
struct Filters {
    basis: [[f64; SIDE]; SIDE],
    low: [f64; TAPS],
    high: [f64; TAPS],
    /// `impacts[0]` for the low-pass filter, `impacts[1]` for the high-pass filter.
    impacts: [[[f64; IMPACT]; SIDE]; 2],
}

impl Filters {
    fn new() -> Self {
        let basis = std::array::from_fn(|x| {
            std::array::from_fn(|u| {
                let scale = if u == 0 {
                    std::f64::consts::FRAC_1_SQRT_2
                } else {
                    1.0
                };
                0.5 * scale * ((2 * x + 1) as f64 * u as f64 * std::f64::consts::PI / 16.0).cos()
            })
        });
        let high = std::array::from_fn(|i| LOW[TAPS - 1 - i] * if i % 2 == 0 { -1.0 } else { 1.0 });
        let impacts = [impact(&LOW, &basis), impact(&high, &basis)];
        Self {
            basis,
            low: LOW,
            high,
            impacts,
        }
    }
}

/// `impact[f][s]` = |Σ_i basis[i][f] · filter[i + TAPS − 1 − s]|: the response of the full
/// correlation used by [`horizontal`] and [`vertical`] at offset `s` from the block start.
fn impact(filter: &[f64; TAPS], basis: &[[f64; SIDE]; SIDE]) -> [[f64; IMPACT]; SIDE] {
    std::array::from_fn(|frequency| {
        std::array::from_fn(|sample| {
            let mut sum = 0.0;
            for (i, row) in basis.iter().enumerate() {
                let j = i as isize + (TAPS - 1) as isize - sample as isize;
                if (0..TAPS as isize).contains(&j) {
                    sum += row[frequency] * filter[j as usize];
                }
            }
            sum.abs()
        })
    })
}

/// Reciprocal cover residuals `1 / (σ + |W_k|)` of one tile for the three directional bands.
struct Residuals {
    left: usize,
    top: usize,
    row_length: usize,
    reciprocal: [Vec<f64>; 3],
}

impl Residuals {
    fn new(plane: &DctPlane, filters: &Filters, left: usize, top: usize) -> Self {
        let full_w = plane.blocks_wide * SIDE;
        let full_h = plane.blocks_high * SIDE;
        let width = TILE.min(full_w - left) + 2 * HALO;
        let height = TILE.min(full_h - top) + 2 * HALO;
        let pixels = tile_pixels(
            plane,
            filters,
            left as isize - HALO as isize,
            top as isize - HALO as isize,
            width,
            height,
        );
        let low_rows = horizontal(&pixels, width, height, &filters.low);
        let high_rows = horizontal(&pixels, width, height, &filters.high);
        let row_length = width + TAPS - 1;
        let reciprocal = [
            vertical(&low_rows, row_length, height, &filters.high),
            vertical(&high_rows, row_length, height, &filters.low),
            vertical(&high_rows, row_length, height, &filters.high),
        ]
        .map(|band| band.into_iter().map(|w| 1.0 / (w.abs() + SIGMA)).collect());
        Self {
            left,
            top,
            row_length,
            reciprocal,
        }
    }

    fn cost(&self, plane: &DctPlane, filters: &Filters, position: usize) -> f64 {
        let block = position / BLOCK;
        let mode = position % BLOCK;
        let x = (block % plane.blocks_wide) * SIDE - self.left + HALO;
        let y = (block / plane.blocks_wide) * SIDE - self.top + HALO;
        let mut sum = 0.0;
        // Bands: (vertical filter, horizontal filter) = (high, low), (low, high), (high, high).
        for (band, (vf, hf)) in [(1, 0), (0, 1), (1, 1)].into_iter().enumerate() {
            let a = &filters.impacts[vf][mode / SIDE];
            let b = &filters.impacts[hf][mode % SIDE];
            let rec = &self.reciprocal[band];
            for (dy, ay) in a.iter().enumerate() {
                let row = &rec[(y + dy) * self.row_length + x..][..IMPACT];
                sum += ay * b.iter().zip(row).map(|(bx, r)| bx * r).sum::<f64>();
            }
        }
        sum * f64::from(plane.quant[mode])
    }
}

/// Symmetric (half-sample) reflection of a coordinate into `0..len`.
pub fn reflect(coordinate: isize, len: usize) -> usize {
    let period = 2 * len as isize;
    let value = coordinate.rem_euclid(period);
    if value < len as isize {
        value as usize
    } else {
        (period - 1 - value) as usize
    }
}

/// Decompressed pixels (unrounded, unclipped) of a padded tile with mirrored borders.
fn tile_pixels(
    plane: &DctPlane,
    filters: &Filters,
    left: isize,
    top: isize,
    width: usize,
    height: usize,
) -> Vec<f64> {
    let full_w = plane.blocks_wide * SIDE;
    let full_h = plane.blocks_high * SIDE;
    let mut pixels = vec![0.0; width * height];
    for by in (0..height).step_by(SIDE) {
        for bx in (0..width).step_by(SIDE) {
            let sx = reflect(left + bx as isize, full_w) / SIDE;
            let sy = reflect(top + by as isize, full_h) / SIDE;
            let block = decode_block(plane, filters, sy * plane.blocks_wide + sx);
            for y in 0..SIDE.min(height - by) {
                for x in 0..SIDE.min(width - bx) {
                    let gx = reflect(left + (bx + x) as isize, full_w) % SIDE;
                    let gy = reflect(top + (by + y) as isize, full_h) % SIDE;
                    pixels[(by + y) * width + bx + x] = block[gy * SIDE + gx];
                }
            }
        }
    }
    pixels
}

/// Inverse orthonormal 8×8 DCT of one dequantized block, plus 128.
fn decode_block(plane: &DctPlane, filters: &Filters, block: usize) -> [f64; BLOCK] {
    let coefficients = &plane.coefficients[block * BLOCK..][..BLOCK];
    let basis = &filters.basis;
    let mut temp = [[0.0; SIDE]; SIDE];
    for (y, row) in temp.iter_mut().enumerate() {
        for (v, value) in row.iter_mut().enumerate() {
            for u in 0..SIDE {
                *value += basis[y][u]
                    * f64::from(coefficients[u * SIDE + v])
                    * f64::from(plane.quant[u * SIDE + v]);
            }
        }
    }
    let mut out = [128.0; BLOCK];
    for y in 0..SIDE {
        for x in 0..SIDE {
            out[y * SIDE + x] += temp[y]
                .iter()
                .enumerate()
                .map(|(v, t)| basis[x][v] * t)
                .sum::<f64>();
        }
    }
    out
}

/// Full horizontal correlation: `out[y][x] = Σ_j filter[j] · p[y][x + j − 15]`, mirrored at the edges.
fn horizontal(pixels: &[f64], width: usize, height: usize, filter: &[f64; TAPS]) -> Vec<f64> {
    let columns = width + TAPS - 1;
    let mut out = vec![0.0; columns * height];
    for y in 0..height {
        for x in 0..columns {
            out[y * columns + x] = filter
                .iter()
                .enumerate()
                .map(|(j, tap)| {
                    tap * pixels
                        [y * width + reflect(x as isize + j as isize - (TAPS - 1) as isize, width)]
                })
                .sum();
        }
    }
    out
}

/// Full vertical correlation of the horizontal result, same convention as [`horizontal`].
fn vertical(rows: &[f64], columns: usize, height: usize, filter: &[f64; TAPS]) -> Vec<f64> {
    let mut out = vec![0.0; columns * (height + TAPS - 1)];
    for y in 0..height + TAPS - 1 {
        for x in 0..columns {
            out[y * columns + x] = filter
                .iter()
                .enumerate()
                .map(|(j, tap)| {
                    tap * rows[reflect(y as isize + j as isize - (TAPS - 1) as isize, height)
                        * columns
                        + x]
                })
                .sum();
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "test code")]
mod tests {
    use super::*;

    fn plane(blocks_wide: usize, blocks_high: usize, seed: u64) -> DctPlane {
        let mut state = seed;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as i64
        };
        let coefficients = (0..blocks_wide * blocks_high * BLOCK)
            .map(|i| {
                let mode = i % BLOCK;
                let spread = if mode == 0 {
                    40
                } else {
                    1 + 12 / (1 + mode / 8 + mode % 8) as i64
                };
                (next() % (2 * spread + 1) - spread) as i16
            })
            .collect();
        let quant = std::array::from_fn(|m| (1 + (m / 8 + m % 8) / 2) as u16);
        DctPlane {
            blocks_wide,
            blocks_high,
            coefficients,
            quant,
        }
    }

    /// Brute force: distortion = Σ |W(X + Δ) − W(X)| / (σ + |W(X)|) over the whole padded tile,
    /// with Δ placed only at the changed block. This checks the precomputed impact windows and
    /// their alignment (the reference J-UNIWARD code reads its window one pixel off).
    fn brute(plane: &DctPlane, position: usize) -> f64 {
        let filters = Filters::new();
        let width = plane.blocks_wide * SIDE + 2 * HALO;
        let height = plane.blocks_high * SIDE + 2 * HALO;
        let cover = tile_pixels(
            plane,
            &filters,
            -(HALO as isize),
            -(HALO as isize),
            width,
            height,
        );
        let mut changed = plane.clone();
        changed.coefficients[position] += 1;
        let block = position / BLOCK;
        let decoded = decode_block(&changed, &filters, block);
        let original = decode_block(plane, &filters, block);
        let mut stego = cover.clone();
        let bx = (block % plane.blocks_wide) * SIDE + HALO;
        let by = (block / plane.blocks_wide) * SIDE + HALO;
        for y in 0..SIDE {
            for x in 0..SIDE {
                stego[(by + y) * width + bx + x] += decoded[y * SIDE + x] - original[y * SIDE + x];
            }
        }
        let bands = |p: &[f64]| {
            let low = horizontal(p, width, height, &filters.low);
            let high = horizontal(p, width, height, &filters.high);
            let cols = width + TAPS - 1;
            [
                vertical(&low, cols, height, &filters.high),
                vertical(&high, cols, height, &filters.low),
                vertical(&high, cols, height, &filters.high),
            ]
        };
        let (wc, ws) = (bands(&cover), bands(&stego));
        wc.iter()
            .zip(&ws)
            .map(|(c, s)| {
                c.iter()
                    .zip(s)
                    .map(|(a, b)| (b - a).abs() / (SIGMA + a.abs()))
                    .sum::<f64>()
            })
            .sum()
    }

    #[test]
    fn fast_costs_equal_the_definition() {
        let plane = plane(5, 4, 7);
        let positions: Vec<usize> = (0..plane.coefficients.len()).step_by(7).collect();
        let fast = distortions(&plane, &positions);
        for (&position, &cost) in positions.iter().zip(&fast) {
            let reference = brute(&plane, position);
            assert!(
                (cost - reference).abs() <= 1e-9 * reference,
                "position {position}: {cost} vs {reference}"
            );
        }
    }

    #[test]
    fn tiles_do_not_change_costs() {
        let plane = plane(70, 3, 11);
        let positions: Vec<usize> = (0..plane.coefficients.len()).step_by(97).collect();
        let fast = distortions(&plane, &positions);
        for (&position, &cost) in positions.iter().zip(&fast).step_by(5) {
            let reference = brute(&plane, position);
            assert!(
                (cost - reference).abs() <= 1e-9 * reference,
                "position {position}"
            );
        }
    }

    #[test]
    fn permissions_map_to_infinite_costs() {
        let plane = plane(2, 2, 3);
        let positions = [1, 2, 3, 4];
        let rules = [
            Permitted::None,
            Permitted::Plus,
            Permitted::Minus,
            Permitted::Both,
        ];
        let costs = JUniward.costs(&plane, &positions, &rules, 0.0).unwrap();
        assert!(costs.plus[0].is_infinite() && costs.minus[0].is_infinite());
        assert!(costs.plus[1].is_finite() && costs.minus[1].is_infinite());
        assert!(costs.plus[2].is_infinite() && costs.minus[2].is_finite());
        assert_eq!(costs.plus[3], costs.minus[3]);
        assert!(costs.plus[3] > 0.0);
        assert_eq!(
            JUniward
                .costs(&plane, &[1, 1], &rules[..2], 0.0)
                .unwrap_err(),
            CostError::Permission
        );
        assert_eq!(
            JUniward.costs(&plane, &[1], &rules, 0.0).unwrap_err(),
            CostError::Permission
        );
    }
}
