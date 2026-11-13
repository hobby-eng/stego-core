//! UERD costs (Guo, Ni, Su, Chen and Shi, "Using statistical image model for JPEG
//! steganography: uniform embedding revisited", IEEE TIFS 10(12):2669–2680, 2015) for ±1 changes.
//!
//! The cost of changing mode `(u, v)` of block `b` is the quantization step `q_uv` divided by the
//! block's complexity: its energy `E_b = Σ |c| · q` over the block's AC modes, plus a quarter of
//! the energies of its eight neighbouring blocks (outside the image the edge blocks are repeated,
//! as in the reference implementations). The DC step is replaced by `(q_01 + q_10) / 2`. A change
//! of +1 and of −1 cost the same; a block whose complexity is zero gets an infinite cost. Equal to
//! conseal 2026.11 (`conseal.uerd.compute_cost_adjusted`) on four public photos, interior and edge
//! blocks and DC.

use crate::algorithm::juniward::check_positions;
use crate::algorithm::model::{BLOCK, CostError, CostModel, Costs, DctPlane, Permitted};

/// The UERD cost model. Stateless; costs do not depend on the payload.
#[derive(Clone, Copy, Debug, Default)]
pub struct Uerd;

impl CostModel for Uerd {
    fn costs(
        &self,
        plane: &DctPlane,
        positions: &[usize],
        permitted: &[Permitted],
        _payload_bits: f64,
    ) -> Result<Costs, CostError> {
        check_positions(plane, positions, permitted)?;
        let cost = distortions(plane, positions);
        let mut plus = Vec::with_capacity(positions.len());
        let mut minus = Vec::with_capacity(positions.len());
        for (c, rule) in cost.iter().zip(permitted) {
            let (p, m) = match rule {
                Permitted::None => (f64::INFINITY, f64::INFINITY),
                Permitted::Plus => (*c, f64::INFINITY),
                Permitted::Minus => (f64::INFINITY, *c),
                Permitted::Both => (*c, *c),
            };
            plus.push(p);
            minus.push(m);
        }
        Ok(Costs { plus, minus })
    }
}

/// UERD cost of a unit change at each position (positions already validated).
pub fn distortions(plane: &DctPlane, positions: &[usize]) -> Vec<f64> {
    let (wide, high) = (plane.blocks_wide, plane.blocks_high);
    let q: Vec<f64> = plane.quant.iter().map(|&s| f64::from(s)).collect();
    let energy: Vec<f64> = plane
        .coefficients
        .as_chunks::<BLOCK>()
        .0
        .iter()
        .map(|block| {
            block
                .iter()
                .zip(&q)
                .skip(1)
                .map(|(&c, &step)| f64::from(c).abs() * step)
                .sum()
        })
        .collect();
    let complexity = |b: usize| -> f64 {
        let (by, bx) = (b / wide, b % wide);
        let mut neighbours = 0.0;
        for dy in -1_isize..=1 {
            for dx in -1_isize..=1 {
                if dy == 0 && dx == 0 {
                    continue;
                }
                let y = (by as isize + dy).clamp(0, high as isize - 1) as usize;
                let x = (bx as isize + dx).clamp(0, wide as isize - 1) as usize;
                neighbours += energy[y * wide + x];
            }
        }
        energy[b] + 0.25 * neighbours
    };
    let dc_step = (q[1] + q[8]) / 2.0;
    positions
        .iter()
        .map(|&p| {
            let (block, mode) = (p / BLOCK, p % BLOCK);
            let step = if mode == 0 { dc_step } else { q[mode] };
            let d = complexity(block);
            if d > 0.0 { step / d } else { f64::INFINITY }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plane(wide: usize, high: usize, fill: impl Fn(usize) -> i16) -> DctPlane {
        DctPlane {
            blocks_wide: wide,
            blocks_high: high,
            coefficients: (0..wide * high * BLOCK).map(fill).collect(),
            quant: std::array::from_fn(|m| (1 + m % 7) as u16),
        }
    }

    #[test]
    fn interior_block_uses_its_energy_and_a_quarter_of_eight_neighbours() {
        // Every AC coefficient is 1, so every block's energy is the sum of the AC steps.
        let p = plane(3, 3, |i| i16::from(i % BLOCK != 0));
        let energy: f64 = (1..BLOCK).map(|m| f64::from(p.quant[m])).sum();
        let centre = 4 * BLOCK + 9; // block (1, 1), mode (1, 1)
        let cost = distortions(&p, &[centre])[0];
        let expected = f64::from(p.quant[9]) / (energy + 0.25 * 8.0 * energy);
        assert!(
            (cost - expected).abs() <= 1e-15 * expected,
            "{cost} vs {expected}"
        );
    }

    #[test]
    fn a_flat_neighbourhood_is_wet_and_the_dc_step_is_the_mean_of_two() {
        let flat = plane(2, 2, |_| 0);
        assert!(distortions(&flat, &[5])[0].is_infinite());
        let p = plane(1, 1, |i| i16::from(i == 1));
        let energy = f64::from(p.quant[1]);
        let dc = distortions(&p, &[0])[0];
        let expected =
            (f64::from(p.quant[1]) + f64::from(p.quant[8])) / 2.0 / (energy + 0.25 * 8.0 * energy);
        assert!((dc - expected).abs() <= 1e-15 * expected);
    }
}
