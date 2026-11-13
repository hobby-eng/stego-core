use super::sampling::{BlockRect, Dct, Raster, SIDE, Selection, Sum, TILE_BLOCKS};
use crate::algorithm::model::{BLOCK, DctPlane};

pub(super) fn fisher_information(plane: &DctPlane, selection: &Selection<'_>) -> Vec<f64> {
    let dct = Dct::new();
    let noise = global_noise(plane, &dct);
    selected_information(plane, selection, &dct, noise, TILE_BLOCKS)
}

pub(crate) fn global_noise(plane: &DctPlane, dct: &Dct) -> f64 {
    let mut sum = Sum::new();
    for y in (0..plane.blocks_high).step_by(TILE_BLOCKS) {
        for x in (0..plane.blocks_wide).step_by(TILE_BLOCKS) {
            let tile = BlockRect::tile(plane, x, y, TILE_BLOCKS);
            let image = Raster::reconstruct(plane, tile.expanded(plane), dct, None);
            for py in y * SIDE..(y + tile.height) * SIDE {
                for px in x * SIDE..(x + tile.width) * SIDE {
                    sum.add(image.moments(px, py).1);
                }
            }
        }
    }
    sum.value() / plane.coefficients.len() as f64
}

fn selected_information(
    plane: &DctPlane,
    selection: &Selection<'_>,
    dct: &Dct,
    noise: f64,
    tile_blocks: usize,
) -> Vec<f64> {
    let mut information = vec![0.0; selection.len()];
    for y in (0..plane.blocks_high).step_by(tile_blocks) {
        for x in (0..plane.blocks_wide).step_by(tile_blocks) {
            let tile = BlockRect::tile(plane, x, y, tile_blocks);
            let rect = tile.expanded(plane);
            let mut modes = vec![0u64; rect.width * rect.height];
            selection.visit(tile, plane.blocks_wide, |position, _| {
                let block = position / BLOCK;
                let bit = 1u64 << (position % BLOCK);
                rect.neighbors(
                    block % plane.blocks_wide,
                    block / plane.blocks_wide,
                    |bx, by, _| {
                        modes[rect.index(bx, by)] |= bit;
                    },
                );
            });
            if modes.iter().all(|&m| m == 0) {
                continue;
            }
            let variances = tile_variances(plane, rect, &modes, dct, noise);
            selection.visit(tile, plane.blocks_wide, |position, output| {
                let block = position / BLOCK;
                let mode = position % BLOCK;
                let mut weighted = 0.0;
                let mut weight_sum = 0;
                rect.neighbors(
                    block % plane.blocks_wide,
                    block / plane.blocks_wide,
                    |bx, by, weight| {
                        let variance = variances[rect.index(bx, by) * BLOCK + mode];
                        weighted += weight as f64 / variance.powi(2);
                        weight_sum += weight;
                    },
                );
                information[output] =
                    f64::from(plane.quant[mode]).powi(4) * weighted / weight_sum as f64;
            });
        }
    }
    information
}

fn tile_variances(
    plane: &DctPlane,
    rect: BlockRect,
    modes: &[u64],
    dct: &Dct,
    noise: f64,
) -> Vec<f64> {
    let image_rect = rect.expanded(plane);
    let mut needed = vec![false; image_rect.width * image_rect.height];
    for by in rect.y..rect.y + rect.height {
        for bx in rect.x..rect.x + rect.width {
            if modes[rect.index(bx, by)] != 0 {
                image_rect.neighbors(bx, by, |x, y, _| {
                    needed[image_rect.index(x, y)] = true;
                });
            }
        }
    }
    let residual = Raster::reconstruct(plane, image_rect, dct, Some(&needed)).residual(noise);
    let mut variances = vec![0.0; rect.width * rect.height * BLOCK];
    for by in rect.y..rect.y + rect.height {
        for bx in rect.x..rect.x + rect.width {
            let index = rect.index(bx, by);
            if modes[index] == 0 {
                continue;
            }
            let mut pixels = [0.0; BLOCK];
            for y in 0..SIDE {
                for x in 0..SIDE {
                    let mut patch = [0.0; 9];
                    for dy in 0..3 {
                        for dx in 0..3 {
                            patch[dy * 3 + dx] = residual.mirror(
                                (bx * SIDE + x + dx) as isize - 1,
                                (by * SIDE + y + dy) as isize - 1,
                            );
                        }
                    }
                    pixels[y * SIDE + x] = projected_variance(&patch);
                }
            }
            variances[index * BLOCK..(index + 1) * BLOCK]
                .copy_from_slice(&dct.variance(&pixels, modes[index]));
        }
    }
    variances
}

fn projected_variance(r: &[f64; 9]) -> f64 {
    // The six low-frequency DCT-II cosine products span a+b<3. Its orthogonal
    // complement consists of the three modes (1,2), (2,1), (2,2). Their squared
    // projections avoid a per-pixel matrix inverse; the residual has 9-6=3 DOF.
    let top = r[0] - 2.0 * r[1] + r[2];
    let middle = r[3] - 2.0 * r[4] + r[5];
    let bottom = r[6] - 2.0 * r[7] + r[8];
    let a = top - bottom;
    let b = (r[0] - r[2]) - 2.0 * (r[3] - r[5]) + (r[6] - r[8]);
    let c = top - 2.0 * middle + bottom;
    (a * a / 12.0 + b * b / 12.0 + c * c / 36.0) / 3.0
}

#[cfg(test)]
mod tests;
