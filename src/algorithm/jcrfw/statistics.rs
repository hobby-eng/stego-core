//! Image statistics of J-CRF (Pan et al. 2024, Sec. 4.1): each selected coefficient's variance in
//! quantization steps, and the correlation between neighbouring blocks. The pixel model is
//! J-MiPOD's with a 5×5 window; how the residual is summed is in docs/TECHNICAL.md.

use crate::algorithm::jmipod::sampling::{BlockRect, Dct, Raster, SIDE, Selection, TILE_BLOCKS};
use crate::algorithm::jmipod::statistics::global_noise;
use crate::algorithm::model::{BLOCK, DctPlane};

/// Window side `p` of the variance estimator.
const P: usize = 5;
/// Residual degrees of freedom: `p² − d(d+1)/2` with `d = 3`.
const DOF: f64 = 19.0;
/// Lower bound of the coefficient variance in quantization steps (Sec. 4.1).
pub(crate) const VARIANCE_FLOOR: f64 = 1e-10;
/// Bound on `|ϱ|` (Sec. 4.1).
pub(crate) const CORRELATION_LIMIT: f64 = 0.99;

/// Statistics of one plane for the selected positions.
pub(crate) struct Model {
    /// Variance in quantization steps per position (caller order); 0 for wet positions.
    pub(crate) variance: Vec<f64>,
    /// Correlation between block `b` and block `b + 1`; NaN where not computed.
    pub(crate) right: Vec<f64>,
    /// Correlation between block `b` and the block below; NaN where not computed.
    pub(crate) down: Vec<f64>,
}

/// Pixel variances and noises of one block, row-major.
type Fit = ([f64; BLOCK], [f64; BLOCK]);

/// The orthonormal 5-point DCT-II basis. Variance and centre noise are summed from the 19 residual
/// coefficients directly, not as total minus fit, so nothing cancels when the fit holds most of
/// the energy.
pub(super) struct Basis {
    phi: [[f64; P]; P],
}

impl Basis {
    pub(super) fn new() -> Self {
        let phi = std::array::from_fn(|k| {
            let scale = if k == 0 { 0.2f64.sqrt() } else { 0.4f64.sqrt() };
            std::array::from_fn(|j| {
                scale
                    * (k as f64 * std::f64::consts::PI * (2 * j + 1) as f64 / (2 * P) as f64).cos()
            })
        });
        Self { phi }
    }

    /// Row projections `h[v] = Σ_j φ_v[j] row[j]` of five consecutive pixels.
    fn rows(&self, row: &[f64]) -> [f64; P] {
        std::array::from_fn(|v| self.phi[v].iter().zip(row).map(|(f, r)| f * r).sum())
    }

    /// Pixel variance `ζ²` and noise `ξ` of the window centre from the row projections of its
    /// five rows.
    fn finish(&self, h: [&[f64; P]; P]) -> (f64, f64) {
        let (mut energy, mut noise) = (0.0, 0.0);
        for (u, phi_u) in self.phi.iter().enumerate() {
            for v in (3usize.saturating_sub(u))..P {
                let c: f64 = phi_u.iter().zip(&h).map(|(f, row)| f * row[v]).sum();
                energy += c * c;
                noise += c * phi_u[P / 2] * self.phi[v][P / 2];
            }
        }
        (energy / DOF, noise)
    }

    /// Pixel variance `ζ²` and noise `ξ` of the centre of one 5×5 window.
    #[cfg(test)]
    pub(super) fn fit(&self, window: &[[f64; P]; P]) -> (f64, f64) {
        let h: [[f64; P]; P] = std::array::from_fn(|i| self.rows(&window[i]));
        self.finish(std::array::from_fn(|i| &h[i]))
    }
}

/// Variances of the selected positions and block correlations around their blocks.
pub(crate) fn model(plane: &DctPlane, selection: &Selection<'_>) -> Model {
    let dct = Dct::new();
    let basis = Basis::new();
    let noise = global_noise(plane, &dct);
    let blocks = plane.blocks_wide * plane.blocks_high;
    let mut out = Model {
        variance: vec![0.0; selection.len()],
        right: vec![f64::NAN; blocks],
        down: vec![f64::NAN; blocks],
    };
    for y in (0..plane.blocks_high).step_by(TILE_BLOCKS) {
        for x in (0..plane.blocks_wide).step_by(TILE_BLOCKS) {
            let tile = BlockRect::tile(plane, x, y, TILE_BLOCKS);
            tile_model(plane, selection, tile, (&dct, &basis, noise), &mut out);
        }
    }
    out
}

/// One tile: decode the blocks around the position blocks, fit windows, write the model.
fn tile_model(
    plane: &DctPlane,
    selection: &Selection<'_>,
    tile: BlockRect,
    (dct, basis, noise): (&Dct, &Basis, f64),
    out: &mut Model,
) {
    let rect = tile.expanded(plane);
    // Modes needed per position block of the tile, indexed in `rect`.
    let mut modes = vec![0u64; rect.width * rect.height];
    selection.visit(tile, plane.blocks_wide, |position, _| {
        let block = position / BLOCK;
        modes[rect.index(block % plane.blocks_wide, block / plane.blocks_wide)] |=
            1 << (position % BLOCK);
    });
    if modes.iter().all(|&m| m == 0) {
        return;
    }
    // Blocks whose noise is needed: position blocks and their four neighbours.
    let mut noisy = vec![false; modes.len()];
    for by in rect.y..rect.y + rect.height {
        for bx in rect.x..rect.x + rect.width {
            if modes[rect.index(bx, by)] != 0 {
                for (nx, ny) in cross(bx, by, plane).into_iter().flatten() {
                    if rect_contains(rect, nx, ny) {
                        noisy[rect.index(nx, ny)] = true;
                    }
                }
                noisy[rect.index(bx, by)] = true;
            }
        }
    }
    let image_rect = rect.expanded(plane);
    let mut decode = vec![false; image_rect.width * image_rect.height];
    for by in rect.y..rect.y + rect.height {
        for bx in rect.x..rect.x + rect.width {
            if noisy[rect.index(bx, by)] {
                image_rect.neighbors(bx, by, |x, y, _| decode[image_rect.index(x, y)] = true);
            }
        }
    }
    let residual = Raster::reconstruct(plane, image_rect, dct, Some(&decode)).residual(noise);
    let mut fits: Vec<Option<Fit>> = vec![None; modes.len()];
    for by in rect.y..rect.y + rect.height {
        for bx in rect.x..rect.x + rect.width {
            if noisy[rect.index(bx, by)] {
                fits[rect.index(bx, by)] = Some(block_fit(&residual, basis, bx, by));
            }
        }
    }
    write_tile(plane, selection, tile, rect, (&modes, &fits, dct), out);
}

/// Pixel variances and noises of block `(bx, by)`, row-major. The row projections of the
/// block's 12×8 window positions are shared by the windows of a column.
fn block_fit(residual: &Raster, basis: &Basis, bx: usize, by: usize) -> Fit {
    const SPAN: usize = SIDE + P - 1;
    let half = (P / 2) as isize;
    let (x0, y0) = ((bx * SIDE) as isize - half, (by * SIDE) as isize - half);
    let mut h = [[[0.0; P]; SIDE]; SPAN];
    for (dy, projections) in h.iter_mut().enumerate() {
        let row: [f64; SPAN] =
            std::array::from_fn(|dx| residual.mirror(x0 + dx as isize, y0 + dy as isize));
        for (x, value) in projections.iter_mut().enumerate() {
            *value = basis.rows(&row[x..x + P]);
        }
    }
    let (mut variance, mut noise) = ([0.0; BLOCK], [0.0; BLOCK]);
    for y in 0..SIDE {
        for x in 0..SIDE {
            (variance[y * SIDE + x], noise[y * SIDE + x]) =
                basis.finish(std::array::from_fn(|i| &h[y + i][x]));
        }
    }
    (variance, noise)
}

/// Writes coefficient variances of the tile's positions and correlations of their blocks.
fn write_tile(
    plane: &DctPlane,
    selection: &Selection<'_>,
    tile: BlockRect,
    rect: BlockRect,
    (modes, fits, dct): (&[u64], &[Option<Fit>], &Dct),
    out: &mut Model,
) {
    let mut variances: Vec<Option<[f64; BLOCK]>> = vec![None; modes.len()];
    for by in tile.y..tile.y + tile.height {
        for bx in tile.x..tile.x + tile.width {
            let index = rect.index(bx, by);
            let Some((pixels, noise)) = &fits[index] else {
                continue;
            };
            if modes[index] == 0 {
                continue;
            }
            variances[index] = Some(dct.variance(pixels, modes[index]));
            let block = by * plane.blocks_wide + bx;
            for (nx, ny) in cross(bx, by, plane).into_iter().flatten() {
                let Some((_, other)) = &fits[rect.index(nx, ny)] else {
                    continue;
                };
                let rho = correlation(noise, other);
                let neighbour = ny * plane.blocks_wide + nx;
                match (ny == by, nx > bx || ny > by) {
                    (true, true) => out.right[block] = rho,
                    (true, false) => out.right[neighbour] = rho,
                    (false, true) => out.down[block] = rho,
                    (false, false) => out.down[neighbour] = rho,
                }
            }
        }
    }
    selection.visit(tile, plane.blocks_wide, |position, output| {
        let block = position / BLOCK;
        let mode = position % BLOCK;
        let index = rect.index(block % plane.blocks_wide, block / plane.blocks_wide);
        if let Some(values) = &variances[index] {
            // `Dct::variance` already floors at 1e-10 in DCT units; with steps ≥ 1 that never
            // lifts a value above the floor applied here in quantization steps.
            let step = f64::from(plane.quant[mode]);
            out.variance[output] = (values[mode] / (step * step)).max(VARIANCE_FLOOR);
        }
    });
}

/// The four neighbours of a block that exist: left, right, up, down.
pub(crate) fn cross(bx: usize, by: usize, plane: &DctPlane) -> [Option<(usize, usize)>; 4] {
    [
        (bx > 0).then(|| (bx - 1, by)),
        (bx + 1 < plane.blocks_wide).then(|| (bx + 1, by)),
        (by > 0).then(|| (bx, by - 1)),
        (by + 1 < plane.blocks_high).then(|| (bx, by + 1)),
    ]
}

fn rect_contains(rect: BlockRect, x: usize, y: usize) -> bool {
    x >= rect.x && x < rect.x + rect.width && y >= rect.y && y < rect.y + rect.height
}

/// Pearson's correlation of two blocks of noise, bounded by [`CORRELATION_LIMIT`]; 0 when either
/// block has no spread.
pub(crate) fn correlation(a: &[f64; BLOCK], b: &[f64; BLOCK]) -> f64 {
    let mean_a = a.iter().sum::<f64>() / BLOCK as f64;
    let mean_b = b.iter().sum::<f64>() / BLOCK as f64;
    let (mut ab, mut aa, mut bb) = (0.0, 0.0, 0.0);
    for (x, y) in a.iter().zip(b) {
        let (dx, dy) = (x - mean_a, y - mean_b);
        ab += dx * dy;
        aa += dx * dx;
        bb += dy * dy;
    }
    let denominator = (aa * bb).sqrt();
    if denominator > 0.0 {
        (ab / denominator).clamp(-CORRELATION_LIMIT, CORRELATION_LIMIT)
    } else {
        0.0
    }
}

#[cfg(test)]
pub(super) fn basis_fit(window: &[[f64; P]; P]) -> (f64, f64) {
    Basis::new().fit(window)
}
