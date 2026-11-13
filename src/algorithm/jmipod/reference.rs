//! A slow whole-image Fisher information for tests, written straight from the formulas and
//! independent of the tiled code: textbook inverse DCT, Matlab-style Wiener statistics
//! (`E[x²] − m²`), MiPOD's projector `P⊥ = I − G(GᵀG)⁻¹Gᵀ` built by Gauss–Jordan inversion
//! and used as a 9×9 quadratic form, the 64×64 DCT matrix, and explicit smoothing.

use std::f64::consts::{FRAC_1_SQRT_2, PI};

use crate::algorithm::model::{BLOCK, DctPlane};

/// Window side `p` and polynomial degree `l` chosen by J-MiPOD.
const P: usize = 3;
const DEGREE: usize = 3;

/// `G` of MiPOD eq. (25)–(26): columns `cos(a·u) · cos(b·v)` for `a + b ≤ l − 1`, where
/// `U[i][j] = π(2j+1)/(2p)` and `V = Uᵀ`, unfolded column-major as in the paper.
fn model_matrix() -> Vec<[f64; P * P]> {
    let mut columns = Vec::new();
    for total in 0..DEGREE {
        for a in (0..=total).rev() {
            let b = total - a;
            let mut column = [0.0; P * P];
            for j in 0..P {
                for i in 0..P {
                    let u = PI * (2 * j + 1) as f64 / (2 * P) as f64;
                    let v = PI * (2 * i + 1) as f64 / (2 * P) as f64;
                    column[j * P + i] = (a as f64 * u).cos() * (b as f64 * v).cos();
                }
            }
            columns.push(column);
        }
    }
    columns
}

/// `P⊥ = I − G (GᵀG)⁻¹ Gᵀ` by Gauss–Jordan inversion of the 6×6 Gram matrix.
pub(super) fn projector() -> [[f64; P * P]; P * P] {
    let g = model_matrix();
    let q = g.len();
    assert_eq!(q, DEGREE * (DEGREE + 1) / 2);
    let mut gram: Vec<Vec<f64>> = (0..q)
        .map(|r| {
            (0..q)
                .map(|c| (0..P * P).map(|k| g[r][k] * g[c][k]).sum())
                .collect()
        })
        .collect();
    let mut inverse: Vec<Vec<f64>> = (0..q)
        .map(|r| (0..q).map(|c| if r == c { 1.0 } else { 0.0 }).collect())
        .collect();
    for col in 0..q {
        let pivot = gram[col][col];
        assert!(pivot.abs() > 1e-9);
        for c in 0..q {
            gram[col][c] /= pivot;
            inverse[col][c] /= pivot;
        }
        for row in (0..q).filter(|&r| r != col) {
            let factor = gram[row][col];
            for c in 0..q {
                gram[row][c] -= factor * gram[col][c];
                inverse[row][c] -= factor * inverse[col][c];
            }
        }
    }
    let mut out = [[0.0; P * P]; P * P];
    for (r, row) in out.iter_mut().enumerate() {
        for (c, value) in row.iter_mut().enumerate() {
            let mut hat = 0.0;
            for a in 0..q {
                for b in 0..q {
                    hat += g[a][r] * inverse[a][b] * g[b][c];
                }
            }
            *value = if r == c { 1.0 } else { 0.0 } - hat;
        }
    }
    out
}

/// `D[(u,v),(i,j)] = (1/4) C(u) C(v) cos((2i+1)uπ/16) cos((2j+1)vπ/16)`.
fn dct_entry(u: usize, v: usize, i: usize, j: usize) -> f64 {
    let c = |k: usize| if k == 0 { FRAC_1_SQRT_2 } else { 1.0 };
    0.25 * c(u)
        * c(v)
        * ((2 * i + 1) as f64 * u as f64 * PI / 16.0).cos()
        * ((2 * j + 1) as f64 * v as f64 * PI / 16.0).cos()
}

/// Decompressed image centred on zero (no level shift), row-major `height × width`.
fn decompress(plane: &DctPlane) -> Vec<f64> {
    let width = plane.blocks_wide * 8;
    let mut image = vec![0.0; width * plane.blocks_high * 8];
    for (b, block) in plane.coefficients.as_chunks::<BLOCK>().0.iter().enumerate() {
        let (by, bx) = (b / plane.blocks_wide, b % plane.blocks_wide);
        for (k, &level) in block.iter().enumerate() {
            let value = f64::from(level) * f64::from(plane.quant[k]);
            for i in 0..8 {
                for j in 0..8 {
                    image[(by * 8 + i) * width + bx * 8 + j] +=
                        value * dct_entry(k / 8, k % 8, i, j);
                }
            }
        }
    }
    image
}

/// `wiener2(X, [2 2])` residual `X − F(X)`: window rows `y, y+1`, columns `x, x+1`, zeros
/// outside, noise = mean local variance.
fn wiener_residual(image: &[f64], width: usize, height: usize) -> Vec<f64> {
    let at = |y: usize, x: usize| {
        if y < height && x < width {
            image[y * width + x]
        } else {
            0.0
        }
    };
    let stats: Vec<(f64, f64)> = (0..width * height)
        .map(|n| {
            let (y, x) = (n / width, n % width);
            let window = [at(y, x), at(y, x + 1), at(y + 1, x), at(y + 1, x + 1)];
            let mean = window.iter().sum::<f64>() / 4.0;
            let square = window.iter().map(|v| v * v).sum::<f64>() / 4.0;
            (mean, square - mean * mean)
        })
        .collect();
    let noise = stats.iter().map(|s| s.1).sum::<f64>() / (width * height) as f64;
    stats
        .iter()
        .zip(image)
        .map(|(&(mean, variance), &x)| {
            let gain = (variance - noise).max(0.0) / variance.max(noise);
            x - (mean + gain * (x - mean))
        })
        .collect()
}

/// Pixel variances `rᵀ P⊥ r / 3` over 3×3 windows, edge sample repeated outside the image.
fn pixel_variances(residual: &[f64], width: usize, height: usize) -> Vec<f64> {
    let p = projector();
    let clamp = |v: isize, n: usize| v.clamp(0, n as isize - 1) as usize;
    (0..width * height)
        .map(|n| {
            let (y, x) = ((n / width) as isize, (n % width) as isize);
            let mut r = [0.0; 9];
            for i in 0..3 {
                for j in 0..3 {
                    let (yy, xx) = (clamp(y + i - 1, height), clamp(x + j - 1, width));
                    r[(j * 3 + i) as usize] = residual[yy * width + xx];
                }
            }
            (0..9)
                .map(|a| (0..9).map(|b| r[a] * p[a][b] * r[b]).sum::<f64>())
                .sum::<f64>()
                / 3.0
        })
        .collect()
}

/// `FI~` of every coefficient of the plane, in plane order; outside the grid the edge block
/// repeats.
pub(super) fn fisher_information(plane: &DctPlane) -> Vec<f64> {
    let (width, height) = (plane.blocks_wide * 8, plane.blocks_high * 8);
    let residual = wiener_residual(&decompress(plane), width, height);
    let variance = pixel_variances(&residual, width, height);
    let blocks = plane.blocks_wide * plane.blocks_high;
    let mut inverse4 = vec![0.0; blocks * BLOCK];
    for b in 0..blocks {
        let (by, bx) = (b / plane.blocks_wide, b % plane.blocks_wide);
        for mode in 0..BLOCK {
            let mut sum = 0.0;
            for i in 0..8 {
                for j in 0..8 {
                    let d = dct_entry(mode / 8, mode % 8, i, j);
                    sum += d * d * variance[(by * 8 + i) * width + bx * 8 + j];
                }
            }
            inverse4[b * BLOCK + mode] = sum.max(1e-10).powi(-2);
        }
    }
    let weights = [[1.0, 3.0, 1.0], [3.0, 4.0, 3.0], [1.0, 3.0, 1.0]];
    let mut out = vec![0.0; blocks * BLOCK];
    for b in 0..blocks {
        let (by, bx) = (
            (b / plane.blocks_wide) as isize,
            (b % plane.blocks_wide) as isize,
        );
        for mode in 0..BLOCK {
            let mut sum = 0.0;
            for (di, row) in weights.iter().enumerate() {
                for (dj, &w) in row.iter().enumerate() {
                    let y = (by + di as isize - 1).clamp(0, plane.blocks_high as isize - 1);
                    let x = (bx + dj as isize - 1).clamp(0, plane.blocks_wide as isize - 1);
                    sum +=
                        w * inverse4[(y as usize * plane.blocks_wide + x as usize) * BLOCK + mode];
                }
            }
            out[b * BLOCK + mode] = f64::from(plane.quant[mode]).powi(4) * sum / 20.0;
        }
    }
    out
}
