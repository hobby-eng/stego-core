//! Slow whole-image J-CRF statistics for tests, straight from the formulas and independent of
//! the tiled code: textbook inverse DCT, Matlab-style Wiener statistics, the 25×25 projector
//! `P⊥ = I − G(GᵀG)⁻¹Gᵀ` by Gauss–Jordan inversion, Pearson correlation in two passes, and
//! S-UNIWARD costs by brute-force 2-D sums.

use std::f64::consts::{FRAC_1_SQRT_2, PI};

use crate::algorithm::model::{BLOCK, DctPlane};

const P: usize = 5;

fn dct_entry(u: usize, v: usize, i: usize, j: usize) -> f64 {
    let c = |k: usize| if k == 0 { FRAC_1_SQRT_2 } else { 1.0 };
    0.25 * c(u)
        * c(v)
        * ((2 * i + 1) as f64 * u as f64 * PI / 16.0).cos()
        * ((2 * j + 1) as f64 * v as f64 * PI / 16.0).cos()
}

/// Decompressed image centred on zero, row-major.
pub(super) fn decompress(plane: &DctPlane) -> Vec<f64> {
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
            let w = [at(y, x), at(y, x + 1), at(y + 1, x), at(y + 1, x + 1)];
            let mean = w.iter().sum::<f64>() / 4.0;
            (
                mean,
                w.iter().map(|v| v * v).sum::<f64>() / 4.0 - mean * mean,
            )
        })
        .collect();
    let noise = stats.iter().map(|s| s.1).sum::<f64>() / (width * height) as f64;
    stats
        .iter()
        .zip(image)
        .map(|(&(mean, variance), &x)| {
            let gain = if variance.max(noise) > 0.0 {
                (variance - noise).max(0.0) / variance.max(noise)
            } else {
                0.0
            };
            x - (mean + gain * (x - mean))
        })
        .collect()
}

/// `P⊥` for the 5×5 window and the six cosines `a + b ≤ 2`.
pub(super) fn projector() -> Vec<Vec<f64>> {
    let n = P * P;
    let mut g: Vec<Vec<f64>> = Vec::new();
    for total in 0..3 {
        for a in 0..=total {
            let b = total - a;
            g.push(
                (0..n)
                    .map(|k| {
                        let (i, j) = (k / P, k % P);
                        (a as f64 * PI * (2 * i + 1) as f64 / 10.0).cos()
                            * (b as f64 * PI * (2 * j + 1) as f64 / 10.0).cos()
                    })
                    .collect(),
            );
        }
    }
    let q = g.len();
    let mut gram: Vec<Vec<f64>> = (0..q)
        .map(|r| {
            (0..q)
                .map(|c| (0..n).map(|k| g[r][k] * g[c][k]).sum())
                .collect()
        })
        .collect();
    let mut inverse: Vec<Vec<f64>> = (0..q)
        .map(|r| (0..q).map(|c| if r == c { 1.0 } else { 0.0 }).collect())
        .collect();
    for col in 0..q {
        let pivot = gram[col][col];
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
    (0..n)
        .map(|r| {
            (0..n)
                .map(|c| {
                    let hat: f64 = (0..q)
                        .flat_map(|a| (0..q).map(move |b| (a, b)))
                        .map(|(a, b)| g[a][r] * inverse[a][b] * g[b][c])
                        .sum();
                    if r == c { 1.0 - hat } else { -hat }
                })
                .collect()
        })
        .collect()
}

fn reflect(c: isize, len: usize) -> usize {
    let period = 2 * len as isize;
    let v = c.rem_euclid(period);
    if v < len as isize {
        v as usize
    } else {
        (period - 1 - v) as usize
    }
}

/// Per pixel `(ζ², ξ)`: `rᵀP⊥r/19` and `(P⊥r)` at the window centre.
pub(super) fn pixel_fits(plane: &DctPlane) -> Vec<(f64, f64)> {
    let (width, height) = (plane.blocks_wide * 8, plane.blocks_high * 8);
    let residual = wiener_residual(&decompress(plane), width, height);
    let p = projector();
    (0..width * height)
        .map(|n| {
            let (y, x) = ((n / width) as isize, (n % width) as isize);
            let r: Vec<f64> = (0..P * P)
                .map(|k| {
                    let yy = reflect(y + (k / P) as isize - 2, height);
                    let xx = reflect(x + (k % P) as isize - 2, width);
                    residual[yy * width + xx]
                })
                .collect();
            let pr: Vec<f64> = (0..P * P)
                .map(|a| (0..P * P).map(|b| p[a][b] * r[b]).sum())
                .collect();
            let quadratic: f64 = r.iter().zip(&pr).map(|(a, b)| a * b).sum();
            (quadratic / 19.0, pr[P * P / 2])
        })
        .collect()
}

/// Variance in quantization steps of every coefficient, floored at 1e-10.
pub(super) fn variances(plane: &DctPlane) -> Vec<f64> {
    let width = plane.blocks_wide * 8;
    let fits = pixel_fits(plane);
    let mut out = vec![0.0; plane.coefficients.len()];
    for (b, chunk) in out.chunks_mut(BLOCK).enumerate() {
        let (by, bx) = (b / plane.blocks_wide, b % plane.blocks_wide);
        for (mode, value) in chunk.iter_mut().enumerate() {
            let mut sum = 0.0;
            for i in 0..8 {
                for j in 0..8 {
                    let d = dct_entry(mode / 8, mode % 8, i, j);
                    sum += d * d * fits[(by * 8 + i) * width + bx * 8 + j].0;
                }
            }
            let step = f64::from(plane.quant[mode]);
            *value = (sum / (step * step)).max(1e-10);
        }
    }
    out
}

/// Block noise vectors, row-major per block.
pub(super) fn block_noise(plane: &DctPlane) -> Vec<[f64; BLOCK]> {
    let width = plane.blocks_wide * 8;
    let fits = pixel_fits(plane);
    (0..plane.blocks_wide * plane.blocks_high)
        .map(|b| {
            let (by, bx) = (b / plane.blocks_wide, b % plane.blocks_wide);
            std::array::from_fn(|k| fits[(by * 8 + k / 8) * width + bx * 8 + k % 8].1)
        })
        .collect()
}

/// S-UNIWARD (σ = 1, Daubechies-8, symmetric reflection) costs summed per block, brute force:
/// `W(y) = Σ_s K(s) Z(y − s)` over every residual a pixel touches, cost `Σ |K| / (1 + |W|)`.
pub(super) fn block_weights(plane: &DctPlane, low: &[f64; 16]) -> Vec<f64> {
    let (width, height) = (plane.blocks_wide * 8, plane.blocks_high * 8);
    let image = decompress(plane);
    let high: [f64; 16] =
        std::array::from_fn(|i| low[15 - i] * if i % 2 == 0 { -1.0 } else { 1.0 });
    let px = |y: isize, x: isize| image[reflect(y, height) * width + reflect(x, width)];
    let mut cost = vec![0.0; width * height];
    for (fv, fh) in [(low, &high), (&high, low), (&high, &high)] {
        // Residual positions y = 0..height+15 cover every W a pixel 0..height touches (y = p + s).
        let (wx, wy) = (width + 15, height + 15);
        let mut reciprocal = vec![0.0; wx * wy];
        for y in 0..wy {
            for x in 0..wx {
                let mut sum = 0.0;
                for (s, fs) in fv.iter().enumerate() {
                    for (t, ft) in fh.iter().enumerate() {
                        sum += fs * ft * px(y as isize - s as isize, x as isize - t as isize);
                    }
                }
                reciprocal[y * wx + x] = 1.0 / (1.0 + sum.abs());
            }
        }
        for y in 0..height {
            for x in 0..width {
                let mut sum = 0.0;
                for (s, fs) in fv.iter().enumerate() {
                    for (t, ft) in fh.iter().enumerate() {
                        sum += (fs * ft).abs() * reciprocal[(y + s) * wx + x + t];
                    }
                }
                cost[y * width + x] += sum;
            }
        }
    }
    (0..plane.blocks_wide * plane.blocks_high)
        .map(|b| {
            let (by, bx) = (b / plane.blocks_wide, b % plane.blocks_wide);
            (0..BLOCK)
                .map(|k| cost[(by * 8 + k / 8) * width + bx * 8 + k % 8])
                .sum()
        })
        .collect()
}
