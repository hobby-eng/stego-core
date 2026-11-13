use super::*;
use crate::algorithm::jmipod::tests::plane;
use crate::algorithm::model::Permitted;

#[test]
fn jpeg_dct_is_orthonormal_and_preserves_constant_variance() {
    let dct = Dct::new();
    for u in 0..SIDE {
        for v in 0..SIDE {
            let dot: f64 = dct.basis[u]
                .iter()
                .zip(&dct.basis[v])
                .map(|(a, b)| a * b)
                .sum();
            assert!((dot - if u == v { 1.0 } else { 0.0 }).abs() < 1e-12);
        }
    }
    for value in dct.variance(&[4.0; BLOCK], u64::MAX) {
        assert!((value - 4.0).abs() < 1e-12);
    }
    for value in dct.variance(&[0.0; BLOCK], u64::MAX) {
        assert_eq!(value, 1e-10);
    }
}

#[test]
fn wiener_moments_and_residuals_match_a_hand_computed_example() {
    let image = Raster {
        x: 0,
        y: 0,
        width: 2,
        height: 2,
        full_width: 2,
        full_height: 2,
        values: vec![1.0, 2.0, 3.0, 4.0],
    };
    let expected = [(2.5, 1.25), (1.5, 2.75), (1.75, 3.1875), (1.0, 3.0)];
    for y in 0..2 {
        for x in 0..2 {
            assert_eq!(image.moments(x, y), expected[y * 2 + x]);
        }
    }
    let noise = 2.546875;
    let result = image.residual(noise);
    let expected = [-1.5, 0.5 * noise / 2.75, 1.25 * noise / 3.1875, noise];
    for (actual, expected) in result.values.iter().zip(expected) {
        assert!((actual - expected).abs() < 1e-14);
    }
    assert_eq!(result.mirror(-1, -1), result.at(0, 0));
    assert_eq!(result.mirror(2, 2), result.at(1, 1));
}

fn projection() -> [[f64; 9]; 9] {
    // P_ij = 3*variance(e_i+e_j)/2 - 3*variance(e_i)/2 - 3*variance(e_j)/2.
    let mut result = [[0.0; 9]; 9];
    for i in 0..9 {
        for j in 0..9 {
            let mut a = [0.0; 9];
            let mut b = [0.0; 9];
            a[i] = 1.0;
            b[j] = 1.0;
            let mut both = a;
            both[j] += 1.0;
            result[i][j] =
                1.5 * (projected_variance(&both) - projected_variance(&a) - projected_variance(&b));
        }
    }
    result
}

#[test]
fn the_variance_projection_is_symmetric_idempotent_and_annihilates_the_six_basis_modes() {
    let p = projection();
    let trace: f64 = (0..9).map(|i| p[i][i]).sum();
    assert!((trace - 3.0).abs() < 1e-12);
    for i in 0..9 {
        for j in 0..9 {
            assert!((p[i][j] - p[j][i]).abs() < 1e-12);
            let squared: f64 = (0..9).map(|k| p[i][k] * p[k][j]).sum();
            assert!((squared - p[i][j]).abs() < 1e-12);
        }
    }
    for a in 0..3 {
        for b in 0..3 - a {
            let mut patch = [0.0; 9];
            for y in 0..3 {
                for x in 0..3 {
                    patch[y * 3 + x] = (std::f64::consts::PI * (y as f64 + 0.5) * a as f64 / 3.0)
                        .cos()
                        * (std::f64::consts::PI * (x as f64 + 0.5) * b as f64 / 3.0).cos();
                }
            }
            assert!(projected_variance(&patch) < 1e-28);
        }
    }
    let mut impulse = [0.0; 9];
    impulse[4] = 1.0;
    assert!((projected_variance(&impulse) - 4.0 / 27.0).abs() < 1e-15);
}

#[test]
fn projection_estimates_the_variance_of_synthetic_gaussian_noise() {
    let side = 512;
    let mut state = 0x6a09e667f3bcc909u64;
    let mut uniform = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        ((state >> 11) as f64 + 0.5) / ((1u64 << 53) as f64)
    };
    let mut noise = Vec::with_capacity(side * side);
    while noise.len() < side * side {
        let radius = (-2.0 * uniform().ln()).sqrt() * 2.0;
        let angle = std::f64::consts::TAU * uniform();
        noise.push(radius * angle.cos());
        noise.push(radius * angle.sin());
    }
    let mut total = 0.0;
    for y in 1..side - 1 {
        for x in 1..side - 1 {
            let mut patch = [0.0; 9];
            for dy in 0..3 {
                for dx in 0..3 {
                    patch[dy * 3 + dx] = noise[(y + dy - 1) * side + x + dx - 1];
                }
            }
            total += projected_variance(&patch);
        }
    }
    assert!((total / ((side - 2) * (side - 2)) as f64 / 4.0 - 1.0).abs() < 0.05);
}

#[test]
fn smoothing_extends_edge_blocks_symmetrically() {
    let image = plane(3, 3);
    let rect = BlockRect::tile(&image, 0, 0, 3);
    for (x, y, expected) in [(1, 1, 20), (0, 1, 20), (0, 0, 20)] {
        let mut weights = Vec::new();
        rect.neighbors(x, y, |_, _, weight| weights.push(weight));
        assert_eq!(weights.iter().sum::<usize>(), expected);
        let normalized: f64 = weights.iter().map(|&w| w as f64 / expected as f64).sum();
        assert!((normalized - 1.0).abs() < 1e-15);
    }
}

#[test]
fn global_wiener_noise_includes_unselected_blocks_and_zero_padded_borders() {
    let mut image = plane(1, 1);
    image.coefficients.fill(0);
    assert_eq!(global_noise(&image, &Dct::new()), 0.0);
    image.quant[0] = 1;
    image.coefficients[0] = 1024; // Every centered pixel is 128: the hand result is 944.
    // The DC inverse uses 1/sqrt(8), so allow its floating-point roundoff.
    assert!((global_noise(&image, &Dct::new()) - 944.0).abs() < 1e-12);
    image = plane(4, 1);
    let before = global_noise(&image, &Dct::new());
    image.coefficients[3 * BLOCK] += 1000;
    assert_ne!(before, global_noise(&image, &Dct::new()));
}

#[test]
fn changing_tile_partition_preserves_fisher_information() {
    let image = plane(7, 5);
    let positions: Vec<_> = (0..image.coefficients.len()).step_by(37).rev().collect();
    let flags = vec![Permitted::Both; positions.len()];
    let selection = Selection::new(&image, &positions, &flags).unwrap();
    let dct = Dct::new();
    let noise = global_noise(&image, &dct);
    let small = selected_information(&image, &selection, &dct, noise, 1);
    let large = selected_information(&image, &selection, &dct, noise, 7);
    assert_eq!(
        small.iter().map(|x| x.to_bits()).collect::<Vec<_>>(),
        large.iter().map(|x| x.to_bits()).collect::<Vec<_>>()
    );
}

#[test]
fn a_sparse_selection_matches_the_same_positions_in_a_full_selection() {
    let image = plane(7, 5);
    let sparse: Vec<_> = (0..image.coefficients.len()).step_by(37).rev().collect();
    let full: Vec<_> = (0..image.coefficients.len()).collect();
    let sparse_flags: Vec<_> = sparse
        .iter()
        .map(|p| {
            if p % BLOCK == 0 {
                Permitted::None
            } else {
                Permitted::Both
            }
        })
        .collect();
    let full_flags: Vec<_> = full
        .iter()
        .map(|p| {
            if p % BLOCK == 0 {
                Permitted::None
            } else {
                Permitted::Both
            }
        })
        .collect();
    let sparse_selection = Selection::new(&image, &sparse, &sparse_flags).unwrap();
    let full_selection = Selection::new(&image, &full, &full_flags).unwrap();
    let sparse_fi = fisher_information(&image, &sparse_selection);
    let full_fi = fisher_information(&image, &full_selection);
    for (i, &position) in sparse.iter().enumerate() {
        assert_eq!(sparse_fi[i].to_bits(), full_fi[position].to_bits());
    }
}

#[test]
fn the_default_tile_seam_preserves_selected_coefficients() {
    let image = plane(66, 2);
    let positions = [
        63 * BLOCK + 7,
        64 * BLOCK + 8,
        65 * BLOCK + 63,
        129 * BLOCK + 9,
    ];
    let selection = Selection::new(&image, &positions, &[Permitted::Both; 4]).unwrap();
    let dct = Dct::new();
    let noise = global_noise(&image, &dct);
    let tiled = selected_information(&image, &selection, &dct, noise, TILE_BLOCKS);
    let single = selected_information(&image, &selection, &dct, noise, 66);
    assert_eq!(tiled, single);
}

#[test]
fn fisher_information_matches_an_independent_public_synthetic_oracle() {
    // conseal 2026.11 public compute_cost on plane(3,2), divided by its common
    // kernel scale 20. No implementation source was consulted. See the report.
    let expected = [
        (1, 0.0005037637269985452),
        (2, 0.0006132060545658714),
        (7, 0.0008504339616864385),
        (63, 0.0011114873428105143),
        (64, 0.0003780473023602873),
        (71, 0.0004269984129182401),
        (127, 0.000522171912377906),
        (128, 0.0002508402308964117),
        (191, 0.00017699627093834087),
        (200, 0.0006289532746996055),
        (255, 0.0005944879102728869),
        (383, 0.0001692262676991655),
    ];
    let image = plane(3, 2);
    let positions: Vec<_> = expected.iter().map(|&(p, _)| p).collect();
    let selection = Selection::new(&image, &positions, &[Permitted::Both; 12]).unwrap();
    let actual = fisher_information(&image, &selection);
    for (&value, &(_, reference)) in actual.iter().zip(&expected) {
        assert!((value / reference - 1.0).abs() < 1e-11);
    }
    let rect = BlockRect::tile(&image, 0, 0, 3);
    let mut corner = [0usize; 4];
    rect.neighbors(0, 0, |x, y, w| {
        corner[y * 2 + x] += w;
    });
    assert_eq!(corner, [11, 4, 4, 1]);
}
