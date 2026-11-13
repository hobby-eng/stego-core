use super::*;
use crate::algorithm::model::BLOCK;

pub(super) fn plane(width: usize, height: usize) -> DctPlane {
    let coefficients = (0..width * height * BLOCK)
        .map(|i| ((i * 31 + i * i % 101) % 37) as i16 - 18)
        .collect();
    DctPlane {
        blocks_wide: width,
        blocks_high: height,
        coefficients,
        quant: [3; BLOCK],
    }
}

/// Deterministic standard normal samples (splitmix64 + Box–Muller).
struct Gaussian(u64);

impl Gaussian {
    fn uniform(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        ((z >> 11) as f64 + 0.5) / (1_u64 << 53) as f64
    }

    fn sample(&mut self) -> f64 {
        let (u1, u2) = (self.uniform(), self.uniform());
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}

/// Laplacian-like coefficients that shrink with frequency, quality-75-like steps.
fn sample_plane(wide: usize, high: usize, seed: u64) -> DctPlane {
    let mut rng = Gaussian(seed);
    let mut quant = [0_u16; BLOCK];
    for (k, q) in quant.iter_mut().enumerate() {
        *q = (8 + 4 * (k / 8 + k % 8)) as u16;
    }
    let coefficients = (0..wide * high * BLOCK)
        .map(|i| {
            let k = i % BLOCK;
            let scale = if k == 0 {
                30.0
            } else {
                6.0 / (1 + k / 8 + k % 8) as f64
            };
            (scale * rng.sample()).round() as i16
        })
        .collect();
    DctPlane {
        blocks_wide: wide,
        blocks_high: high,
        coefficients,
        quant,
    }
}

fn wet_dc(positions: &[usize]) -> Vec<Permitted> {
    positions
        .iter()
        .map(|p| {
            if p % BLOCK == 0 {
                Permitted::None
            } else {
                Permitted::Both
            }
        })
        .collect()
}

fn h3(b: f64) -> f64 {
    if b == 0.0 {
        return 0.0;
    }
    (-2.0 * b * b.ln() - (1.0 - 2.0 * b) * (-2.0 * b).ln_1p()) / std::f64::consts::LN_2
}

#[test]
fn costs_obey_the_permission_and_symmetry_contract() {
    let image = plane(2, 2);
    let positions = [2, 71, 1, 200];
    let permissions = [
        Permitted::Both,
        Permitted::None,
        Permitted::Both,
        Permitted::Both,
    ];
    let (beta, lambda) = change_probabilities(&image, &positions, &permissions, 1.2).unwrap();
    let costs = JMiPod.costs(&image, &positions, &permissions, 1.2).unwrap();
    assert!(lambda > 0.0 && lambda.is_finite());
    assert_eq!(beta[1], 0.0);
    assert!(costs.plus[1].is_infinite());
    assert_eq!(costs.plus, costs.minus);
    for index in [0, 2, 3] {
        assert!(costs.plus[index].is_finite() && costs.plus[index] > 0.0);
        let recovered = 1.0 / (costs.plus[index].exp() + 2.0);
        assert!((recovered / beta[index] - 1.0).abs() < 1e-12);
    }
}

#[test]
fn malformed_planes_positions_and_policies_are_refused() {
    let image = plane(1, 1);
    let call = |p: &[usize], flags: &[Permitted]| change_probabilities(&image, p, flags, 0.1);
    assert_eq!(call(&[1], &[]).unwrap_err(), CostError::Permission);
    assert_eq!(
        call(&[64], &[Permitted::Both]).unwrap_err(),
        CostError::Permission
    );
    assert_eq!(
        call(&[2, 1, 2], &[Permitted::Both; 3]).unwrap_err(),
        CostError::Permission
    );
    for flag in [Permitted::Plus, Permitted::Minus] {
        assert_eq!(call(&[1], &[flag]).unwrap_err(), CostError::Unsupported);
    }
    let mut wrong = plane(1, 1);
    wrong.coefficients.pop();
    assert_eq!(
        change_probabilities(&wrong, &[1], &[Permitted::Both], 0.1).unwrap_err(),
        CostError::Shape
    );
    wrong.blocks_wide = usize::MAX;
    assert_eq!(
        change_probabilities(&wrong, &[1], &[Permitted::Both], 0.1).unwrap_err(),
        CostError::Shape
    );
    // blocks fits in usize but blocks · 64 does not: the shared validator alone would wrap.
    let wrapped = DctPlane {
        blocks_wide: usize::MAX / 64 + 1,
        blocks_high: 1,
        coefficients: Vec::new(),
        quant: [3; BLOCK],
    };
    assert_eq!(
        fisher_information(&wrapped, &[]).unwrap_err(),
        CostError::Shape
    );
    wrong = plane(1, 1);
    wrong.quant[0] = 0;
    assert_eq!(
        change_probabilities(&wrong, &[1], &[Permitted::Both], 0.1).unwrap_err(),
        CostError::Quantization
    );
}

#[test]
fn payload_validation_counts_only_both_positions() {
    let image = plane(1, 1);
    for payload in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -1.0,
        3.0f64.log2(),
        2.0,
    ] {
        assert_eq!(
            change_probabilities(
                &image,
                &[1, 2],
                &[Permitted::Both, Permitted::None],
                payload
            )
            .unwrap_err(),
            CostError::Payload
        );
    }
    assert_eq!(
        change_probabilities(&image, &[], &[], 0.0).unwrap_err(),
        CostError::Payload
    );
    assert_eq!(
        change_probabilities(&image, &[1], &[Permitted::None], 0.0).unwrap_err(),
        CostError::Payload
    );
    let (beta, lambda) =
        change_probabilities(&image, &[1, 2], &[Permitted::Both, Permitted::None], 0.0).unwrap();
    assert_eq!(beta, [probability::MIN_BETA, 0.0]);
    assert_eq!(lambda, 0.0);
    let costs = JMiPod
        .costs(&image, &[1, 2], &[Permitted::Both, Permitted::None], 0.0)
        .unwrap();
    assert_eq!(costs.plus, [probability::RHO_MAX, f64::INFINITY]);
    assert_eq!(costs.plus, costs.minus);
}

#[test]
fn tiny_and_exact_payloads_are_carried_to_1e9() {
    let image = sample_plane(12, 9, 9);
    let positions: Vec<usize> = (0..image.coefficients.len()).collect();
    let permitted = wet_dc(&positions);
    let capacity =
        permitted.iter().filter(|p| **p == Permitted::Both).count() as f64 * 3.0f64.log2();
    for bits in [1e-6, 0.5, 1.0, 5.0, 60.0, 900.0, capacity - 2.0] {
        let (beta, _) = change_probabilities(&image, &positions, &permitted, bits).unwrap();
        let total: f64 = beta.iter().map(|&b| h3(b)).sum();
        assert!(
            (total - bits).abs() <= 2e-9 * bits.max(1.0),
            "{bits}: {total}"
        );
    }
    // One permitted coefficient and one bit: β is fixed by H3(β) = 1.
    let (beta, _) = change_probabilities(&image, &[7], &[Permitted::Both], 1.0).unwrap();
    assert!((h3(beta[0]) - 1.0).abs() <= 1e-9);
}

#[test]
fn beta_satisfies_the_stationarity_condition() {
    // β · FI~ = λ · log2(1/β − 2) (eq. 29, corrected) at every modelled position.
    let image = sample_plane(5, 5, 3);
    let positions: Vec<usize> = (0..image.coefficients.len()).collect();
    let permitted = wet_dc(&positions);
    let (beta, lambda) = change_probabilities(&image, &positions, &permitted, 300.0).unwrap();
    let fi = fisher_information(&image, &positions).unwrap();
    for ((&b, &fi), p) in beta.iter().zip(&fi).zip(&permitted) {
        if *p == Permitted::Both && b > 1e-200 {
            let rhs = lambda * (1.0 / b - 2.0).log2();
            assert!(((b * fi - rhs) / rhs).abs() < 1e-9);
        }
    }
}

#[test]
fn fisher_information_matches_whole_image_reference() {
    // (66, 2) crosses the 64-block tile seam.
    for (wide, high, seed) in [
        (5, 4, 11),
        (1, 1, 12),
        (1, 3, 13),
        (4, 1, 14),
        (2, 2, 15),
        (66, 2, 16),
    ] {
        let image = sample_plane(wide, high, seed);
        let positions: Vec<usize> = (0..image.coefficients.len()).collect();
        let got = fisher_information(&image, &positions).unwrap();
        let expected = super::reference::fisher_information(&image);
        for (k, (g, e)) in got.iter().zip(&expected).enumerate() {
            assert!(
                ((g - e) / e).abs() < 1e-8,
                "{wide}×{high} coefficient {k}: {g:e} vs {e:e}"
            );
        }
    }
}

#[test]
fn flat_planes_hit_the_variance_floor() {
    // All zeros: every variance is 0, so FI = Δ⁴ / (1e-10)² everywhere.
    let mut image = sample_plane(4, 3, 31);
    image.coefficients.fill(0);
    let all: Vec<usize> = (0..image.coefficients.len()).collect();
    for (p, fi) in fisher_information(&image, &all).unwrap().iter().enumerate() {
        let expected = f64::from(image.quant[p % BLOCK]).powi(4) * 1e20;
        assert!(
            ((fi - expected) / expected).abs() < 1e-15,
            "position {p}: {fi:e}"
        );
    }
    let costs = JMiPod
        .costs(&image, &all, &vec![Permitted::Both; all.len()], 100.0)
        .unwrap();
    assert!(costs.plus.iter().all(|c| c.is_finite() && *c >= 0.0));
    // A plane whose high-frequency variances sit between 1e-10 and 1e-5: a wrong floor shows.
    let mut quiet = sample_plane(3, 3, 32);
    quiet.quant = [1; BLOCK];
    for (i, c) in quiet.coefficients.iter_mut().enumerate() {
        *c = if i % BLOCK == 0 { 50 } else { 0 };
    }
    quiet.coefficients[4 * BLOCK + 9] = 1;
    let all: Vec<usize> = (0..quiet.coefficients.len()).collect();
    let got = fisher_information(&quiet, &all).unwrap();
    let expected = super::reference::fisher_information(&quiet);
    assert!(expected.iter().any(|&e| e > 1e10 && e < 1e20));
    for (g, e) in got.iter().zip(&expected) {
        assert!(((g - e) / e).abs() < 1e-8);
    }
}

#[test]
fn position_order_and_tile_boundaries_preserve_the_model() {
    let image = sample_plane(70, 3, 10);
    let sorted: Vec<usize> = (0..image.coefficients.len())
        .filter(|i| i % 7 == 3)
        .collect();
    let mut rng = Gaussian(11);
    let mut keyed = sorted.clone();
    for i in (1..keyed.len()).rev() {
        let j = (rng.uniform() * (i + 1) as f64) as usize;
        keyed.swap(i, j);
    }
    let flags = vec![Permitted::Both; sorted.len()];
    let (forward, a) = change_probabilities(&image, &sorted, &flags, 500.0).unwrap();
    let (shuffled, b) = change_probabilities(&image, &keyed, &flags, 500.0).unwrap();
    assert_eq!(a.to_bits(), b.to_bits());
    for (i, &p) in keyed.iter().enumerate() {
        let k = sorted.binary_search(&p).unwrap();
        assert_eq!(shuffled[i].to_bits(), forward[k].to_bits());
    }
    let repeated = change_probabilities(&image, &sorted, &flags, 500.0).unwrap();
    assert!(
        forward
            .iter()
            .zip(&repeated.0)
            .all(|(x, y)| x.to_bits() == y.to_bits())
    );
}

#[test]
fn subsets_get_the_same_information_as_the_full_plane() {
    let image = sample_plane(9, 8, 21);
    let all: Vec<usize> = (0..image.coefficients.len()).collect();
    let full = fisher_information(&image, &all).unwrap();
    let subset: Vec<usize> = (0..300)
        .map(|i| (i * 7_919 + 13) % image.coefficients.len())
        .collect();
    let part = fisher_information(&image, &subset).unwrap();
    for (&p, value) in subset.iter().zip(&part) {
        assert_eq!(value.to_bits(), full[p].to_bits(), "position {p}");
    }
}
