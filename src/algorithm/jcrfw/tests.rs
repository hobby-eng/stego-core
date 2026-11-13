use super::*;
use crate::algorithm::model::BLOCK;

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

/// Coefficients that shrink with frequency; quality-75-like steps; a few textured blocks.
fn sample_plane(wide: usize, high: usize, seed: u64) -> DctPlane {
    let mut rng = Gaussian(seed);
    let mut quant = [0_u16; BLOCK];
    for (k, q) in quant.iter_mut().enumerate() {
        *q = (8 + 4 * (k / 8 + k % 8)) as u16;
    }
    let coefficients = (0..wide * high * BLOCK)
        .map(|i| {
            let k = i % BLOCK;
            let texture = if (i / BLOCK).is_multiple_of(3) {
                3.0
            } else {
                1.0
            };
            let scale = if k == 0 {
                30.0
            } else {
                texture * 6.0 / (1 + k / 8 + k % 8) as f64
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

fn all(plane: &DctPlane) -> (Vec<usize>, Vec<Permitted>) {
    let positions: Vec<usize> = (0..plane.coefficients.len()).collect();
    let permitted = positions
        .iter()
        .map(|p| {
            if p % BLOCK == 0 {
                Permitted::None
            } else {
                Permitted::Both
            }
        })
        .collect();
    (positions, permitted)
}

fn h3(b: f64) -> f64 {
    if b == 0.0 {
        return 0.0;
    }
    (-2.0 * b * b.ln() - (1.0 - 2.0 * b) * (-2.0 * b).ln_1p()) / std::f64::consts::LN_2
}

#[test]
fn window_fit_equals_the_projector_of_the_paper() {
    let p = reference::projector();
    let mut rng = Gaussian(5);
    for _ in 0..100 {
        let mut window = [[0.0; 5]; 5];
        for row in &mut window {
            for v in row.iter_mut() {
                *v = 3.0 * rng.sample();
            }
        }
        let r: Vec<f64> = window.iter().flatten().copied().collect();
        let pr: Vec<f64> = (0..25)
            .map(|a| (0..25).map(|b| p[a][b] * r[b]).sum())
            .collect();
        let variance = r.iter().zip(&pr).map(|(a, b)| a * b).sum::<f64>() / 19.0;
        let (got_variance, got_noise) = statistics::basis_fit(&window);
        assert!((got_variance - variance).abs() < 1e-10 * variance.max(1.0));
        assert!((got_noise - pr[12]).abs() < 1e-10);
    }
}

#[test]
fn window_variance_is_unbiased_on_gaussian_noise() {
    let mut rng = Gaussian(42);
    let mut total = 0.0;
    for _ in 0..20_000 {
        let mut window = [[0.0; 5]; 5];
        for row in &mut window {
            for v in row.iter_mut() {
                *v = 2.0 * rng.sample();
            }
        }
        total += statistics::basis_fit(&window).0;
    }
    assert!((total / 20_000.0 / 4.0 - 1.0).abs() < 0.02);
}

#[test]
fn correlation_is_pearson_with_bounds() {
    let mut a = [0.0; BLOCK];
    let mut rng = Gaussian(9);
    for v in &mut a {
        *v = rng.sample();
    }
    let negated = a.map(|v| -v);
    assert_eq!(
        statistics::correlation(&a, &a),
        statistics::CORRELATION_LIMIT
    );
    assert_eq!(
        statistics::correlation(&a, &negated),
        -statistics::CORRELATION_LIMIT
    );
    assert_eq!(statistics::correlation(&a, &[1.0; BLOCK]), 0.0);
    let shifted = a.map(|v| 2.0 * v + 7.0 + rng.sample());
    let rho = statistics::correlation(&a, &shifted);
    assert!(rho > 0.8 && rho < 0.99);
}

#[test]
fn model_matches_the_whole_image_reference() {
    for (wide, high, seed) in [(5, 4, 1), (1, 1, 2), (1, 3, 3), (3, 1, 4), (66, 2, 5)] {
        let plane = sample_plane(wide, high, seed);
        let (positions, _) = all(&plane);
        let both = vec![Permitted::Both; positions.len()];
        let selection = Selection::new(&plane, &positions, &both).unwrap();
        let model = statistics::model(&plane, &selection);
        let expected = reference::variances(&plane);
        for (k, (g, e)) in model.variance.iter().zip(&expected).enumerate() {
            assert!(
                ((g - e) / e).abs() < 1e-8,
                "{wide}×{high} coefficient {k}: {g:e} vs {e:e}"
            );
        }
        let noise = reference::block_noise(&plane);
        for by in 0..high {
            for bx in 0..wide {
                let b = by * wide + bx;
                if bx + 1 < wide {
                    let rho = statistics::correlation(&noise[b], &noise[b + 1]);
                    assert!((model.right[b] - rho).abs() < 1e-9, "right {b}");
                }
                if by + 1 < high {
                    let rho = statistics::correlation(&noise[b], &noise[b + wide]);
                    assert!((model.down[b] - rho).abs() < 1e-9, "down {b}");
                }
            }
        }
    }
}

#[test]
fn s_uniward_block_weights_match_brute_force() {
    let low: [f64; 16] = [
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
    for (wide, high, seed) in [(3, 2, 7), (1, 1, 8)] {
        let plane = sample_plane(wide, high, seed);
        let got = weights::block_weights(&plane, &vec![true; wide * high]);
        let expected = reference::block_weights(&plane, &low);
        for (g, e) in got.iter().zip(&expected) {
            assert!(((g - e) / e).abs() < 1e-9, "{g} vs {e}");
        }
    }
    // A flat plane has zero residuals: every pixel costs Σ_k (Σ|f|)², the maximum.
    let mut flat = sample_plane(2, 2, 9);
    flat.coefficients.fill(0);
    let weights = weights::block_weights(&flat, &[true; 4]);
    let textured = weights::block_weights(&sample_plane(2, 2, 9), &[true; 4]);
    assert!(weights.iter().zip(&textured).all(|(f, t)| f > t));
}

#[test]
fn heavy_modes_follow_the_paper_at_75_and_95() {
    let table = |quality: u32| -> [u16; BLOCK] {
        let ijg: [u16; BLOCK] = [
            16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57,
            69, 56, 14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55,
            64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100,
            103, 99,
        ];
        let scale = if quality < 50 {
            5000 / quality
        } else {
            200 - 2 * quality
        };
        ijg.map(|t| ((u32::from(t) * scale + 50) / 100).clamp(1, 255) as u16)
    };
    for quality in [60, 75, 90, 95, 98, 100] {
        assert_eq!(weights::ijg_quality(&table(quality)), quality);
    }
    assert_eq!(weights::heavy_modes(&table(75)), 16);
    assert_eq!(weights::heavy_modes(&table(95)), 3);
    assert_eq!(weights::heavy_modes(&table(100)), 0);
    let w = weights::mode_weights(3);
    assert_eq!(w.iter().filter(|&&v| v == weights::HEAVY).count(), 3);
    assert!(w[63] == weights::HEAVY && w[62] == weights::HEAVY && w[55] == weights::HEAVY);
}

#[test]
fn solution_carries_the_payload_and_satisfies_the_coupled_condition() {
    let plane = sample_plane(9, 7, 21);
    let (positions, permitted) = all(&plane);
    for crf in [JCrfw::unweighted(), JCrfw::default()] {
        for bits in [20.0, 400.0, 3000.0] {
            let solution = crf
                .change_probabilities(&plane, &positions, &permitted, bits)
                .unwrap();
            let (beta, lambda, iterations) = (&solution.beta, solution.lambda, solution.iterations);
            assert!((2..MAX_ITERATIONS).contains(&iterations), "{iterations}");
            assert!(solution.converged);
            assert!((solution.entropy_bits - bits).abs() <= 2e-9 * bits);
            let total: f64 = beta.iter().map(|&b| h3(b)).sum();
            assert!((total - bits).abs() <= 2e-9 * bits, "{bits}: {total}");
            // Recompute FI from the final β and check β·FI = λ log2(1/β − 2).
            let selection = Selection::new(&plane, &positions, &permitted).unwrap();
            let coupling = Coupling::new(&crf, &plane, &positions, &selection);
            for (i, &b) in beta.iter().enumerate() {
                if permitted[i] != Permitted::Both || b < 1e-6 {
                    continue;
                }
                let fi = coupling.ln_information(i, beta, false).exp();
                let rhs = lambda * (1.0 / b - 2.0).log2();
                assert!(((b * fi - rhs) / rhs).abs() < 1e-5, "position {i}");
            }
        }
    }
}

#[test]
fn contract_order_subsets_and_costs() {
    let plane = sample_plane(70, 2, 31);
    let (positions, permitted) = all(&plane);
    let crf = JCrfw::default();
    // Permutation gives the same bits.
    let mut keyed: Vec<usize> = positions.clone();
    let mut rng = Gaussian(3);
    for i in (1..keyed.len()).rev() {
        keyed.swap(i, (rng.uniform() * (i + 1) as f64) as usize);
    }
    let keyed_permitted: Vec<Permitted> = keyed.iter().map(|&p| permitted[p]).collect();
    let first = crf
        .change_probabilities(&plane, &positions, &permitted, 5000.0)
        .unwrap();
    let second = crf
        .change_probabilities(&plane, &keyed, &keyed_permitted, 5000.0)
        .unwrap();
    let (sorted, shuffled) = (&first.beta, &second.beta);
    assert_eq!(first.lambda.to_bits(), second.lambda.to_bits());
    assert_eq!(first.energy.to_bits(), second.energy.to_bits());
    assert_eq!(first.entropy_bits.to_bits(), second.entropy_bits.to_bits());
    for (i, &p) in keyed.iter().enumerate() {
        assert_eq!(shuffled[i].to_bits(), sorted[p].to_bits());
    }
    // Costs: infinite where wet, ln(1/β − 2) elsewhere, symmetric.
    let costs = crf.costs(&plane, &positions, &permitted, 5000.0).unwrap();
    assert_eq!(costs.plus, costs.minus);
    assert_eq!(costs.plus, first.rho);
    for ((&c, &b), p) in costs.plus.iter().zip(sorted).zip(&permitted) {
        if *p == Permitted::None {
            assert!(c.is_infinite() && b == 0.0);
        } else {
            assert!(c.is_finite() && (b - 1.0 / (2.0 + c.exp())).abs() <= 1e-15);
        }
    }
    // A sparse subset gets the statistics of the full plane bit for bit.
    let subset: Vec<usize> = (0..400)
        .map(|i| (i * 7_919 + 13) % positions.len())
        .collect();
    let both = vec![Permitted::Both; subset.len()];
    let full = vec![Permitted::Both; positions.len()];
    let sparse = statistics::model(&plane, &Selection::new(&plane, &subset, &both).unwrap());
    let dense = statistics::model(&plane, &Selection::new(&plane, &positions, &full).unwrap());
    for (i, &p) in subset.iter().enumerate() {
        assert_eq!(sparse.variance[i].to_bits(), dense.variance[p].to_bits());
    }
    // Errors and the zero payload follow J-MiPOD.
    let mut one_way = permitted.clone();
    one_way[5] = Permitted::Plus;
    assert_eq!(
        crf.costs(&plane, &positions, &one_way, 10.0).err(),
        Some(CostError::Unsupported)
    );
    assert_eq!(
        crf.costs(&plane, &positions, &permitted, -1.0).err(),
        Some(CostError::Payload)
    );
    let zero = crf
        .change_probabilities(&plane, &positions, &permitted, 0.0)
        .unwrap();
    assert_eq!(zero.lambda, 0.0);
    assert!(
        zero.beta
            .iter()
            .zip(&permitted)
            .all(|(&b, p)| (*p == Permitted::Both) == (b > 0.0))
    );
}

#[test]
fn effective_information_follows_the_paper_formula() {
    // FI_i = w_u [w_b/σ⁴ + Σ_j w_ij/(σ⁴(1−ϱ²)²) + Σ_j w_ij ϱ²/(σ²σ_j²(1−ϱ²)²) · β_j/β_i],
    // written out directly from the model, the weights and a β vector.
    let plane = sample_plane(6, 5, 41);
    let (positions, permitted) = all(&plane);
    let crf = JCrfw::default();
    let beta = crf
        .change_probabilities(&plane, &positions, &permitted, 2000.0)
        .unwrap()
        .beta;
    let selection = Selection::new(&plane, &positions, &permitted).unwrap();
    let coupling = Coupling::new(&crf, &plane, &positions, &selection);
    let model = statistics::model(&plane, &selection);
    let block_weight = weights::block_weights(&plane, &[true; 30]);
    let mode_weight = weights::mode_weights(weights::heavy_modes(&plane.quant));
    let wide = plane.blocks_wide;
    for (i, &p) in positions.iter().enumerate() {
        if permitted[i] != Permitted::Both {
            continue;
        }
        let (block, mode) = (p / BLOCK, p % BLOCK);
        let sigma2 = model.variance[i];
        let mut fi = block_weight[block] / (sigma2 * sigma2);
        for (nx, ny) in statistics::cross(block % wide, block / wide, &plane)
            .into_iter()
            .flatten()
        {
            let other = ny * wide + nx;
            let (low, high) = (block.min(other), block.max(other));
            let rho = if high == low + 1 {
                model.right[low]
            } else {
                model.down[low]
            };
            let damp = (1.0 - rho * rho).powi(2);
            let w = 0.5 * (block_weight[block] + block_weight[other]);
            fi += w / (sigma2 * sigma2 * damp);
            let j = other * BLOCK + mode;
            if permitted[j] == Permitted::Both {
                fi += w * rho * rho / (sigma2 * model.variance[j] * damp) * beta[j] / beta[i];
            }
        }
        fi *= mode_weight[mode];
        let got = coupling.ln_information(i, &beta, false).exp();
        assert!(
            ((got - fi) / fi).abs() < 1e-12,
            "position {p}: {got:e} vs {fi:e}"
        );
    }
}

#[test]
fn s_uniward_matches_conseal_golden_costs() {
    // conseal 2026.11 `suniward.compute_cost_adjusted` (σ = 1) on a 40×36 integer image in
    // 2..252 (no wet adjustment), run once as an external oracle; values copied here.
    let (h, w) = (40usize, 36usize);
    let image = |y: usize, x: usize| (2 + (7 * y * y + 13 * x * y + 29 * x + 3 * y) % 251) as f64;
    let reflect = |c: isize, n: usize| {
        let period = 2 * n as isize;
        let v = c.rem_euclid(period);
        if v < n as isize {
            v as usize
        } else {
            (period - 1 - v) as usize
        }
    };
    let halo = weights::HALO;
    let (columns, rows) = (w + 2 * halo, h + 2 * halo);
    let mut window = vec![0.0; columns * rows];
    for r in 0..rows {
        for c in 0..columns {
            window[r * columns + c] = image(
                reflect(r as isize - halo as isize, h),
                reflect(c as isize - halo as isize, w),
            );
        }
    }
    let cost = weights::window_costs(&window, columns, rows);
    let golden = [
        (0, 0, 0.9303344880837328),
        (0, 35, 0.6159422469064788),
        (39, 0, 1.3020905309834507),
        (39, 35, 1.5475590094414975),
        (1, 17, 0.9265457666805759),
        (5, 5, 0.5974107280647054),
        (12, 30, 0.7832051672361278),
        (20, 18, 0.7886629169177521),
        (27, 3, 0.614459566348893),
        (33, 22, 0.6487565867382524),
        (38, 11, 0.8055095156653691),
        (16, 34, 0.7597154495302962),
    ];
    // conseal's filter constants carry about ten digits; mirrored filters miss by about 0.4.
    for (y, x, expected) in golden {
        let got = cost[y * w + x];
        assert!(
            ((got - expected) / expected).abs() < 1e-8,
            "({y}, {x}): {got} vs {expected}"
        );
    }
    let total: f64 = cost.iter().sum();
    assert!((total / 1166.1652890418688 - 1.0).abs() < 1e-8);
}

/// The plane of `tests/reference/jcrfw_reference.py`.
fn oracle_plane() -> DctPlane {
    DctPlane {
        blocks_wide: 3,
        blocks_high: 2,
        coefficients: (0..384)
            .map(|i| ((i * 17 + i / 64) % 31) as i16 - 15)
            .collect(),
        quant: [2; BLOCK],
    }
}

/// Positions of the oracle: blocks 0, 1, 2, 4, 5 and modes 1, 5 and 55 (heavy at quality 95).
const ORACLE_POSITIONS: [usize; 8] = [1, 65, 129, 257, 321, 55, 119, 5];

fn relative(a: f64, b: f64) -> f64 {
    ((a - b) / b).abs()
}

#[test]
fn statistics_and_weights_match_the_dense_python_oracle() {
    // `tests/reference/jcrfw_reference.py`: dense 25×25 projector, Wiener filter written
    // out, S-UNIWARD as full convolutions checked against conseal's golden values (2e-9).
    let plane = oracle_plane();
    let permitted = [Permitted::Both; 8];
    let selection = Selection::new(&plane, &ORACLE_POSITIONS, &permitted).unwrap();
    let dct = crate::algorithm::jmipod::sampling::Dct::new();
    let noise = crate::algorithm::jmipod::statistics::global_noise(&plane, &dct);
    assert!(relative(noise, 239.644_372_092_732_2) < 1e-13);
    let model = statistics::model(&plane, &selection);
    let variance = [
        21.218_682_113_718_78,
        23.301_799_030_945_36,
        25.932_679_000_546_138,
        28.840_087_946_332_4,
        27.735_614_174_456_675,
        25.984_638_996_129_064,
        22.252_376_232_941_213,
        22.936_063_315_718_947,
    ];
    for (got, expected) in model.variance.iter().zip(variance) {
        assert!(relative(*got, expected) < 1e-12, "{got} vs {expected}");
    }
    let correlation = [
        (model.right[0], 0.128_889_797_568_106_53),
        (model.down[0], -0.113_026_989_898_469_31),
        (model.right[1], 0.022_615_049_925_120_884),
        (model.down[1], -0.182_180_506_292_747),
        (model.down[2], -0.155_570_077_640_632_7),
        (model.right[3], 0.053_386_692_326_128_124),
        (model.right[4], -0.005_369_351_078_482_657_5),
    ];
    for (got, expected) in correlation {
        assert!((got - expected).abs() < 1e-12, "{got} vs {expected}");
    }
    let weight = [
        131.555_736_177_351_1,
        131.771_597_163_693_49,
        120.544_907_949_845_45,
        128.126_931_892_690_66,
        114.114_141_237_509_97,
        121.862_295_453_504_77,
    ];
    for (got, expected) in weights::block_weights(&plane, &[true; 6])
        .iter()
        .zip(weight)
    {
        assert!(relative(*got, expected) < 1e-12, "{got} vs {expected}");
    }
}

#[test]
fn converged_solution_matches_the_dense_kkt_solve() {
    // The oracle solves the original conditions and the payload together (scipy
    // least_squares), not by frozen ratios; residual below 1e-15.
    let oracle = [
        (
            0.4,
            0.000_254_007_069_549_492_46,
            4.334_772_342_454_081e-5,
            [
                0.002_458_768_897_468_113_3,
                0.002_267_231_609_378_928_6,
                0.003_658_513_689_592_784,
                0.003_517_713_617_591_726,
                0.004_168_476_710_684_423,
                0.000_866_648_752_830_547_5,
                0.000_518_864_746_002_283_5,
                0.002_820_202_217_235_464,
            ],
        ),
        (
            2.4,
            0.003_633_366_206_377_054_6,
            0.003_396_099_178_067_728,
            [
                0.022_075_555_212_131_295,
                0.020_504_318_922_980_526,
                0.031_644_005_763_930_144,
                0.030_538_557_677_528_527,
                0.035_552_802_544_687_5,
                0.008_379_061_702_314_143,
                0.005_159_494_424_604_352,
                0.025_014_620_145_941_406,
            ],
        ),
        (
            8.0,
            0.043_139_483_535_663_93,
            0.102_229_814_576_675_36,
            [
                0.124_782_235_883_636_9,
                0.118_237_130_130_521_38,
                0.160_257_415_427_955_57,
                0.156_462_059_387_249_36,
                0.172_522_143_935_626_48,
                0.057_189_483_462_898_83,
                0.037_402_083_938_678_29,
                0.136_548_260_254_281_5,
            ],
        ),
    ];
    let plane = oracle_plane();
    let permitted = [Permitted::Both; 8];
    for (payload, lambda, energy, beta) in oracle {
        let strict = JCrfw::new(FrequencyProfile::Paper95)
            .with_iterations(400)
            .change_probabilities(&plane, &ORACLE_POSITIONS, &permitted, payload)
            .unwrap();
        let fast = JCrfw::new(FrequencyProfile::Paper95)
            .change_probabilities(&plane, &ORACLE_POSITIONS, &permitted, payload)
            .unwrap();
        let worst = |s: &Solution| {
            s.beta
                .iter()
                .zip(beta)
                .map(|(&got, expected)| relative(got, expected))
                .fold(relative(s.lambda, lambda), f64::max)
                .max(relative(s.energy, energy))
        };
        // The payload tolerance, 1e-9 · max(R, 1) bits, bounds the agreement.
        assert!(worst(&strict) < 2e-9, "{payload}: {:e}", worst(&strict));
        assert!(strict.kkt_max < 1e-12 && strict.converged);
        assert!(worst(&fast) < 1e-8, "{payload}: {:e}", worst(&fast));
        assert!(fast.converged && fast.kkt_max < 1e-8);
        assert!(relative(fast.entropy_bits, payload) < 1e-9);
    }
}

/// Replays `count` updates with exact solves only, independently of the table updates.
fn replay(crf: &JCrfw, plane: &DctPlane, payload: f64, count: usize) -> Vec<f64> {
    let (positions, permitted) = all(plane);
    let (positions, permitted) = (&positions[..], &permitted[..]);
    let selection = Selection::new(plane, positions, permitted).unwrap();
    let coupling = Coupling::new(crf, plane, positions, &selection);
    let mut beta = vec![0.0; positions.len()];
    let mut ln_fi = vec![0.0; positions.len()];
    for update in 0..count {
        coupling.refresh(&beta, update == 0, &mut ln_fi);
        probability::solve(coupling.view(&ln_fi), payload, &mut beta, Output::Beta).unwrap();
    }
    beta
}

fn l1(a: &[f64], b: &[f64]) -> f64 {
    let total: f64 = b.iter().sum();
    a.iter().zip(b).map(|(x, y)| (x - y).abs()).sum::<f64>() / total
}

#[test]
fn fixed_update_counts_are_exact_and_reported() {
    // `with_iterations(n)` runs n updates, the paper's three included: it equals n exact
    // updates replayed here (the table ones differ by 3e-14 of the map) and not n + 1
    // (5e-7 to 4e-3 of the map apart on this plane).
    let plane = sample_plane(9, 7, 23);
    let (positions, permitted) = all(&plane);
    let crf = JCrfw::default();
    for count in 1..=4 {
        let solution = crf
            .with_iterations(count)
            .change_probabilities(&plane, &positions, &permitted, 1500.0)
            .unwrap();
        assert_eq!(solution.iterations, count);
        let same = replay(&crf, &plane, 1500.0, count);
        let next = replay(&crf, &plane, 1500.0, count + 1);
        assert!(l1(&solution.beta, &same) < 1e-11, "{count}");
        assert!(l1(&same, &next) > 1e-7, "{count}");
        // The map still moves by more than 1e-6 of its total in the last of four updates.
        assert!(!solution.converged, "{count}");
    }
    // Until the map settles, and far beyond: the default leaves 4e-9 of the change
    // probability off the optimality condition here, 2000 updates leave 1e-13.
    let strict = crf
        .with_iterations(2000)
        .change_probabilities(&plane, &positions, &permitted, 1500.0)
        .unwrap();
    let fast = crf
        .change_probabilities(&plane, &positions, &permitted, 1500.0)
        .unwrap();
    assert!(strict.converged && strict.kkt_max < 1e-11);
    assert!(fast.converged && fast.kkt_residual < 1e-7 && fast.kkt_max < 1e-5);
    assert!(l1(&fast.beta, &strict.beta) < 1e-7);
}

#[test]
fn costs_beyond_the_floor_solve_the_condition_with_final_neighbours() {
    // Where the payload search keeps β at the floor 1e-300, the cost is solved from
    // `λρ/ln 2 = w_u (A β(ρ) + C)` with the neighbours fixed (a coordinate
    // step). Here each position in turn sits at the floor, as the search leaves it, and λ is
    // lowered until the coupled sum alone asks for a cost `s` of 800 or 10⁴.
    let plane = sample_plane(9, 7, 21);
    let (positions, permitted) = all(&plane);
    let crf = JCrfw::default();
    let mut beta = crf
        .change_probabilities(&plane, &positions, &permitted, 800.0)
        .unwrap()
        .beta;
    let selection = Selection::new(&plane, &positions, &permitted).unwrap();
    let coupling = Coupling::new(&crf, &plane, &positions, &selection);
    let mut checked = 0;
    for (index, &p) in positions.iter().enumerate() {
        let (uncoupled, coupled) = coupling.terms(index, &beta, false);
        if permitted[index] != Permitted::Both || coupled == 0.0 {
            continue;
        }
        let weight = coupling.mode_weight[p % BLOCK];
        let kept = std::mem::replace(&mut beta[index], probability::MIN_BETA);
        for shift in [800.0, 1e4] {
            let ln_lambda = (std::f64::consts::LN_2 * weight * coupled / shift).ln();
            let ln_fi = coupling.ln_information(index, &beta, false);
            let rho = coupling.final_cost(index, ln_fi, &beta, ln_lambda);
            assert!(
                rho.is_finite() && rho >= shift * (1.0 - 1e-12),
                "{index}: {rho}"
            );
            let left = weight * uncoupled.mul_add(probability::beta((-rho).exp()), coupled);
            let right = ln_lambda.exp() * rho / std::f64::consts::LN_2;
            assert!(
                relative(left, right) < 1e-12,
                "{index}: {left:e} vs {right:e}"
            );
            checked += 1;
        }
        beta[index] = kept;
    }
    assert!(checked > 1000, "{checked}");
}

#[test]
fn variance_floor_applies_in_quantization_steps() {
    let plane = DctPlane {
        blocks_wide: 2,
        blocks_high: 2,
        coefficients: vec![0; 4 * BLOCK],
        quant: [10; BLOCK],
    };
    let (positions, permitted) = all(&plane);
    let selection = Selection::new(&plane, &positions, &permitted).unwrap();
    let model = statistics::model(&plane, &selection);
    for (variance, p) in model.variance.iter().zip(&permitted) {
        assert!(*p == Permitted::None || *variance == statistics::VARIANCE_FLOOR);
    }
}
