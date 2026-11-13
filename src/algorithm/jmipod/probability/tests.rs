use super::*;

/// The paper's `f(x) = x / log2(1/x − 2)` (eq. 29, corrected).
fn f(x: f64) -> f64 {
    x / (1.0 / x - 2.0).log2()
}

/// `f⁻¹(y)` through the cost form: `a = ln 2 / y`.
fn f_inverse(y: f64) -> f64 {
    beta(cost(LN_2.ln() - y.ln()).1)
}

/// Ternary entropy in bits from its definition; 0 for an unchanged position.
fn h3(b: f64) -> f64 {
    if b == 0.0 {
        return 0.0;
    }
    (-2.0 * b * b.ln() - (1.0 - 2.0 * b) * (-2.0 * b).ln_1p()) / LN_2
}

/// Solves change probabilities for Fisher informations `fi` (0 = wet).
fn solve_fi(fi: &[f64], payload: f64) -> Result<(Vec<f64>, f64), CostError> {
    let ln_fi: Vec<f64> = fi.iter().map(|v| v.ln()).collect();
    let mut out = vec![0.0; fi.len()];
    let view = View {
        values: &ln_fi,
        order: None,
    };
    let ln_lambda = solve(view, payload, &mut out, Output::Beta)?;
    Ok((out, ln_lambda.exp()))
}

/// A spread of Fisher informations like a real image's: ln FI from −5 to 60.
fn spread(n: usize) -> Vec<f64> {
    (0..n)
        .map(|i| (-5.0 + 65.0 * ((i * 7919) % n) as f64 / n as f64).exp())
        .collect()
}

#[test]
fn floor_constant_matches_its_definition() {
    let exact = (1.0 / MIN_BETA - 2.0).ln();
    assert!((RHO_MAX - exact).abs() <= 2.0 * f64::EPSILON * exact);
    let (rho, e, capped) = cost(1e4);
    assert!(capped && rho == RHO_MAX);
    assert!((beta(e) - MIN_BETA).abs() <= 1e-12 * MIN_BETA);
}

#[test]
fn inverse_of_f_is_exact_to_1e12() {
    // y from 1e-300 to 100; above that f itself is ill-conditioned in β (β → 1/3).
    let mut y = 1e-300_f64;
    while y <= 100.0 {
        let b = f_inverse(y);
        assert!(b > 0.0 && b < 1.0 / 3.0);
        assert!(((f(b) - y) / y).abs() < 1e-12, "y {y:e}");
        y *= 1.37;
    }
    for log_y in [50.0, 500.0, 1000.0] {
        assert!((f_inverse(f64::exp(log_y)) - 1.0 / 3.0).abs() < 1e-15);
    }
}

#[test]
fn cost_solves_its_equation_on_the_whole_range() {
    let mut k = -60.0;
    while k < 800.0 {
        let (rho, e, capped) = cost(k);
        assert!(rho > 0.0 && rho.is_finite() && e > 0.0);
        if !capped {
            let residual = rho.ln() + rho + (2.0 * e).ln_1p() - k;
            assert!(
                residual.abs() <= 1e-13 * (k.abs() + 1.0),
                "k {k}: {residual:e}"
            );
            let (plain, _) = newton(k, Node::at(k).rho);
            assert!(((rho - plain) / plain).abs() <= 1e-14, "k {k}");
        }
        k += 0.173;
    }
}

#[test]
fn table_entropy_is_within_1e9_of_exact() {
    // Points between nodes, where cubic interpolation is worst. Correctness does not rely on
    // this bound (the exact passes check the payload); it only keeps them to one pass.
    let table = table();
    let mut k = SMALL_K - 5.0;
    while k < table.top + 5.0 {
        let (bits, slope) = table.bits(k);
        let exact = if k >= table.top {
            table.floor
        } else {
            Node::at(k)
        };
        assert!(
            ((bits - exact.bits) / exact.bits).abs() <= 1e-9,
            "k {k}: {bits:e} vs {:e}",
            exact.bits
        );
        assert!(
            (slope - exact.bits_slope).abs() <= 1e-4 * exact.bits_slope.abs() + 1e-11,
            "k {k}"
        );
        k += table.width * 0.5 + 0.0371;
    }
}

#[test]
fn entropy_from_cost_matches_definition() {
    for rho in [1e-6_f64, 0.01, 0.3, 1.0, 5.0, 40.0, 300.0] {
        let e = (-rho).exp();
        let b = beta(e);
        assert!(
            (Node::new(rho, e).bits - h3(b)).abs() <= 1e-12 * h3(b),
            "ρ {rho}"
        );
    }
}

#[test]
fn solved_lambda_carries_the_payload_to_1e9_and_beta_grows_with_it() {
    let fi = spread(200_000);
    let mut previous: Option<Vec<f64>> = None;
    for bits in [
        1e-3, 0.5, 1.0, 10.0, 1_000.0, 20_000.0, 150_000.0, 300_000.0,
    ] {
        let (beta, _) = solve_fi(&fi, bits).unwrap();
        let total: f64 = beta.iter().map(|&b| h3(b)).sum();
        // The naive sum here adds about 1e-11 relative on top of the solver's tolerance.
        assert!(
            (total - bits).abs() <= 2e-9 * bits.max(1.0),
            "{bits}: {total}"
        );
        if let Some(before) = previous {
            assert!(before.iter().zip(&beta).all(|(a, b)| b >= a));
        }
        previous = Some(beta);
    }
}

#[test]
fn solved_probabilities_satisfy_entropy_and_stationarity() {
    let original = [0.0, 1e-20, 0.0003, 0.1, 1.0, 5.0, 1e10, 1e39];
    for payload in [0.01, 0.3, 1.0, 4.0, 8.0, 10.0] {
        let (beta, lambda) = solve_fi(&original, payload).unwrap();
        let total: f64 = beta.iter().map(|&b| h3(b)).sum();
        assert!((total - payload).abs() <= 1e-9 * payload.max(1.0) + 1e-15);
        assert_eq!(beta[0], 0.0);
        for (&b, &fi) in beta.iter().zip(&original).filter(|(_, fi)| **fi > 0.0) {
            if b > MIN_BETA && b < 0.32 {
                let reconstructed = b / ((1.0 - 2.0 * b) / b).log2() * fi;
                assert!((reconstructed / lambda - 1.0).abs() < 1e-12);
            }
        }
    }
}

#[test]
fn equal_information_gives_the_known_uniform_probability() {
    // H3(1/4) = 1.5 bits exactly; f(1/4) = 1/4, so λ = FI/4.
    let (beta, lambda) = solve_fi(&[4.0; 8], 12.0).unwrap();
    for b in beta {
        assert!((b - 0.25).abs() < 1e-9);
    }
    assert!((lambda - 1.0).abs() < 1e-8);
}

#[test]
fn endpoint_payloads_keep_costs_finite_and_obey_the_tolerance() {
    let capacity = 3.0 * 3.0f64.log2();
    for payload in [
        1e-300,
        1e-12,
        1e-4,
        capacity - 1e-8,
        capacity * (1.0 - 1e-12),
    ] {
        let (beta, lambda) = solve_fi(&[1e-44, 1.0, 1e39], payload).unwrap();
        assert!(lambda.is_finite() && lambda > 0.0);
        let achieved: f64 = beta.iter().map(|&b| h3(b)).sum();
        assert!(
            (achieved - payload).abs() <= 1e-9 * payload.max(1.0),
            "{payload}: {achieved}"
        );
        for b in beta {
            let cost = (-2.0 * b).ln_1p() - b.ln();
            assert!(cost.is_finite() && cost >= 0.0);
        }
    }
}

#[test]
fn cost_output_matches_beta_output() {
    let fi = spread(5_000);
    let ln_fi: Vec<f64> = fi.iter().map(|v| v.ln()).collect();
    let view = View {
        values: &ln_fi,
        order: None,
    };
    let (mut betas, mut costs) = (vec![0.0; fi.len()], vec![0.0; fi.len()]);
    let a = solve(view, 900.0, &mut betas, Output::Beta).unwrap();
    let b = solve(view, 900.0, &mut costs, Output::Cost).unwrap();
    assert_eq!(a.to_bits(), b.to_bits());
    for (&b, &rho) in betas.iter().zip(&costs) {
        assert!((b - 1.0 / (2.0 + rho.exp())).abs() <= 1e-15 * b);
    }
}

#[test]
fn impossible_payloads_are_rejected() {
    assert_eq!(
        validate_payload(1000, 1000.0 * 3.0f64.log2()),
        Err(CostError::Payload)
    );
    assert_eq!(validate_payload(1000, f64::NAN), Err(CostError::Payload));
    assert_eq!(
        validate_payload(1000, f64::INFINITY),
        Err(CostError::Payload)
    );
    assert_eq!(validate_payload(1000, -1.0), Err(CostError::Payload));
    assert_eq!(validate_payload(0, 1.0), Err(CostError::Payload));
    assert_eq!(validate_payload(1000, 0.0), Ok(()));
    let bits = 1000.0 * 3.0f64.log2() - 5.0;
    assert_eq!(validate_payload(1000, bits), Ok(()));
    assert!(solve_fi(&spread(1000), bits).is_ok());
}

#[test]
fn uncapped_cost_solves_its_equation_past_the_floor() {
    // ρ (2 + e^ρ) = e^k in logarithms, from k = −60 to far past the floor's k ≈ 697.3;
    // below the cap it is the capped solver's ρ, and the two meet at the cap.
    let ln_lambda = 3.0;
    for i in 0..4000 {
        let k = -60.0 + f64::from(i) * 0.5;
        let ln_fi = k - LN_2.ln() + ln_lambda;
        let rho = uncapped_cost(ln_fi, ln_lambda);
        let solved = rho.ln() + rho + (2.0 * (-rho).exp()).ln_1p();
        assert!((solved - k).abs() <= 1e-12 * k.abs().max(1.0), "{k}: {rho}");
        let (capped, _, at_cap) = cost(k);
        if at_cap {
            assert!(rho >= RHO_MAX && capped == RHO_MAX);
        } else {
            assert!((rho - capped).abs() <= 1e-15 * rho.max(1e-300), "{k}");
        }
    }
    assert_eq!(uncapped_cost(f64::NEG_INFINITY, ln_lambda), f64::INFINITY);
}
