//! Which luminance coefficients carry a record and which way each may move.
//!
//! Every rule keeps zeros at zero and non-zeros away from zero, so a reader finds the same sites
//! in the changed photo as the writer found in the original, and every change keeps its place in
//! the entropy-coded run of zeros. A move whose new size has no code in the photo's own Huffman
//! table is forbidden, so the file keeps its tables.

use crate::jpeg::{COEFFICIENTS, Jpeg, ZIGZAG};

/// Largest magnitude of an AC coefficient in 8-bit baseline JPEG.
const AC_LIMIT: i32 = 1023;

/// Which coefficients are sites and how they may move. The detectability measurements decide
/// which one the program recommends; a reader tries every rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteRule {
    /// Sites are the coefficients with |q| >= 2; a 2 may only grow.
    Keep2,
    /// Sites are the non-zero coefficients; a 1 may only grow to 2, larger ones move both ways.
    Grow1,
    /// Sites are the non-zero coefficients; ones never change, larger ones move both ways.
    Frozen1,
}

impl SiteRule {
    /// Every rule, in the order a reader tries them.
    pub const ALL: [Self; 3] = [Self::Frozen1, Self::Grow1, Self::Keep2];

    /// The rule's short name, as the measurements and reports name it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Keep2 => "keep2",
            Self::Grow1 => "grow1",
            Self::Frozen1 => "frozen1",
        }
    }

    /// One sentence on the rule for the advanced view.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Keep2 => "Only coefficients of magnitude 2 or more change, and a 2 only grows.",
            Self::Grow1 => "Every non-zero coefficient may change; a 1 only grows to 2.",
            Self::Frozen1 => "Coefficients of magnitude 2 or more change; ones and zeros never do.",
        }
    }

    /// The byte that binds the rule into a record's associated data.
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::Keep2 => 1,
            Self::Grow1 => 2,
            Self::Frozen1 => 3,
        }
    }

    fn is_site(self, q: i32) -> bool {
        match self {
            Self::Keep2 => q.abs() >= 2,
            Self::Grow1 | Self::Frozen1 => q != 0,
        }
    }

    fn allows(self, q: i32, v: i32) -> bool {
        v != 0
            && v.abs() <= AC_LIMIT
            && match self {
                Self::Keep2 => q.abs() > 2 || v.abs() > q.abs(),
                Self::Grow1 => q.abs() > 1 || v.abs() > q.abs(),
                Self::Frozen1 => q.abs() >= 2,
            }
    }
}

/// The sites of a photo under one rule, in raster order of the full luminance blocks.
pub(crate) struct Sites {
    /// Indexes into the luminance plane.
    pub positions: Vec<usize>,
    /// Non-zero AC coefficients of the full blocks, the base of the bits-per-nonzero-AC rate.
    pub nonzero_ac: usize,
}

impl Sites {
    /// The sites of `luma` under `rule`; the reader passes the changed plane, the writer the
    /// original, and both get the same list.
    pub(crate) fn find(jpeg: &Jpeg, luma: &[i16], rule: SiteRule) -> Self {
        let (wide, high) = jpeg.frame().full_blocks();
        let stride = jpeg.frame().components[0].stride;
        let mut positions = Vec::new();
        let mut nonzero_ac = 0;
        for by in 0..high {
            for bx in 0..wide {
                let base = (by * stride + bx) * COEFFICIENTS;
                for mode in 1..COEFFICIENTS {
                    let q = i32::from(luma[base + mode]);
                    nonzero_ac += usize::from(q != 0);
                    if rule.is_site(q) {
                        positions.push(base + mode);
                    }
                }
            }
        }
        Self {
            positions,
            nonzero_ac,
        }
    }

    /// Allowed directions `(plus, minus)` of every site of the original `luma`.
    pub(crate) fn directions(
        &self,
        jpeg: &Jpeg,
        luma: &[i16],
        rule: SiteRule,
    ) -> Vec<(bool, bool)> {
        let runs = zero_runs(luma);
        self.positions
            .iter()
            .map(|&position| {
                let q = i32::from(luma[position]);
                let run = usize::from(runs[position]);
                let ok = |v: i32| rule.allows(q, v) && jpeg.luma_codes(run, v);
                (ok(q + 1), ok(q - 1))
            })
            .collect()
    }
}

/// For every coefficient, the zeros before it in zigzag order since the previous non-zero
/// coefficient of its block: the run its Huffman symbol carries.
fn zero_runs(luma: &[i16]) -> Vec<u8> {
    let mut runs = vec![0_u8; luma.len()];
    for (block, out) in luma
        .as_chunks::<COEFFICIENTS>()
        .0
        .iter()
        .zip(runs.as_chunks_mut::<COEFFICIENTS>().0)
    {
        let mut run = 0_u8;
        for &index in &ZIGZAG[1..] {
            out[index] = run;
            run = if block[index] == 0 { run + 1 } else { 0 };
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rule_lets_a_site_reach_zero_or_a_zero_become_a_site() {
        for rule in SiteRule::ALL {
            for q in -5..=5 {
                for v in [q - 1, q + 1] {
                    if rule.is_site(q) && rule.allows(q, v) {
                        assert!(rule.is_site(v), "{} {q} -> {v}", rule.name());
                    }
                }
                assert!(!rule.is_site(0));
            }
        }
    }

    #[test]
    fn the_rules_move_ones_and_twos_as_named() {
        assert!(!SiteRule::Frozen1.allows(1, 2));
        assert!(SiteRule::Frozen1.allows(2, 1));
        assert!(SiteRule::Grow1.allows(-1, -2));
        assert!(!SiteRule::Grow1.allows(1, 0));
        assert!(!SiteRule::Keep2.allows(2, 1));
        assert!(SiteRule::Keep2.allows(-2, -3));
        assert!(!SiteRule::Keep2.allows(1023, 1024));
    }

    #[test]
    fn runs_count_zeros_since_the_last_nonzero_in_zigzag_order() {
        let mut block = vec![0_i16; COEFFICIENTS];
        // Zigzag positions 1, 2 and 5 hold natural indexes 1, 8 and 2.
        block[1] = 3;
        block[2] = -1;
        let runs = zero_runs(&block);
        assert_eq!(runs[1], 0);
        assert_eq!(runs[2], 3);
    }
}
