//! Which coefficient changes the next JPEG profile allows.
//!
//! The rules are shared by every cost model so that comparisons use the same cover.

use crate::algorithm::model::{BLOCK, CostError, DctPlane, Permitted};

/// Largest magnitude a baseline 8-bit JPEG AC coefficient may hold.
pub const AC_LIMIT: i16 = 1023;

/// Rule for coefficients that are zero or would become zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroRule {
    /// Every AC coefficient may change by ±1, zeros included.
    Unrestricted,
    /// Zeros and unit magnitudes stay unchanged, so no zero appears or disappears and every
    /// remaining coefficient can move in both directions.
    NoZeros,
    /// Zeros stay unchanged in modes with `u + v >= from`; everything else as `Unrestricted`.
    HighFrequencyZeros {
        /// Smallest `u + v` whose zeros are kept.
        from: u8,
    },
}

/// Permitted directions for each position: luminance AC only, DC unchanged, the format limits
/// respected, and zeros treated by `rule`.
pub fn permitted(
    plane: &DctPlane,
    positions: &[usize],
    rule: ZeroRule,
) -> Result<Vec<Permitted>, CostError> {
    plane.validate()?;
    positions
        .iter()
        .map(|&position| {
            let value = *plane
                .coefficients
                .get(position)
                .ok_or(CostError::Permission)?;
            Ok(one(position % BLOCK, value, rule))
        })
        .collect()
}

fn one(mode: usize, value: i16, rule: ZeroRule) -> Permitted {
    if mode == 0 {
        return Permitted::None;
    }
    let frequency_sum = mode / 8 + mode % 8;
    let kept = match rule {
        ZeroRule::Unrestricted => false,
        ZeroRule::NoZeros => value.abs() <= 1,
        ZeroRule::HighFrequencyZeros { from } => value == 0 && frequency_sum >= usize::from(from),
    };
    if kept {
        return Permitted::None;
    }
    match (value < AC_LIMIT, value > -AC_LIMIT) {
        (true, true) => Permitted::Both,
        (true, false) => Permitted::Plus,
        (false, true) => Permitted::Minus,
        (false, false) => Permitted::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_limits_and_zero_rules() {
        assert_eq!(one(0, 5, ZeroRule::Unrestricted), Permitted::None);
        assert_eq!(one(1, 0, ZeroRule::Unrestricted), Permitted::Both);
        assert_eq!(one(1, 0, ZeroRule::NoZeros), Permitted::None);
        assert_eq!(one(1, -1, ZeroRule::NoZeros), Permitted::None);
        assert_eq!(one(1, 2, ZeroRule::NoZeros), Permitted::Both);
        assert_eq!(
            one(63, 0, ZeroRule::HighFrequencyZeros { from: 8 }),
            Permitted::None
        );
        assert_eq!(
            one(9, 0, ZeroRule::HighFrequencyZeros { from: 8 }),
            Permitted::Both
        );
        assert_eq!(one(5, AC_LIMIT, ZeroRule::Unrestricted), Permitted::Minus);
        assert_eq!(one(5, -AC_LIMIT, ZeroRule::Unrestricted), Permitted::Plus);
    }
}
