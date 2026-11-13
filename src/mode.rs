//! The choices a person makes: the mode, and in the advanced view the cost model and site rule.

use crate::StegoError;
use crate::algorithm::jcrfw::JCrfw;
use crate::algorithm::jmipod::JMiPod;
use crate::algorithm::model::{CostModel as _, DctPlane, Permitted};
use crate::algorithm::{juniward, uerd};
use crate::sites::SiteRule;

/// How a photo carries its records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One record, written with ±1 changes chosen by a ternary syndrome-trellis code.
    Standard,
    /// A decoy record with its own password, and the secret hidden in the directions of the
    /// decoy's changes. Whoever has only the decoy password cannot tell a second record exists.
    Decoy,
}

impl Mode {
    /// Every mode, in the order a host lists them.
    pub const ALL: [Self; 2] = [Self::Standard, Self::Decoy];

    /// The mode's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Decoy => "With decoy",
        }
    }

    /// One sentence for the simple view.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::Standard => "The most room for the secret; one password opens it.",
            Self::Decoy => {
                "A decoy message with its own password; the secret hides behind it and is much smaller."
            }
        }
    }

    /// The technical description for the advanced view.
    #[must_use]
    pub const fn technical(self) -> &'static str {
        match self {
            Self::Standard => {
                "Ternary syndrome-trellis code (h = 10, 128-bit segments) over the sites of the chosen rule, two layers: second bit then parity."
            }
            Self::Decoy => {
                "Binary syndrome-trellis code over the non-zero AC coefficients carries the decoy; the ±1 direction of each two-way change carries the secret through a keyed wet-paper code on the second bit of |q|."
            }
        }
    }
}

/// The source of the costs that decide which coefficients change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostModel {
    /// Holub, Fridrich and Denemark, EURASIP JIS 2014: wavelet residuals of the decoded image.
    JUniward,
    /// Cogranne, Giboulot and Bas, IEEE TIFS 2021: a statistical model of the coefficients.
    JMiPod,
    /// Pan et al., Signal Processing 2024: J-MiPOD with correlations between neighbouring blocks.
    JCrfw,
    /// Guo et al., IEEE TIFS 2015: uniform embedding revisited; the fastest.
    Uerd,
}

impl CostModel {
    /// Every model, in the order a host lists them.
    pub const ALL: [Self; 4] = [Self::JUniward, Self::JMiPod, Self::JCrfw, Self::Uerd];

    /// The model's usual name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::JUniward => "J-UNIWARD",
            Self::JMiPod => "J-MiPOD",
            Self::JCrfw => "J-CRFW",
            Self::Uerd => "UERD",
        }
    }

    /// One sentence for the advanced view.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::JUniward => "Changes go where the photo's texture hides them best.",
            Self::JMiPod => "Changes follow a statistical model of the photo's noise.",
            Self::JCrfw => "Like J-MiPOD, also counting how neighbouring blocks move together.",
            Self::Uerd => "Spreads changes by block energy; fast, older and easier to detect.",
        }
    }

    /// The symmetric cost of changing each position; `any` says whether a position may change
    /// at all, and `bits` is the payload the payload-aware models solve for.
    pub(crate) fn costs(
        self,
        plane: &DctPlane,
        positions: &[usize],
        any: &[bool],
        bits: usize,
    ) -> Result<Vec<f64>, StegoError> {
        Ok(match self {
            Self::JUniward => juniward::distortions(plane, positions),
            Self::Uerd => uerd::distortions(plane, positions),
            Self::JMiPod | Self::JCrfw => {
                // These models need both directions open; the rule closes one afterwards.
                let permitted: Vec<Permitted> = any
                    .iter()
                    .map(|&open| {
                        if open {
                            Permitted::Both
                        } else {
                            Permitted::None
                        }
                    })
                    .collect();
                // Payload bits are far below 2^53, so the conversion is exact.
                let payload = bits as f64;
                let costs = if self == Self::JMiPod {
                    JMiPod.costs(plane, positions, &permitted, payload)?
                } else {
                    JCrfw::default().costs(plane, positions, &permitted, payload)?
                };
                costs.plus
            }
        })
    }
}

/// The full choice for one hiding job. [`Settings::default`] is what the simple view uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The mode.
    pub mode: Mode,
    /// The cost model.
    pub cost_model: CostModel,
    /// The site rule of the standard mode. The decoy mode always uses [`SiteRule::Grow1`].
    pub site_rule: SiteRule,
    /// With several photos: `None` splits each message so that every photo is needed;
    /// `Some(k)` makes any `k` photos enough: every photo carries a Reed–Solomon shard of 1/k
    /// of the encrypted message and a Shamir share of its key.
    pub needed: Option<u8>,
}

impl Default for Settings {
    /// J-UNIWARD with `frozen1`: a provisional choice until the detectability measurements
    /// name the best pair; a reader opens every pair either way.
    fn default() -> Self {
        Self {
            mode: Mode::Standard,
            cost_model: CostModel::JUniward,
            site_rule: SiteRule::Frozen1,
            needed: None,
        }
    }
}

impl Settings {
    /// The rule the mode actually uses.
    pub(crate) const fn rule(&self) -> SiteRule {
        match self.mode {
            Mode::Standard => self.site_rule,
            Mode::Decoy => SiteRule::Grow1,
        }
    }
}
