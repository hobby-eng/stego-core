//! Shared types between cost models and the coder.

use std::fmt;

/// Number of coefficients in one 8×8 block.
pub const BLOCK: usize = 64;

/// Quantized luminance DCT coefficients of one JPEG image.
///
/// Layout: block `(by, bx)` starts at `(by * blocks_wide + bx) * 64`; inside a block the
/// coefficient for vertical frequency `u` and horizontal frequency `v` sits at `u * 8 + v`
/// (natural order, not zigzag). `quant` uses the same `u * 8 + v` order.
#[derive(Clone, Debug)]
pub struct DctPlane {
    /// Number of luminance blocks in each row.
    pub blocks_wide: usize,
    /// Number of luminance block rows.
    pub blocks_high: usize,
    /// Quantized coefficients in block-major, natural frequency order.
    pub coefficients: Vec<i16>,
    /// Nonzero quantization steps in natural frequency order.
    pub quant: [u16; BLOCK],
}

impl DctPlane {
    /// Checks the layout invariants every cost model relies on.
    pub fn validate(&self) -> Result<(), CostError> {
        let blocks = self
            .blocks_wide
            .checked_mul(self.blocks_high)
            .ok_or(CostError::Shape)?;
        let coefficients = blocks.checked_mul(BLOCK).ok_or(CostError::Shape)?;
        if blocks == 0 || self.coefficients.len() != coefficients {
            return Err(CostError::Shape);
        }
        if self.quant.contains(&0) {
            return Err(CostError::Quantization);
        }
        Ok(())
    }
}

/// Which changes the policy layer allows for one coefficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permitted {
    /// The coefficient must stay unchanged (wet).
    None,
    /// Only `+1` is allowed.
    Plus,
    /// Only `-1` is allowed.
    Minus,
    /// Both `+1` and `-1` are allowed.
    Both,
}

/// Costs of changing each selected coefficient by `+1` and by `-1`.
///
/// Indexes match the `positions` passed to [`CostModel::costs`]. `f64::INFINITY` marks a
/// forbidden change; every other value is finite. Costs are only compared within one image
/// and one payload.
#[derive(Clone, Debug)]
pub struct Costs {
    /// Costs of adding one, in the caller's position order.
    pub plus: Vec<f64>,
    /// Costs of subtracting one, in the caller's position order.
    pub minus: Vec<f64>,
}

/// A source of embedding costs.
pub trait CostModel {
    /// Costs for the coefficients the coder will use. `positions` index the plane's coefficients and
    /// `permitted` has one entry each; a forbidden direction must cost infinity. `payload_bits` (framing
    /// included) matters only to model-based costs such as J-MiPOD and J-CRFW.
    fn costs(
        &self,
        plane: &DctPlane,
        positions: &[usize],
        permitted: &[Permitted],
        payload_bits: f64,
    ) -> Result<Costs, CostError>;
}

/// Why a cost model refused its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostError {
    /// Coefficient count does not match the block grid, or the grid is empty.
    Shape,
    /// A quantization step is zero.
    Quantization,
    /// `permitted` does not have one entry per position, or a position is out of range or
    /// repeated.
    Permission,
    /// The payload cannot be carried by the permitted coefficients.
    Payload,
    /// The model got a coefficient it does not support, such as one permitted direction
    /// where the model needs both.
    Unsupported,
    /// The model could not compute finite costs with its required accuracy.
    Computation,
}

impl fmt::Display for CostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Shape => "the coefficient count does not match the block grid",
            Self::Quantization => "a quantization step is zero",
            Self::Permission => "the permission list does not match the coefficients",
            Self::Payload => "the permitted coefficients cannot carry the payload",
            Self::Unsupported => "the cost model does not support this coefficient policy",
            Self::Computation => "the cost model could not compute accurate finite costs",
        })
    }
}

impl std::error::Error for CostError {}
