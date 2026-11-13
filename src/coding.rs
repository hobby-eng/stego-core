//! The three coding layers: the ternary record, the binary decoy, and the record hidden in the
//! directions of the decoy's changes.

use crate::StegoError;
use crate::algorithm::model::Costs;
use crate::algorithm::stc::{
    HEIGHT, SEGMENT_BITS, Ternary, binary_embed, binary_extract, columns, lsb, ternary_embed_split,
    ternary_extract,
};
use crate::algorithm::wetpaper;
use crate::random::{Random, next_u64};
use crate::sites::Sites;

/// Free sites the hidden record leaves to coins beyond its bits, so that its system of
/// equations has a solution except with probability below 2^-64.
pub(crate) const HIDDEN_MARGIN: usize = 64;
/// Largest hidden record, in bits: the wet-paper solve grows with the cube of its size (about
/// 3.4 s at 8,192 bits on a laptop core, minutes at 32,768).
pub(crate) const HIDDEN_CAP: usize = 8_192;

/// One layer's sites in its keyed order, with their values.
pub(crate) struct Lane {
    pub positions: Vec<usize>,
    pub values: Vec<i32>,
}

impl Lane {
    pub(crate) fn new(sites: &Sites, luma: &[i16], order: &[u32]) -> Self {
        let positions: Vec<usize> = order.iter().map(|&i| sites.positions[i as usize]).collect();
        let values = positions.iter().map(|&p| i32::from(luma[p])).collect();
        Self { positions, values }
    }

    /// Writes `stego` (in lane order) into `luma`; returns the number of changed coefficients.
    pub(crate) fn apply(&self, stego: &[i32], luma: &mut [i16]) -> Result<usize, StegoError> {
        let mut changes = 0;
        for ((&position, &before), &after) in self.positions.iter().zip(&self.values).zip(stego) {
            if before != after {
                luma[position] = i16::try_from(after).map_err(|_| StegoError::Coding)?;
                changes += 1;
            }
        }
        Ok(changes)
    }
}

/// Directional costs in lane order: the model's cost where the rule allows the move, infinite
/// where it does not.
pub(crate) fn directional(base: &[f64], directions: &[(bool, bool)], order: &[u32]) -> Costs {
    let mut plus = Vec::with_capacity(order.len());
    let mut minus = Vec::with_capacity(order.len());
    for &i in order {
        let (up, down) = directions[i as usize];
        let cost = base[i as usize];
        plus.push(if up { cost } else { f64::INFINITY });
        minus.push(if down { cost } else { f64::INFINITY });
    }
    Costs { plus, minus }
}

/// The ternary layer: half the bits in the second-bit layer, the rest in the parities, so that
/// the reader knows the split from the record size alone.
pub(crate) fn write_ternary(
    lane: &Lane,
    costs: &Costs,
    message: &[u8],
    seed: u64,
) -> Result<Ternary, StegoError> {
    ternary_embed_split(
        &lane.values,
        costs,
        message,
        seed,
        SEGMENT_BITS,
        message.len() / 2,
    )
    .map_err(|_| StegoError::Coding)
}

pub(crate) fn read_ternary(values: &[i32], bits: usize, seed: u64) -> Vec<u8> {
    ternary_extract(values, [bits / 2, bits - bits / 2], seed, SEGMENT_BITS)
}

/// The binary decoy before the directions of its two-way changes are chosen.
pub(crate) struct BinaryWrite {
    pub stego: Vec<i32>,
    /// Lane indexes of changed sites that may move either way.
    pub free: Vec<usize>,
}

/// The parity cost of flipping a site: the mean of its open directions.
fn flip_cost(plus: f64, minus: f64) -> f64 {
    match (plus.is_finite(), minus.is_finite()) {
        (true, true) => 0.5 * (plus + minus),
        (true, false) => plus,
        (false, true) => minus,
        (false, false) => f64::INFINITY,
    }
}

pub(crate) fn write_binary(
    lane: &Lane,
    costs: &Costs,
    message: &[u8],
    seed: u64,
) -> Result<BinaryWrite, StegoError> {
    let parities: Vec<u8> = lane.values.iter().map(|&v| lsb(v)).collect();
    let flips: Vec<f64> = costs
        .plus
        .iter()
        .zip(&costs.minus)
        .map(|(&p, &m)| flip_cost(p, m))
        .collect();
    let n = parities.len();
    let chosen = binary_embed(
        &parities,
        &flips,
        message,
        &columns(n, HEIGHT, seed),
        HEIGHT,
        SEGMENT_BITS,
    )
    .map_err(|_| StegoError::Coding)?;
    let mut stego = lane.values.clone();
    let mut free = Vec::new();
    for j in 0..n {
        if chosen[j] == parities[j] {
            continue;
        }
        match (costs.plus[j].is_finite(), costs.minus[j].is_finite()) {
            (true, true) => free.push(j),
            (true, false) => stego[j] += 1,
            (false, true) => stego[j] -= 1,
            (false, false) => return Err(StegoError::Coding),
        }
    }
    Ok(BinaryWrite { stego, free })
}

pub(crate) fn read_binary(values: &[i32], bits: usize, seed: u64) -> Vec<u8> {
    let parities: Vec<u8> = values.iter().map(|&v| lsb(v)).collect();
    binary_extract(
        &parities,
        bits,
        &columns(parities.len(), HEIGHT, seed),
        HEIGHT,
        SEGMENT_BITS,
    )
}

/// Gives every free change a coin-chosen direction: the decoy mode without a secret behind it.
pub(crate) fn write_coins(
    write: &mut BinaryWrite,
    random: &mut dyn Random,
) -> Result<(), StegoError> {
    for &j in &write.free {
        let up = next_u64(random)? & 1 == 1;
        write.stego[j] += if up { 1 } else { -1 };
    }
    Ok(())
}

/// Chooses the direction of every free change: the hidden record's bits through the wet-paper
/// code, and coins from the host's random source for the rest. Coins and the solver's free
/// variables come from the random source, never from a password, so that the decoy password
/// cannot recompute them.
pub(crate) fn write_hidden(
    lane: &Lane,
    write: &mut BinaryWrite,
    message: &[u8],
    key: u64,
    random: &mut dyn Random,
) -> Result<(), StegoError> {
    let bits = message.len();
    if bits > HIDDEN_CAP || bits + HIDDEN_MARGIN > write.free.len() {
        return Err(StegoError::HiddenLong);
    }
    let (solved, coined) = write.free.split_at(bits + HIDDEN_MARGIN);
    for &j in coined {
        let up = next_u64(random)? & 1 == 1;
        write.stego[j] += if up { 1 } else { -1 };
    }
    let mut is_solved = vec![false; write.stego.len()];
    for &j in solved {
        is_solved[j] = true;
    }
    let rest = wetpaper::syndrome(
        (0..write.stego.len()).filter(|&j| !is_solved[j]).map(|j| {
            (
                lane.positions[j] as u64,
                wetpaper::magnitude_bit(write.stego[j]),
            )
        }),
        key,
        bits,
    );
    let target: Vec<u64> = wetpaper::pack(message)
        .iter()
        .zip(&rest)
        .map(|(a, b)| a ^ b)
        .collect();
    let positions: Vec<u64> = solved.iter().map(|&j| lane.positions[j] as u64).collect();
    let mut coins = Vec::with_capacity(solved.len());
    for _ in 0..solved.len() {
        coins.push(next_u64(random)?);
    }
    let mut supply = coins.into_iter();
    let x = wetpaper::solve(&positions, key, bits, &target, &mut || {
        supply.next().unwrap_or(0)
    })
    .ok_or(StegoError::HiddenLong)?;
    for (&j, bit) in solved.iter().zip(x) {
        let up = wetpaper::magnitude_bit(lane.values[j] + 1) == bit;
        write.stego[j] += if up { 1 } else { -1 };
    }
    Ok(())
}

/// The hidden layer's syndrome of `bits` bits over every site, in any order; a shorter record's
/// syndrome is a prefix of a longer one's.
pub(crate) fn hidden_syndrome(sites: &Sites, luma: &[i16], key: u64, bits: usize) -> Vec<u64> {
    wetpaper::syndrome(
        sites
            .positions
            .iter()
            .map(|&p| (p as u64, wetpaper::magnitude_bit(i32::from(luma[p])))),
        key,
        bits,
    )
}

/// The first `bits` bits of a syndrome, one per byte.
pub(crate) fn syndrome_bits(words: &[u64], bits: usize) -> Vec<u8> {
    (0..bits)
        .map(|i| ((words[i / 64] >> (i % 64)) & 1) as u8)
        .collect()
}
