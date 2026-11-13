//! Whether a secret and a decoy fit a set of photos, by the same placement rules as writing:
//! slices in proportion to each photo's room, or the whole message in every photo of a k-of-n
//! set, and the room behind a decoy.

use crate::coding::{HIDDEN_CAP, HIDDEN_MARGIN};
use crate::content::{CONTENT_HEADER, Content};
use crate::cover::{Cover, HIDDEN_SHARE, MAX_BITS_PER_SITE, RECOMMENDED_BPNZAC};
use crate::mode::{Mode, Settings};
use crate::parts::PART_HEADER;
use crate::record::{LENGTH_BYTES, bodies, record_bits};
use crate::sites::Sites;
use crate::{StegoError, threshold};

/// The room for one message, in bytes of its text or file. The name of a file takes room too,
/// so the room is given for the message as it is now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Room {
    /// The message's own size.
    pub needed: usize,
    /// The largest message of this kind and name at the recommended rate.
    pub recommended: usize,
    /// The largest message the coders can place at all.
    pub maximum: usize,
    /// The photo, by its index among those given, whose room ends the recommended size first:
    /// the one to replace with a larger photo when the message does not fit.
    pub limiting: Option<usize>,
}

impl Room {
    /// Whether the message fits at the recommended rate.
    #[must_use]
    pub const fn fits(&self) -> bool {
        self.needed <= self.recommended
    }

    /// Whether the message can be written at all.
    #[must_use]
    pub const fn possible(&self) -> bool {
        self.needed <= self.maximum
    }

    /// Bytes left at the recommended rate; negative when the message is that much too large.
    #[must_use]
    pub fn spare(&self) -> i64 {
        i64::try_from(self.recommended).unwrap_or(i64::MAX)
            - i64::try_from(self.needed).unwrap_or(i64::MAX)
    }
}

/// The rooms of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit {
    /// The secret's room.
    pub secret: Room,
    /// The decoy's room, in the decoy mode.
    pub decoy: Option<Room>,
    /// Photos of the set that may be lost with the message still readable: n − k for any k of
    /// n, none when every photo is needed.
    pub may_lose: usize,
}

/// One photo's limits in bits of a record at the two rates.
struct Limits {
    weight: usize,
    recommended: usize,
    maximum: usize,
}

/// The rooms of `secret` and `decoy` in `covers` under `settings`.
///
/// # Errors
///
/// [`StegoError::Carriers`] for no photos or too many, [`StegoError::DuplicatePhoto`] for the
/// same photo twice (as writing would refuse it), [`StegoError::DecoyChoice`] when the decoy
/// does not match the mode, [`StegoError::Threshold`] for an impossible threshold.
pub fn fit(
    covers: &[&Cover],
    settings: &Settings,
    secret: &Content,
    decoy: Option<&Content>,
) -> Result<Fit, StegoError> {
    crate::hide::check_carriers(covers)?;
    if let Some(needed) = settings.needed
        && (needed < 2
            || usize::from(needed) > covers.len()
            || covers.len() > threshold::THRESHOLD_MAX)
    {
        return Err(StegoError::Threshold);
    }
    let limits: Vec<Limits> = covers
        .iter()
        .map(|cover| {
            let sites = Sites::find(cover.jpeg(), cover.jpeg().luma(), settings.rule());
            let maximum = (sites.positions.len() as f64 * MAX_BITS_PER_SITE) as usize;
            let recommended =
                ((sites.nonzero_ac as f64 * RECOMMENDED_BPNZAC) as usize).min(maximum);
            Limits {
                weight: sites.positions.len(),
                recommended,
                maximum,
            }
        })
        .collect();
    let room = |content: &Content, hidden: bool| {
        let fixed = CONTENT_HEADER + content.name().len();
        let caps_at = |rate: fn(&Limits) -> usize| -> Vec<usize> {
            limits
                .iter()
                .map(|l| {
                    let bits = if hidden {
                        hidden_bits(rate(l))
                    } else {
                        rate(l)
                    };
                    largest_plain(bits)
                })
                .collect()
        };
        let weights: Vec<usize> = limits.iter().map(|l| l.weight).collect();
        let recommended_caps = caps_at(|l| l.recommended);
        let recommended = largest_encoded(&recommended_caps, &weights, settings.needed);
        Room {
            needed: content.bytes().len(),
            recommended: recommended.saturating_sub(fixed),
            maximum: largest_encoded(&caps_at(|l| l.maximum), &weights, settings.needed)
                .saturating_sub(fixed),
            limiting: limiting(&recommended_caps, &weights, settings.needed, recommended),
        }
    };
    let may_lose = settings.needed.map_or(0, |k| covers.len() - usize::from(k));
    match (settings.mode, decoy) {
        (Mode::Standard, None) => Ok(Fit {
            secret: room(secret, false),
            decoy: None,
            may_lose,
        }),
        (Mode::Decoy, Some(decoy)) => Ok(Fit {
            secret: room(secret, true),
            decoy: Some(room(decoy, false)),
            may_lose,
        }),
        (Mode::Decoy, None) => Ok(Fit {
            secret: room(secret, false),
            decoy: None,
            may_lose,
        }),
        (Mode::Standard, Some(_)) => Err(StegoError::DecoyChoice),
    }
}

/// Bits a hidden record may use behind a decoy of at most `decoy_bits` bits.
fn hidden_bits(decoy_bits: usize) -> usize {
    ((decoy_bits as f64 * HIDDEN_SHARE) as usize)
        .saturating_sub(HIDDEN_MARGIN)
        .min(HIDDEN_CAP)
}

/// The largest plain record (part header and payload) whose record has at most `bits` bits.
fn largest_plain(bits: usize) -> usize {
    bodies()
        .take_while(|&body| record_bits(body) <= bits)
        .last()
        .map_or(0, |body| body - LENGTH_BYTES)
}

/// The largest encoded message whose parts fit plain records of at most `caps` bytes.
fn largest_encoded(caps: &[usize], weights: &[usize], needed: Option<u8>) -> usize {
    if needed.is_some() {
        // Every photo of a k-of-n set carries one shard of 1/k of the ciphertext and one key
        // share; the shards are of equal size, so the smallest photo bounds them all.
        let overhead = PART_HEADER + threshold::PAYLOAD_OVERHEAD;
        let shard = caps
            .iter()
            .min()
            .map_or(0, |&cap| cap.saturating_sub(overhead));
        let k = needed.map_or(1, usize::from);
        return (shard * k).saturating_sub(threshold::TAG_BYTES);
    }
    let fits = |length: usize| {
        slice_lengths(length, weights)
            .zip(caps)
            .all(|(slice, &cap)| PART_HEADER + slice <= cap)
    };
    let (mut low, mut high) = (0, caps.iter().sum::<usize>());
    if fits(high) {
        return high;
    }
    // `fits(low)` holds and `fits(high)` does not; the parts grow with the length.
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if fits(middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

/// The photo whose room a message one byte longer than `length` overflows first: the smallest
/// room in a k-of-n set, else the first photo whose slice no longer fits.
fn limiting(caps: &[usize], weights: &[usize], needed: Option<u8>, length: usize) -> Option<usize> {
    if needed.is_some() {
        return caps
            .iter()
            .enumerate()
            .min_by_key(|&(_, cap)| *cap)
            .map(|(i, _)| i);
    }
    slice_lengths(length + 1, weights)
        .zip(caps)
        .position(|(slice, &cap)| PART_HEADER + slice > cap)
}

/// The slice lengths `crate::parts::spread` gives a message of `length` bytes.
fn slice_lengths(length: usize, weights: &[usize]) -> impl Iterator<Item = usize> {
    let total: u128 = weights.iter().map(|&w| w as u128).sum::<u128>().max(1);
    let mut start = 0;
    let mut cumulative: u128 = 0;
    let last = weights.len().saturating_sub(1);
    weights.iter().enumerate().map(move |(index, &weight)| {
        cumulative += weight as u128;
        let end = if index == last {
            length
        } else {
            (length as u128 * cumulative / total) as usize
        };
        let slice = end - start;
        start = end;
        slice
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_add_up_and_follow_the_weights() {
        let slices: Vec<usize> = slice_lengths(1002, &[1, 3]).collect();
        assert_eq!(slices, [250, 752]);
    }

    #[test]
    fn the_largest_split_respects_the_smallest_share_of_room() {
        // Two photos of equal weight: each slice must fit its photo, so the smaller photo bounds it.
        let caps = [PART_HEADER + 100, PART_HEADER + 1000];
        assert_eq!(largest_encoded(&caps, &[1, 1], None), 201);
        let shard = 100 - threshold::PAYLOAD_OVERHEAD;
        let largest = largest_encoded(&caps, &[1, 1], Some(2));
        assert_eq!(largest, 2 * shard - threshold::TAG_BYTES);
        assert_eq!(threshold::shard_bytes(largest, 2), shard);
    }

    #[test]
    fn the_photo_that_ends_the_room_is_named() {
        let caps = [PART_HEADER + 1000, PART_HEADER + 100, PART_HEADER + 1000];
        let weights = [1, 1, 1];
        let largest = largest_encoded(&caps, &weights, None);
        assert_eq!(limiting(&caps, &weights, None, largest), Some(1));
        assert_eq!(limiting(&caps, &weights, Some(2), 0), Some(1));
    }
}
