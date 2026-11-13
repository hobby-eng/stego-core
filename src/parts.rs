//! A message spread over several photos. Each photo's record holds the set it belongs to, the
//! scheme, its number and the count, then its payload:
//! - split: a slice of the message; every photo is needed;
//! - threshold: a Reed–Solomon shard of the ciphertext and one key share; any `needed`
//!   photos suffice (`crate::threshold`).
//!
//! The photos may be read in any order.

use crate::content::Content;
use crate::random::Random;
use crate::{StegoError, threshold};
use zeroize::Zeroizing;

const SET_BYTES: usize = 16;
/// Bytes of a part's header: set, scheme, number and count.
pub(crate) const PART_HEADER: usize = SET_BYTES + 1 + 2 + 2;
/// Most photos in one set.
pub const CARRIERS_MAX: usize = 256;
const SPLIT: u8 = 1;
const THRESHOLD: u8 = 2;

/// One part as read from a photo.
pub(crate) struct Part {
    set: [u8; SET_BYTES],
    scheme: u8,
    index: u16,
    count: u16,
    payload: Zeroizing<Vec<u8>>,
}

/// The parts of `content` for photos with room `weights`: slices in proportion to the room when
/// `needed` is `None`, so that every photo carries the same rate; otherwise a k-of-n set.
pub(crate) fn spread(
    content: &Content,
    weights: &[usize],
    needed: Option<u8>,
    random: &mut dyn Random,
) -> Result<Vec<Zeroizing<Vec<u8>>>, StegoError> {
    let count = u16::try_from(weights.len())
        .ok()
        .filter(|&n| n > 0 && usize::from(n) <= CARRIERS_MAX)
        .ok_or(StegoError::Carriers)?;
    let mut set = [0; SET_BYTES];
    random.fill(&mut set)?;
    let encoded = content.encoded();
    let (scheme, payloads) = match needed {
        Some(needed) => (
            THRESHOLD,
            threshold::split(&encoded, needed, weights.len(), &set, random)?,
        ),
        None => (SPLIT, slices(&encoded, weights)),
    };
    Ok((0_u16..)
        .zip(payloads)
        .map(|(index, payload)| {
            let mut part = Zeroizing::new(Vec::with_capacity(PART_HEADER + payload.len()));
            part.extend_from_slice(&set);
            part.push(scheme);
            part.extend_from_slice(&index.to_be_bytes());
            part.extend_from_slice(&count.to_be_bytes());
            part.extend_from_slice(&payload);
            part
        })
        .collect())
}

fn slices(encoded: &[u8], weights: &[usize]) -> Vec<Zeroizing<Vec<u8>>> {
    let total: u128 = weights.iter().map(|&w| w as u128).sum::<u128>().max(1);
    let mut start = 0;
    let mut cumulative: u128 = 0;
    weights
        .iter()
        .enumerate()
        .map(|(index, &weight)| {
            cumulative += weight as u128;
            let end = if index + 1 == weights.len() {
                encoded.len()
            } else {
                // At most `encoded.len()`: cumulative <= total.
                (encoded.len() as u128 * cumulative / total) as usize
            };
            let slice = Zeroizing::new(encoded[start..end].to_vec());
            start = end;
            slice
        })
        .collect()
}

impl Part {
    /// Reads a part's header; `None` for a record that holds none.
    pub(crate) fn parse(plain: &[u8]) -> Option<Self> {
        let header = plain.get(..PART_HEADER)?;
        let set: [u8; SET_BYTES] = header[..SET_BYTES].try_into().ok()?;
        let scheme = header[SET_BYTES];
        let index = u16::from_be_bytes([header[SET_BYTES + 1], header[SET_BYTES + 2]]);
        let count = u16::from_be_bytes([header[SET_BYTES + 3], header[SET_BYTES + 4]]);
        (index < count && matches!(scheme, SPLIT | THRESHOLD)).then(|| Self {
            set,
            scheme,
            index,
            count,
            payload: Zeroizing::new(plain[PART_HEADER..].to_vec()),
        })
    }

    pub(crate) const fn index(&self) -> u16 {
        self.index
    }

    pub(crate) const fn count(&self) -> u16 {
        self.count
    }

    /// Photos needed to read the set.
    pub(crate) fn needed(&self) -> usize {
        if self.scheme == THRESHOLD {
            threshold::needed(&self.payload).map_or(usize::from(self.count), usize::from)
        } else {
            usize::from(self.count)
        }
    }
}

/// What a set of parts gives.
pub(crate) enum Assembly {
    /// Enough parts were there.
    Complete(Content),
    /// Parts are missing: `found` of the `needed`.
    Incomplete { found: usize, needed: usize },
}

/// Joins the parts of the first set found; parts of other sets are ignored.
pub(crate) fn assemble(mut parts: Vec<Part>) -> Option<Assembly> {
    let first = parts.first()?;
    let (set, scheme, count) = (first.set, first.scheme, first.count);
    let needed = first.needed();
    parts.retain(|p| p.set == set && p.scheme == scheme && p.count == count);
    parts.sort_by_key(|p| p.index);
    parts.dedup_by_key(|p| p.index);
    if parts.len() < needed {
        return Some(Assembly::Incomplete {
            found: parts.len(),
            needed,
        });
    }
    let encoded = if scheme == THRESHOLD {
        let payloads: Vec<(usize, &[u8])> = parts
            .iter()
            .map(|p| (usize::from(p.index), p.payload.as_slice()))
            .collect();
        threshold::join(&payloads, usize::from(count), &set)?
    } else {
        let mut joined = Zeroizing::new(Vec::new());
        for part in &parts {
            joined.extend_from_slice(&part.payload);
        }
        joined
    };
    Content::decode(&encoded).map(Assembly::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::Counter;

    #[test]
    fn slices_follow_the_weights_and_join_in_any_order() {
        let content = Content::text(&"x".repeat(1000)).unwrap();
        let parts = spread(&content, &[1, 3], None, &mut Counter(1)).unwrap();
        // 1002 encoded bytes: a quarter and three quarters.
        assert_eq!(parts[0].len() - PART_HEADER, 250);
        assert_eq!(parts[1].len() - PART_HEADER, 752);
        let read: Vec<Part> = parts
            .iter()
            .rev()
            .map(|p| Part::parse(p).unwrap())
            .collect();
        let Some(Assembly::Complete(back)) = assemble(read) else {
            panic!("the set did not join");
        };
        assert!(back.same_as(&content));
    }

    #[test]
    fn a_missing_slice_is_reported_not_guessed() {
        let content = Content::text("abandon ability able").unwrap();
        let parts = spread(&content, &[1, 1, 1], None, &mut Counter(2)).unwrap();
        let read = vec![
            Part::parse(&parts[2]).unwrap(),
            Part::parse(&parts[0]).unwrap(),
        ];
        assert!(matches!(
            assemble(read),
            Some(Assembly::Incomplete {
                found: 2,
                needed: 3
            })
        ));
    }

    #[test]
    fn two_of_three_photos_restore_a_threshold_set() {
        let content = Content::file("seed.txt", b"abandon ability able".to_vec()).unwrap();
        let parts = spread(&content, &[1, 1, 1], Some(2), &mut Counter(4)).unwrap();
        let read = vec![
            Part::parse(&parts[2]).unwrap(),
            Part::parse(&parts[0]).unwrap(),
        ];
        let Some(Assembly::Complete(back)) = assemble(read) else {
            panic!("two of three did not restore");
        };
        assert!(back.same_as(&content));
        let one = vec![Part::parse(&parts[1]).unwrap()];
        assert!(matches!(
            assemble(one),
            Some(Assembly::Incomplete {
                found: 1,
                needed: 2
            })
        ));
    }
}
