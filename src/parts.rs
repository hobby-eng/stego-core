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
    /// The photo it was read from, by its place among the photos given.
    source: usize,
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
            source: 0,
        })
    }

    /// The part as read from photo `source`, by its place among the photos given.
    pub(crate) const fn at(mut self, source: usize) -> Self {
        self.source = source;
        self
    }

    pub(crate) const fn index(&self) -> u16 {
        self.index
    }

    /// What makes parts one set: the set, the scheme and, for a split, how many parts it has.
    /// A k-of-n set leaves out how many photos were issued, so photos added to it later join it.
    const fn identity(&self) -> ([u8; SET_BYTES], u8, u16) {
        let count = if self.scheme == THRESHOLD {
            0
        } else {
            self.count
        };
        (self.set, self.scheme, count)
    }

    pub(crate) const fn count(&self) -> u16 {
        self.count
    }
}

/// What the parts of one set give.
pub(crate) enum Assembly {
    /// Enough parts were there.
    Complete(Content),
    /// Parts are missing: `found` of the `needed`.
    Incomplete { found: usize, needed: usize },
    /// Two parts claim the same number with different contents, or the parts of a k-of-n set
    /// do not agree with each other.
    Conflict,
    /// The parts opened under the password but are not in a form this version writes.
    Unsupported,
}

/// What the parts found in the photos give: the outcome of one set and what else was there.
pub(crate) struct Assembled {
    /// The outcome of the set chosen.
    pub outcome: Assembly,
    /// The photos whose parts belong to that set, by the places given to [`Part::at`].
    pub sources: Vec<usize>,
    /// How many other sets the parts belonged to.
    pub others: usize,
}

/// Joins the parts by set and gives one set's outcome; `None` when there are no parts.
///
/// Every set is judged on its own, so a set that is wrong never hides one that is right. The
/// sets are tried from the one with the most parts down (among equals, the one whose first photo
/// was given first) and the first that is complete is the answer; when none is complete, the
/// answer is the outcome of the first set tried.
pub(crate) fn assemble(mut parts: Vec<Part>) -> Option<Assembled> {
    parts.sort_by_key(|p| (p.identity(), p.index, p.source));
    let mut sets: Vec<Vec<Part>> = Vec::new();
    for part in parts {
        match sets.last_mut() {
            Some(set) if set[0].identity() == part.identity() => set.push(part),
            _ => sets.push(vec![part]),
        }
    }
    sets.sort_by_key(|set| {
        let first_photo = set.iter().map(|p| p.source).min();
        (std::cmp::Reverse(distinct(set)), first_photo)
    });
    let others = sets.len().saturating_sub(1);
    let mut answer = None;
    for set in sets {
        let sources = set.iter().map(|p| p.source).collect();
        let assembled = Assembled {
            outcome: join(set),
            sources,
            others,
        };
        if matches!(assembled.outcome, Assembly::Complete(_)) {
            return Some(assembled);
        }
        if answer.is_none() {
            answer = Some(assembled);
        }
    }
    answer
}

/// Parts of `set`, which is sorted by number, with the same part read twice counted once.
fn distinct(set: &[Part]) -> usize {
    set.chunk_by(|a, b| a.index == b.index).count()
}

/// The outcome of the parts of one set, sorted by number.
fn join(mut set: Vec<Part>) -> Assembly {
    // The same part read twice (the same photo under two names) counts once; two different
    // parts under one number are a conflict, never a silent choice.
    let mut conflict = false;
    set.dedup_by(|a, b| {
        let same_place = a.index == b.index;
        conflict |= same_place && a.payload != b.payload;
        same_place
    });
    let Some(first) = set.first() else {
        return Assembly::Unsupported;
    };
    if conflict {
        return Assembly::Conflict;
    }
    let (identity, scheme) = (first.set, first.scheme);
    let payloads: Vec<(usize, &[u8])> = set
        .iter()
        .map(|p| (usize::from(p.index), p.payload.as_slice()))
        .collect();
    // What a k-of-n set needs is in its payloads, which are checked before they are believed.
    let needed = if scheme == THRESHOLD {
        match threshold::form(&payloads) {
            threshold::Form::Agreed { needed } => needed,
            threshold::Form::Inconsistent => return Assembly::Conflict,
            threshold::Form::Malformed => return Assembly::Unsupported,
        }
    } else {
        usize::from(first.count)
    };
    if set.len() < needed {
        return Assembly::Incomplete {
            found: set.len(),
            needed,
        };
    }
    let encoded = if scheme == THRESHOLD {
        match threshold::join(&payloads, &identity) {
            threshold::Joined::Message(encoded) => encoded,
            threshold::Joined::Malformed => return Assembly::Unsupported,
            // Enough authenticated parts that do not open together: report it, never "nothing".
            threshold::Joined::Inconsistent | threshold::Joined::Unreadable => {
                return Assembly::Conflict;
            }
        }
    } else {
        let mut joined = Zeroizing::new(Vec::new());
        for part in &set {
            joined.extend_from_slice(&part.payload);
        }
        joined
    };
    // The parts were whole and genuine, so a message that does not decode is another version's.
    Content::decode(&encoded).map_or(Assembly::Unsupported, Assembly::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::Counter;

    /// The outcome alone, for the tests that give one set.
    fn outcome(parts: Vec<Part>) -> Option<Assembly> {
        assemble(parts).map(|assembled| assembled.outcome)
    }

    /// `parts` as read from the photos at `places`.
    fn read_at(parts: &[Zeroizing<Vec<u8>>], places: std::ops::Range<usize>) -> Vec<Part> {
        parts
            .iter()
            .zip(places)
            .map(|(part, place)| Part::parse(part).unwrap().at(place))
            .collect()
    }

    #[test]
    fn a_whole_set_is_read_next_to_a_conflicting_one() {
        let good = Content::text("the good set").unwrap();
        let whole = spread(&good, &[1, 1], None, &mut Counter(8)).unwrap();
        let another = Content::text("another set").unwrap();
        let other = spread(&another, &[1, 1, 1], None, &mut Counter(9)).unwrap();
        let mut forged = other[1].to_vec();
        if let Some(last) = forged.last_mut() {
            *last ^= 1;
        }
        // Photos 0 to 2: a set with two different parts under one number. Photos 3 and 4: a
        // whole set.
        let mut parts = vec![
            Part::parse(&other[0]).unwrap().at(0),
            Part::parse(&other[1]).unwrap().at(1),
            Part::parse(&forged).unwrap().at(2),
        ];
        parts.extend(read_at(&whole, 3..5));
        let Some(Assembled {
            outcome: Assembly::Complete(back),
            sources,
            others,
        }) = assemble(parts)
        else {
            panic!("the whole set was not read");
        };
        assert!(back.same_as(&good));
        assert_eq!((sources, others), (vec![3, 4], 1));
    }

    #[test]
    fn of_two_whole_sets_the_larger_is_read_and_the_other_counted() {
        let small = Content::text("two photos").unwrap();
        let large = Content::text("three photos").unwrap();
        let two = spread(&small, &[1, 1], None, &mut Counter(10)).unwrap();
        let three = spread(&large, &[1, 1, 1], Some(2), &mut Counter(11)).unwrap();
        let mut parts = read_at(&two, 0..2);
        parts.extend(read_at(&three, 2..5));
        let Some(Assembled {
            outcome: Assembly::Complete(back),
            sources,
            others,
        }) = assemble(parts)
        else {
            panic!("no set was read");
        };
        assert!(back.same_as(&large));
        assert_eq!((sources, others), (vec![2, 3, 4], 1));
        // Of two sets of the same size, the one whose first photo was given first.
        let again = spread(&large, &[1, 1], None, &mut Counter(12)).unwrap();
        let mut parts = read_at(&again, 0..2);
        parts.extend(read_at(&two, 2..4));
        let Some(Assembled {
            outcome: Assembly::Complete(back),
            sources,
            ..
        }) = assemble(parts)
        else {
            panic!("no set was read");
        };
        assert!(back.same_as(&large));
        assert_eq!(sources, [0, 1]);
    }

    #[test]
    fn parts_this_version_does_not_write_are_unsupported() {
        let content = Content::text("abandon ability able").unwrap();
        // A k-of-n part moved under another photo's number: its share no longer carries it.
        let parts = spread(&content, &[1, 1, 1], Some(2), &mut Counter(13)).unwrap();
        let mut moved = parts[1].to_vec();
        moved[SET_BYTES + 1..SET_BYTES + 3].copy_from_slice(&2_u16.to_be_bytes());
        let read = vec![
            Part::parse(&parts[0]).unwrap(),
            Part::parse(&moved).unwrap(),
        ];
        assert!(matches!(outcome(read), Some(Assembly::Unsupported)));
        // A whole set whose message is of a kind this version does not know.
        let mut unknown = spread(&content, &[1], None, &mut Counter(14)).unwrap()[0].to_vec();
        unknown[PART_HEADER] = 0xff;
        let read = vec![Part::parse(&unknown).unwrap()];
        assert!(matches!(outcome(read), Some(Assembly::Unsupported)));
    }

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
        let Some(Assembly::Complete(back)) = outcome(read) else {
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
            outcome(read),
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
        let Some(Assembly::Complete(back)) = outcome(read) else {
            panic!("two of three did not restore");
        };
        assert!(back.same_as(&content));
        let one = vec![Part::parse(&parts[1]).unwrap()];
        assert!(matches!(
            outcome(one),
            Some(Assembly::Incomplete {
                found: 1,
                needed: 2
            })
        ));
    }

    #[test]
    fn a_threshold_part_issued_later_joins_its_set() {
        let content = Content::text("abandon ability able").unwrap();
        let parts = spread(&content, &[1, 1, 1], Some(2), &mut Counter(6)).unwrap();
        // The third photo as if it had been issued after the set grew to five.
        let mut later = parts[2].to_vec();
        later[SET_BYTES + 3..SET_BYTES + 5].copy_from_slice(&5_u16.to_be_bytes());
        let read = vec![
            Part::parse(&parts[0]).unwrap(),
            Part::parse(&later).unwrap(),
        ];
        let Some(Assembly::Complete(back)) = outcome(read) else {
            panic!("a part issued later did not join");
        };
        assert!(back.same_as(&content));
        // A split keeps its count: a slice that says otherwise is another set.
        let split = spread(&content, &[1, 1], None, &mut Counter(7)).unwrap();
        let mut other = split[1].to_vec();
        other[SET_BYTES + 3..SET_BYTES + 5].copy_from_slice(&3_u16.to_be_bytes());
        let read = vec![
            Part::parse(&split[0]).unwrap(),
            Part::parse(&other).unwrap(),
        ];
        assert!(matches!(
            outcome(read),
            Some(Assembly::Incomplete { found: 1, .. })
        ));
    }

    #[test]
    fn two_different_parts_under_one_number_are_a_conflict() {
        let content = Content::text("abandon ability able").unwrap();
        let first = spread(&content, &[1, 1], None, &mut Counter(5)).unwrap();
        let mut forged = first[1].to_vec();
        if let Some(last) = forged.last_mut() {
            *last ^= 1;
        }
        let read = vec![
            Part::parse(&first[0]).unwrap(),
            Part::parse(&first[1]).unwrap(),
            Part::parse(&forged).unwrap(),
        ];
        assert!(matches!(outcome(read), Some(Assembly::Conflict)));
    }
}
