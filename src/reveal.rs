//! Reading: a password tries every layer, site rule and record size of every photo given.
//!
//! Nothing in a photo says which layer or size holds a record, so the reader tries them all;
//! only the right password, layer, rule and size pass the record's tag.

use crate::coding::{
    BinaryReader, HIDDEN_CAP, Lane, TernaryReader, hidden_syndrome, syndrome_bits,
};
use crate::content::Content;
use crate::cover::{Cover, MAX_BITS_PER_SITE};
use crate::keys::Keys;
use crate::parts::{Assembled, Assembly, CARRIERS_MAX, Part, assemble};
use crate::record::{associated, bodies, from_bits, open, record_bits};
use crate::report::{Digest, Layer, ReadReport, RecordReport, parameters};
use crate::sites::{SiteRule, Sites};
use crate::{Password, StegoError};
use zeroize::Zeroizing;

/// What a password opened in the photos given.
///
/// The photos may hold more than one set under the same password. Every set is judged on its
/// own and one is answered for: a whole message if any set gives one, taking the set with the
/// most photos and, among equals, the one whose first photo was given first; otherwise the
/// state of the set with the most photos. [`ReadReport::other_sets`] counts what else the
/// password opened, and [`ReadReport::files`] names the photos of the set that was read, so a
/// host can ask for the others to be read apart.
#[derive(Debug)]
pub enum Reading {
    /// No photo opened. A photo without any record gives the same answer.
    Nothing,
    /// Parts opened but others are missing: add the other photos of the set.
    Incomplete {
        /// Parts found.
        found: usize,
        /// Parts in the set.
        needed: usize,
    },
    /// The whole message.
    Complete(Revealed),
    /// Two photos carry different parts under one number, or the parts do not agree: photos of
    /// two different sets were mixed, or one was altered.
    Conflict,
    /// The password opened a record, so it is right, but what the record holds is not in a form
    /// this version reads, as a record of another version of the program would be. The tag
    /// says the record is whole, not who wrote it.
    Unsupported,
}

/// A message that opened, with its technical report.
#[derive(Debug)]
pub struct Revealed {
    content: Content,
    report: ReadReport,
}

impl Revealed {
    /// The text or file.
    #[must_use]
    pub const fn content(&self) -> &Content {
        &self.content
    }

    /// Takes the content out.
    #[must_use]
    pub fn into_content(self) -> Content {
        self.content
    }

    /// The technical report.
    #[must_use]
    pub const fn report(&self) -> &ReadReport {
        &self.report
    }
}

/// Opens what `password` protects in `covers`, which may be given in any order.
///
/// # Errors
///
/// [`StegoError::Carriers`] for no photos or too many, [`StegoError::Crypto`] when the key
/// derivation fails.
pub fn reveal(covers: &[&Cover], password: &Password) -> Result<Reading, StegoError> {
    if covers.is_empty() || covers.len() > CARRIERS_MAX {
        return Err(StegoError::Carriers);
    }
    let mut parts = Vec::new();
    let mut files = Vec::new();
    // Records that opened without a part this version knows: the tag says they are whole, so
    // they are reported as a form this version does not read, never passed over as if nothing
    // had opened.
    let mut unknown = 0;
    let mut seen: Vec<&[u8; 32]> = Vec::with_capacity(covers.len());
    for (index, cover) in covers.iter().enumerate() {
        // The same file given twice (from two folders, say) is read once.
        if seen.contains(&cover.sha256()) {
            continue;
        }
        seen.push(cover.sha256());
        let Some(found) = open_one(cover, password)? else {
            continue;
        };
        let Some(part) = Part::parse(&found.plain) else {
            unknown += 1;
            continue;
        };
        files.push((
            index,
            cover.info(),
            RecordReport {
                layer: found.layer,
                site_rule: found.rule,
                body_bytes: found.body,
                record_bits: record_bits(found.body),
                part: part.index(),
                parts: part.count(),
                part_bytes: found.plain.len() - crate::parts::PART_HEADER,
                kdf_memory_kib: password.work().memory_kib(),
                kdf_passes: password.work().passes(),
            },
        ));
        parts.push(part.at(index));
    }
    let Some(Assembled {
        outcome,
        sources,
        others,
    }) = assemble(parts)
    else {
        return Ok(if unknown > 0 {
            Reading::Unsupported
        } else {
            Reading::Nothing
        });
    };
    Ok(match outcome {
        Assembly::Incomplete { found, needed } => Reading::Incomplete { found, needed },
        Assembly::Conflict => Reading::Conflict,
        Assembly::Unsupported => Reading::Unsupported,
        Assembly::Complete(content) => {
            files.retain(|(index, ..)| sources.contains(index));
            let report = ReadReport {
                files,
                other_sets: others + unknown,
                content_bytes: content.bytes().len(),
                sha256: Digest::new(content.sha256()),
                parameters: parameters(),
            };
            Reading::Complete(Revealed { content, report })
        }
    })
}

/// A record that opened in one photo.
pub(crate) struct Found {
    pub plain: Zeroizing<Vec<u8>>,
    pub layer: Layer,
    pub rule: SiteRule,
    pub body: usize,
}

/// Tries every layer of one photo.
pub(crate) fn open_one(cover: &Cover, password: &Password) -> Result<Option<Found>, StegoError> {
    let keys = Keys::derive(password, cover.context())?;
    if let Some(found) = standard(cover, &keys)? {
        return Ok(Some(found));
    }
    if let Some(found) = decoy(cover, &keys)? {
        return Ok(Some(found));
    }
    hidden(cover, &keys)
}

/// Bodies whose records fit `sites` at the coders' highest rate.
fn feasible(sites: usize) -> impl Iterator<Item = usize> {
    let limit = (sites as f64 * MAX_BITS_PER_SITE) as usize;
    bodies().take_while(move |&body| record_bits(body) <= limit)
}

fn standard(cover: &Cover, keys: &Keys) -> Result<Option<Found>, StegoError> {
    let luma = cover.jpeg().luma();
    for rule in SiteRule::ALL {
        let sites = Sites::find(cover.jpeg(), luma, rule);
        let lane_keys = keys.layer(Layer::Standard, rule.id())?;
        let order = lane_keys.order(sites.positions.len())?;
        let lane = Lane::new(&sites, luma, &order);
        let reader = TernaryReader::new(&lane.values, lane_keys.coder);
        for body in feasible(sites.positions.len()) {
            let bits = reader.read(record_bits(body));
            let aad = associated(cover.context(), Layer::Standard.id(), rule.id(), body);
            if let Some(plain) = open(&from_bits(&bits), lane_keys.cipher(), &aad) {
                return Ok(Some(Found {
                    plain,
                    layer: Layer::Standard,
                    rule,
                    body,
                }));
            }
        }
    }
    Ok(None)
}

fn decoy(cover: &Cover, keys: &Keys) -> Result<Option<Found>, StegoError> {
    let luma = cover.jpeg().luma();
    let rule = SiteRule::Grow1;
    let sites = Sites::find(cover.jpeg(), luma, rule);
    let lane_keys = keys.layer(Layer::Decoy, rule.id())?;
    let order = lane_keys.order(sites.positions.len())?;
    let lane = Lane::new(&sites, luma, &order);
    let reader = BinaryReader::new(&lane.values, lane_keys.coder);
    for body in feasible(sites.positions.len()) {
        let bits = reader.read(record_bits(body));
        let aad = associated(cover.context(), Layer::Decoy.id(), rule.id(), body);
        if let Some(plain) = open(&from_bits(&bits), lane_keys.cipher(), &aad) {
            return Ok(Some(Found {
                plain,
                layer: Layer::Decoy,
                rule,
                body,
            }));
        }
    }
    Ok(None)
}

fn hidden(cover: &Cover, keys: &Keys) -> Result<Option<Found>, StegoError> {
    let luma = cover.jpeg().luma();
    let rule = SiteRule::Grow1;
    let sites = Sites::find(cover.jpeg(), luma, rule);
    let lane_keys = keys.layer(Layer::Hidden, rule.id())?;
    let candidates: Vec<usize> = feasible(sites.positions.len())
        .take_while(|&body| record_bits(body) <= HIDDEN_CAP)
        .collect();
    let Some(&largest) = candidates.last() else {
        return Ok(None);
    };
    // One syndrome of the largest size serves every smaller one as its prefix.
    let words = hidden_syndrome(&sites, luma, lane_keys.coder, record_bits(largest));
    for body in candidates {
        let bits = syndrome_bits(&words, record_bits(body));
        let aad = associated(cover.context(), Layer::Hidden.id(), rule.id(), body);
        if let Some(plain) = open(&from_bits(&bits), lane_keys.cipher(), &aad) {
            return Ok(Some(Found {
                plain,
                layer: Layer::Hidden,
                rule,
                body,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::Counter;

    #[test]
    fn a_record_of_another_version_is_unsupported_and_never_nothing() {
        let cover = Cover::new(crate::self_test::sample_photo()).unwrap();
        let password = Password::new("public-test-password").unwrap();
        // A part header with a scheme this version does not know, then some body: the tag opens,
        // so the password is right, and the record is another version's.
        let mut plain = vec![7; 16];
        plain.extend([9, 0, 0, 0, 1]);
        plain.extend(b"from another version");
        let file = crate::hide::write_plain(&cover, &password, &plain, &mut Counter(21)).unwrap();
        let written = Cover::new(file).unwrap();
        assert!(matches!(
            reveal(&[&written], &password),
            Ok(Reading::Unsupported)
        ));
        // A wrong password learns nothing, not even that a record is there.
        let other = Password::new("another public password").unwrap();
        assert!(matches!(reveal(&[&written], &other), Ok(Reading::Nothing)));
    }
}
