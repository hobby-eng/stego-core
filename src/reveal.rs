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
use crate::parts::{Assembly, CARRIERS_MAX, Part, assemble};
use crate::record::{associated, bodies, from_bits, open, record_bits};
use crate::report::{Digest, Layer, ReadReport, RecordReport, parameters};
use crate::sites::{SiteRule, Sites};
use crate::{Password, StegoError};
use zeroize::Zeroizing;

/// What a password opened in a set of photos.
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
    for (index, cover) in covers.iter().enumerate() {
        let Some(found) = open_one(cover, password)? else {
            continue;
        };
        let Some(part) = Part::parse(&found.plain) else {
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
        parts.push(part);
    }
    Ok(match assemble(parts) {
        None => Reading::Nothing,
        Some(Assembly::Incomplete { found, needed }) => Reading::Incomplete { found, needed },
        Some(Assembly::Complete(content)) => {
            let report = ReadReport {
                files,
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
