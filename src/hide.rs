//! Hiding: the message is split over the photos, each photo gets its record, and the new files
//! are returned only after the whole set reads back with every password and the same SHA-256.

use crate::coding::{Lane, directional, write_binary, write_coins, write_hidden, write_ternary};
use crate::content::Content;
use crate::cover::{Cover, MAX_BITS_PER_SITE, RECOMMENDED_BPNZAC};
use crate::keys::Keys;
use crate::mode::{CostModel, Mode, Settings};
use crate::parts::{CARRIERS_MAX, spread};
use crate::random::Random;
use crate::record::{associated, bodies, body_for, record_bits, seal, to_bits};
use crate::report::{Digest, FileReport, HideReport, Layer, RecordReport, parameters};
use crate::reveal::{Reading, reveal};
use crate::sites::{SiteRule, Sites};
use crate::{Password, StegoError};

/// A message and the password that will open it.
#[derive(Clone, Copy, Debug)]
pub struct Secret<'a> {
    /// The text or file.
    pub content: &'a Content,
    /// Its password.
    pub password: &'a Password,
}

/// The new photos, in the order of the covers, with the report of the job.
#[derive(Debug)]
pub struct HideResult {
    files: Vec<Vec<u8>>,
    report: HideReport,
}

impl HideResult {
    /// The new file of each cover, in the order given. Save each byte for byte.
    #[must_use]
    pub fn files(&self) -> &[Vec<u8>] {
        &self.files
    }

    /// The technical report.
    #[must_use]
    pub const fn report(&self) -> &HideReport {
        &self.report
    }
}

/// What one photo's write produced, before its report.
struct Written {
    bytes: Vec<u8>,
    sites: usize,
    nonzero_ac: usize,
    changes: usize,
    free: Option<usize>,
    coded_bits: usize,
    secret: RecordReport,
    decoy: Option<RecordReport>,
}

/// The photos chosen for writing: between 1 and [`CARRIERS_MAX`], each a different file. The
/// room ([`crate::fit`]) and the writing apply the same check, so the room never counts a photo
/// that writing would refuse.
pub(crate) fn check_carriers(covers: &[&Cover]) -> Result<(), StegoError> {
    if covers.is_empty() || covers.len() > CARRIERS_MAX {
        return Err(StegoError::Carriers);
    }
    let mut seen: Vec<&[u8; 32]> = covers.iter().map(|c| c.sha256()).collect();
    seen.sort_unstable();
    if seen.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StegoError::DuplicatePhoto);
    }
    Ok(())
}

/// Hides `secret` (and in the decoy mode `decoy`) in `covers`.
///
/// # Errors
///
/// [`StegoError::Carriers`], [`StegoError::DuplicatePhoto`], [`StegoError::DecoyChoice`] or
/// [`StegoError::PasswordsEqual`] for a wrong request; [`StegoError::MessageLong`] or
/// [`StegoError::HiddenLong`] when a message does not fit; [`StegoError::Verification`] when the
/// new files do not read back exactly.
pub fn hide(
    covers: &[&Cover],
    settings: &Settings,
    secret: Secret<'_>,
    decoy: Option<Secret<'_>>,
    random: &mut dyn Random,
) -> Result<HideResult, StegoError> {
    check_carriers(covers)?;
    let weights: Vec<usize> = covers
        .iter()
        .map(|c| {
            Sites::find(c.jpeg(), c.jpeg().luma(), settings.rule())
                .positions
                .len()
        })
        .collect();
    let secret_parts = spread(secret.content, &weights, settings.needed, random)?;
    let written: Vec<Written> = match (settings.mode, decoy) {
        (Mode::Standard, None) => covers
            .iter()
            .zip(&secret_parts)
            .map(|(cover, part)| {
                let keys = Keys::derive(secret.password, cover.context())?;
                write_standard(cover, &keys, settings, part, random)
            })
            .collect::<Result<_, _>>()?,
        (Mode::Decoy, Some(decoy)) => {
            if decoy.password.same_as(secret.password) {
                return Err(StegoError::PasswordsEqual);
            }
            let decoy_parts = spread(decoy.content, &weights, settings.needed, random)?;
            covers
                .iter()
                .zip(decoy_parts.iter().zip(&secret_parts))
                .map(|(cover, (decoy_part, secret_part))| {
                    let decoy_keys = Keys::derive(decoy.password, cover.context())?;
                    let secret_keys = Keys::derive(secret.password, cover.context())?;
                    let pair = Pair {
                        decoy_keys: &decoy_keys,
                        decoy_part,
                        behind: Some((&secret_keys, secret_part.as_slice())),
                    };
                    write_decoy(cover, settings, &pair, random)
                })
                .collect::<Result<_, _>>()?
        }
        // A lone message in the decoy mode's form: its directions are coins, so the file looks
        // the same as one that carries a secret behind its message.
        (Mode::Decoy, None) => covers
            .iter()
            .zip(&secret_parts)
            .map(|(cover, part)| {
                let keys = Keys::derive(secret.password, cover.context())?;
                let pair = Pair {
                    decoy_keys: &keys,
                    decoy_part: part,
                    behind: None,
                };
                write_decoy(cover, settings, &pair, random)
            })
            .collect::<Result<_, _>>()?,
        (Mode::Standard, Some(_)) => return Err(StegoError::DecoyChoice),
    };
    finish(written, settings, secret, decoy)
}

/// Reads the new set back with every password and builds the report.
fn finish(
    written: Vec<Written>,
    settings: &Settings,
    secret: Secret<'_>,
    decoy: Option<Secret<'_>>,
) -> Result<HideResult, StegoError> {
    let covers: Vec<Cover> = written
        .iter()
        .map(|w| Cover::new(w.bytes.clone()))
        .collect::<Result<_, _>>()
        .map_err(|_| StegoError::Verification)?;
    let refs: Vec<&Cover> = covers.iter().collect();
    for expected in std::iter::once(secret).chain(decoy) {
        match reveal(&refs, expected.password)? {
            Reading::Complete(read)
                if read.content().same_as(expected.content)
                    && read.content().sha256() == expected.content.sha256() => {}
            _ => return Err(StegoError::Verification),
        }
    }
    let total = u16::try_from(written.len()).map_err(|_| StegoError::Carriers)?;
    let files = written
        .iter()
        .zip(&covers)
        .zip(0_u16..)
        .map(|((w, cover), index)| FileReport {
            photo: cover.info(),
            sites: w.sites,
            changes: w.changes,
            free_changes: w.free,
            bits_per_nonzero_ac: w.coded_bits as f64 / w.nonzero_ac.max(1) as f64,
            secret: RecordReport {
                part: index,
                parts: total,
                kdf_memory_kib: secret.password.work().memory_kib(),
                kdf_passes: secret.password.work().passes(),
                ..w.secret
            },
            decoy: w.decoy.zip(decoy).map(|(d, owner)| RecordReport {
                part: index,
                parts: total,
                kdf_memory_kib: owner.password.work().memory_kib(),
                kdf_passes: owner.password.work().passes(),
                ..d
            }),
        })
        .collect();
    let report = HideReport {
        settings: *settings,
        files,
        secret_bytes: secret.content.bytes().len(),
        secret_sha256: Digest::new(secret.content.sha256()),
        decoy: decoy.map(|d| (d.content.bytes().len(), Digest::new(d.content.sha256()))),
        parameters: parameters(),
    };
    Ok(HideResult {
        files: written.into_iter().map(|w| w.bytes).collect(),
        report,
    })
}

/// The costs of every site in lane order.
fn lane_costs(
    cover: &Cover,
    model: CostModel,
    sites: &Sites,
    directions: &[(bool, bool)],
    bits: usize,
    order: &[u32],
) -> Result<crate::algorithm::model::Costs, StegoError> {
    let any: Vec<bool> = directions.iter().map(|&(up, down)| up || down).collect();
    let base = model.costs(&cover.plane()?, &sites.positions, &any, bits)?;
    Ok(directional(&base, directions, order))
}

fn limit_bits(sites: &Sites) -> usize {
    (sites.positions.len() as f64 * MAX_BITS_PER_SITE) as usize
}

const fn record(layer: Layer, site_rule: SiteRule, body: usize, part_bytes: usize) -> RecordReport {
    RecordReport {
        layer,
        site_rule,
        body_bytes: body,
        record_bits: record_bits(body),
        part: 0,
        parts: 1,
        part_bytes,
        kdf_memory_kib: 0,
        kdf_passes: 0,
    }
}

/// `cover` with `plain` as its record under `password`, written as the standard mode writes it:
/// for tests of what a reader makes of a record this version would not write.
#[cfg(test)]
pub(crate) fn write_plain(
    cover: &Cover,
    password: &crate::Password,
    plain: &[u8],
    random: &mut dyn Random,
) -> Result<Vec<u8>, StegoError> {
    let keys = Keys::derive(password, cover.context())?;
    write_standard(cover, &keys, &Settings::default(), plain, random).map(|written| written.bytes)
}

fn write_standard(
    cover: &Cover,
    keys: &Keys,
    settings: &Settings,
    plain: &[u8],
    random: &mut dyn Random,
) -> Result<Written, StegoError> {
    let (jpeg, luma, rule) = (cover.jpeg(), cover.jpeg().luma(), settings.rule());
    let sites = Sites::find(jpeg, luma, rule);
    let body = body_for(plain.len())?;
    let bits = record_bits(body);
    if bits > limit_bits(&sites) {
        return Err(StegoError::MessageLong);
    }
    let directions = sites.directions(jpeg, luma, rule);
    let keys = keys.layer(Layer::Standard, rule.id())?;
    let order = keys.order(sites.positions.len())?;
    let costs = lane_costs(
        cover,
        settings.cost_model,
        &sites,
        &directions,
        bits,
        &order,
    )?;
    // Each per-site buffer goes as soon as its last use is done: the trellis is the peak.
    drop(directions);
    let lane = Lane::new(&sites, luma, &order);
    drop(order);
    let (site_count, nonzero_ac) = (sites.positions.len(), sites.nonzero_ac);
    drop(sites);
    let aad = associated(cover.context(), Layer::Standard.id(), rule.id(), body);
    let sealed = seal(plain, body, keys.cipher(), &aad, random)?;
    let result = write_ternary(
        &lane,
        &costs,
        &to_bits(&sealed),
        keys.coder,
        settings.workers,
    )?;
    let mut out = luma.to_vec();
    let changes = lane.apply(&result.stego, &mut out)?;
    Ok(Written {
        bytes: jpeg.encode(&out)?,
        sites: site_count,
        nonzero_ac,
        changes,
        free: None,
        coded_bits: bits,
        secret: record(
            Layer::Standard,
            rule,
            body,
            plain.len() - crate::parts::PART_HEADER,
        ),
        decoy: None,
    })
}

/// The keys and parts of one photo in the decoy mode.
struct Pair<'a> {
    decoy_keys: &'a Keys,
    decoy_part: &'a [u8],
    /// The secret's keys and part, when one hides behind the decoy.
    behind: Option<(&'a Keys, &'a [u8])>,
}

/// The decoy's body: its own size, padded up to the photo's recommended room. The padding
/// depends on the photo alone, never on a secret behind the decoy, so the decoy password shows
/// the same size whether or not a secret exists.
fn decoy_body(sites: &Sites, part: usize) -> Result<usize, StegoError> {
    let recommended =
        ((sites.nonzero_ac as f64 * RECOMMENDED_BPNZAC) as usize).min(limit_bits(sites));
    let own = body_for(part)?;
    let padded = bodies()
        .take_while(|&b| record_bits(b) <= recommended)
        .last()
        .unwrap_or(own);
    Ok(own.max(padded))
}

fn write_decoy(
    cover: &Cover,
    settings: &Settings,
    pair: &Pair<'_>,
    random: &mut dyn Random,
) -> Result<Written, StegoError> {
    let (jpeg, luma, rule) = (cover.jpeg(), cover.jpeg().luma(), SiteRule::Grow1);
    let sites = Sites::find(jpeg, luma, rule);
    let body = decoy_body(&sites, pair.decoy_part.len())?;
    let bits = record_bits(body);
    if bits > limit_bits(&sites) {
        return Err(StegoError::MessageLong);
    }
    let decoy_keys = pair.decoy_keys.layer(Layer::Decoy, rule.id())?;
    let directions = sites.directions(jpeg, luma, rule);
    let order = decoy_keys.order(sites.positions.len())?;
    let costs = lane_costs(
        cover,
        settings.cost_model,
        &sites,
        &directions,
        bits,
        &order,
    )?;
    drop(directions);
    let lane = Lane::new(&sites, luma, &order);
    drop(order);
    let aad = associated(cover.context(), Layer::Decoy.id(), rule.id(), body);
    let sealed = seal(pair.decoy_part, body, decoy_keys.cipher(), &aad, random)?;
    let mut write = write_binary(
        &lane,
        &costs,
        &to_bits(&sealed),
        decoy_keys.coder,
        settings.workers,
    )?;
    let free = write.free.len();
    let header = crate::parts::PART_HEADER;
    let secret = match pair.behind {
        Some((secret_keys, secret_part)) => {
            let hidden_body = body_for(secret_part.len())?;
            let hidden_keys = secret_keys.layer(Layer::Hidden, rule.id())?;
            let hidden_aad =
                associated(cover.context(), Layer::Hidden.id(), rule.id(), hidden_body);
            let hidden = seal(
                secret_part,
                hidden_body,
                hidden_keys.cipher(),
                &hidden_aad,
                random,
            )?;
            write_hidden(
                &lane,
                &mut write,
                &to_bits(&hidden),
                hidden_keys.coder,
                random,
            )?;
            record(Layer::Hidden, rule, hidden_body, secret_part.len() - header)
        }
        None => {
            write_coins(&mut write, random)?;
            record(Layer::Decoy, rule, body, pair.decoy_part.len() - header)
        }
    };
    let mut out = luma.to_vec();
    let changes = lane.apply(&write.stego, &mut out)?;
    Ok(Written {
        bytes: jpeg.encode(&out)?,
        sites: sites.positions.len(),
        nonzero_ac: sites.nonzero_ac,
        changes,
        free: Some(free),
        coded_bits: bits,
        secret,
        decoy: pair
            .behind
            .map(|_| record(Layer::Decoy, rule, body, pair.decoy_part.len() - header)),
    })
}
