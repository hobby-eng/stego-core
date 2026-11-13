//! Hiding: the message is split over the photos, each photo gets its record, and the new files
//! are returned only after the whole set reads back with every password and the same SHA-256.

use crate::coding::{
    HIDDEN_CAP, HIDDEN_MARGIN, Lane, directional, write_binary, write_hidden, write_ternary,
};
use crate::content::Content;
use crate::cover::{Cover, HIDDEN_SHARE, MAX_BITS_PER_SITE};
use crate::keys::Keys;
use crate::mode::{CostModel, Mode, Settings};
use crate::parts::{CARRIERS_MAX, spread};
use crate::random::Random;
use crate::record::{associated, bodies, body_for, record_bits, seal, to_bits};
use crate::report::{FileReport, HideReport, Layer, RecordReport, parameters};
use crate::reveal::{Reading, reveal};
use crate::sites::{SiteRule, Sites};
use crate::{Password, StegoError};

/// Decoy sizes tried in turn when the decoy's changes leave too little room for the secret.
const DECOY_ATTEMPTS: usize = 8;

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

/// Hides `secret` (and in the decoy mode `decoy`) in `covers`.
///
/// # Errors
///
/// [`StegoError::Carriers`], [`StegoError::DecoyChoice`] or [`StegoError::PasswordsEqual`] for a
/// wrong request; [`StegoError::MessageLong`] or [`StegoError::HiddenLong`] when a message does
/// not fit; [`StegoError::Verification`] when the new files do not read back exactly.
pub fn hide(
    covers: &[&Cover],
    settings: &Settings,
    secret: Secret<'_>,
    decoy: Option<Secret<'_>>,
    random: &mut dyn Random,
) -> Result<HideResult, StegoError> {
    if covers.is_empty() || covers.len() > CARRIERS_MAX {
        return Err(StegoError::Carriers);
    }
    let weights: Vec<usize> = covers
        .iter()
        .map(|c| Sites::find(c.jpeg(), c.jpeg().luma(), settings.rule()).nonzero_ac)
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
                        secret_keys: &secret_keys,
                        decoy_part,
                        secret_part,
                    };
                    write_decoy(cover, settings, &pair, random)
                })
                .collect::<Result<_, _>>()?
        }
        _ => return Err(StegoError::DecoyChoice),
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
                ..w.secret
            },
            decoy: w.decoy.map(|d| RecordReport {
                part: index,
                parts: total,
                ..d
            }),
        })
        .collect();
    let report = HideReport {
        settings: *settings,
        files,
        secret_bytes: secret.content.bytes().len(),
        secret_sha256: secret.content.sha256(),
        decoy: decoy.map(|d| (d.content.bytes().len(), d.content.sha256())),
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
    }
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
    let lane = Lane::new(&sites, luma, &order);
    let costs = lane_costs(
        cover,
        settings.cost_model,
        &sites,
        &directions,
        bits,
        &order,
    )?;
    let aad = associated(cover.context(), Layer::Standard.id(), rule.id(), body);
    let sealed = seal(plain, body, &keys.cipher, &aad, random)?;
    let result = write_ternary(&lane, &costs, &to_bits(&sealed), keys.coder)?;
    let mut out = luma.to_vec();
    let changes = lane.apply(&result.stego, &mut out)?;
    Ok(Written {
        bytes: jpeg.encode(&out)?,
        sites: sites.positions.len(),
        nonzero_ac: sites.nonzero_ac,
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
    secret_keys: &'a Keys,
    decoy_part: &'a [u8],
    secret_part: &'a [u8],
}

fn write_decoy(
    cover: &Cover,
    settings: &Settings,
    pair: &Pair<'_>,
    random: &mut dyn Random,
) -> Result<Written, StegoError> {
    let (jpeg, luma, rule) = (cover.jpeg(), cover.jpeg().luma(), SiteRule::Grow1);
    let sites = Sites::find(jpeg, luma, rule);
    let hidden_body = body_for(pair.secret_part.len())?;
    let hidden_bits = record_bits(hidden_body);
    if hidden_bits > HIDDEN_CAP {
        return Err(StegoError::HiddenLong);
    }
    let needed_free = hidden_bits + HIDDEN_MARGIN;
    let decoy_keys = pair.decoy_keys.layer(Layer::Decoy, rule.id())?;
    let hidden_keys = pair.secret_keys.layer(Layer::Hidden, rule.id())?;
    let directions = sites.directions(jpeg, luma, rule);
    let order = decoy_keys.order(sites.positions.len())?;
    let lane = Lane::new(&sites, luma, &order);
    let smallest = body_for(pair.decoy_part.len())?;
    if record_bits(smallest) > limit_bits(&sites) {
        return Err(StegoError::MessageLong);
    }
    // A decoy is padded until its expected changes leave room for the secret behind it.
    let payload_free = matches!(settings.cost_model, CostModel::JUniward | CostModel::Uerd);
    let mut cached = None;
    for body in bodies()
        .filter(|&b| b >= smallest && record_bits(b) as f64 * HIDDEN_SHARE >= needed_free as f64)
        .take(DECOY_ATTEMPTS)
    {
        let bits = record_bits(body);
        if bits > limit_bits(&sites) {
            break;
        }
        let costs = match (&cached, payload_free) {
            (Some(costs), true) => crate::algorithm::model::Costs::clone(costs),
            _ => lane_costs(
                cover,
                settings.cost_model,
                &sites,
                &directions,
                bits,
                &order,
            )?,
        };
        if payload_free {
            cached = Some(costs.clone());
        }
        let aad = associated(cover.context(), Layer::Decoy.id(), rule.id(), body);
        let sealed = seal(pair.decoy_part, body, &decoy_keys.cipher, &aad, random)?;
        let mut write = write_binary(&lane, &costs, &to_bits(&sealed), decoy_keys.coder)?;
        if write.free.len() < needed_free {
            continue;
        }
        let free = write.free.len();
        let hidden_aad = associated(cover.context(), Layer::Hidden.id(), rule.id(), hidden_body);
        let hidden = seal(
            pair.secret_part,
            hidden_body,
            &hidden_keys.cipher,
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
        let mut out = luma.to_vec();
        let changes = lane.apply(&write.stego, &mut out)?;
        let header = crate::parts::PART_HEADER;
        return Ok(Written {
            bytes: jpeg.encode(&out)?,
            sites: sites.positions.len(),
            nonzero_ac: sites.nonzero_ac,
            changes,
            free: Some(free),
            coded_bits: bits,
            secret: record(
                Layer::Hidden,
                rule,
                hidden_body,
                pair.secret_part.len() - header,
            ),
            decoy: Some(record(
                Layer::Decoy,
                rule,
                body,
                pair.decoy_part.len() - header,
            )),
        });
    }
    Err(StegoError::HiddenLong)
}
