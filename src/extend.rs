//! A further photo for a k-of-n set: one in place of a lost photo, or one more under a new number.
//! Nothing in the set changes; the new photo's piece and key share come from any k photos, so the
//! part for a number is always the same and two copies count as one. It is read back with k − 1
//! old photos before it is returned.

use crate::cover::Cover;
use crate::hide::{Pair, Written, write_decoy, write_standard};
use crate::keys::Keys;
use crate::mode::{Mode, Settings};
use crate::parts::{NoQuorum, Part, Quorum, quorum};
use crate::plain::Plain;
use crate::random::Random;
use crate::report::{FileReport, Layer, RecordReport};
use crate::reveal::{Reading, open_one, reveal};
use crate::threshold::{Refused, THRESHOLD_MAX};
use crate::{CARRIERS_MAX, Password, StegoError};
use std::fmt;

/// Which number the new photo takes in its set. Numbers count from 1, as a person sees them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// The number after the last one issued, as far as the photos given know. A photo added
    /// elsewhere from an older copy of the set is not known to them: it may carry the same
    /// number, and then holds the very same part.
    Next,
    /// This number: that of a lost photo, to replace it, or one chosen by a person who keeps
    /// count of the photos issued.
    Number(u16),
}

/// What [`extend`] is asked to do.
#[derive(Clone, Copy)]
pub struct Addition<'a> {
    /// The photos of the set that are at hand: at least as many as the set needs, and none of
    /// another set under the same password.
    pub photos: &'a [&'a Cover],
    /// The photo that becomes a member of the set. It is not one of `photos`.
    pub photo: &'a Cover,
    /// The password of the set: the message's own, or the decoy's when the photos were written
    /// with a decoy.
    pub password: &'a Password,
    /// With a decoy: the password of the secret behind it, so that the new photo gets its part
    /// of the secret too. Without it the new photo carries the decoy alone, as a decoy written
    /// by itself does, and the secret stays in the photos that had it. The secret must sit in
    /// photos of the decoy's own set: the password is tried on those and on no other.
    pub behind: Option<&'a Password>,
    /// The number the new photo takes.
    pub place: Place,
}

/// Why a set was not given a further photo. Nothing was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetError {
    /// The password opened nothing in the photos given.
    Nothing,
    /// The password opened more than one set, or records of different kinds: only the photos
    /// of one set may be given, since a set is changed only when it is certain which.
    Several,
    /// The set needs every one of its photos, so it has nothing spare to make another from.
    EveryPhotoNeeded,
    /// Fewer photos of the set than it needs.
    Incomplete {
        /// Photos of the set that were given.
        found: usize,
        /// Photos the set needs.
        needed: usize,
    },
    /// The photos of the set do not agree with each other.
    Conflict,
    /// What the password opened is not in a form this version reads.
    Unsupported,
    /// [`Place::Next`] found no number after the highest count the photos declare: the numbers
    /// of a set end at 16. A number below it may still be free; [`Place::Number`] names it.
    Full,
    /// The number asked for is not one a set can have.
    Number,
    /// The password opens a secret behind a decoy. A photo is written with the decoy's
    /// password; the secret's goes second.
    DecoyPassword,
    /// The second password opens no secret behind the decoy of these photos.
    NothingBehind,
}

impl fmt::Display for SetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Nothing => "the password opened nothing in these photos",
            Self::Several => {
                "the password opens more than one set in these photos; give the photos of one set only"
            }
            Self::EveryPhotoNeeded => {
                "this set needs every one of its photos, so no photo can be added or replaced; hide the message again"
            }
            Self::Incomplete { found, needed } => {
                return write!(
                    f,
                    "{found} of the {needed} photos this set needs were given; add the others"
                );
            }
            Self::Conflict => "the photos of the set do not agree with each other",
            Self::Unsupported => "the photos hold a set in a form this version does not read",
            Self::Full => {
                "the set's numbers run to 16 and none is left after the last one issued; name a free number if there is one"
            }
            Self::Number => "the photo's number must be from 1 to 16",
            Self::DecoyPassword => {
                "this password opens a secret behind a decoy; give the decoy's password first and this one second"
            }
            Self::NothingBehind => "the second password opens no secret behind these photos",
        };
        f.write_str(text)
    }
}

impl From<NoQuorum> for StegoError {
    fn from(reason: NoQuorum) -> Self {
        Self::Set(match reason {
            NoQuorum::Memory => return Self::Memory,
            NoQuorum::Nothing => SetError::Nothing,
            NoQuorum::Several => SetError::Several,
            NoQuorum::Split => SetError::EveryPhotoNeeded,
            NoQuorum::Incomplete { found, needed } => SetError::Incomplete { found, needed },
            NoQuorum::Conflict => SetError::Conflict,
            NoQuorum::Unsupported => SetError::Unsupported,
        })
    }
}

/// The new photo's place in one set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The photo's number in the set, from 1.
    pub number: u16,
    /// Whether a photo with that number was among the photos given. The new photo then holds
    /// the same part as that photo, and the two count as one. Whether a number that was not at
    /// hand had ever been issued is not known here: no record of the photos issued exists
    /// outside the photos, and `issued` is only the highest count they declare.
    pub at_hand: bool,
    /// Photos the set needs.
    pub needed: usize,
    /// Different numbers of the set at hand after this: those of the photos given and the new
    /// one. Any `needed` of them open the message. What was issued elsewhere is not known here.
    pub numbers: usize,
    /// The highest count the photos given declare, or the new photo's number if that is higher:
    /// the count the new photo declares.
    pub issued: u16,
}

/// What [`extend`] did.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendReport {
    /// The new photo's place in the set of the password given first.
    pub set: Membership,
    /// Its place in the set of the secret behind the decoy, when that was extended too.
    pub behind: Option<Membership>,
    /// The written photo.
    pub file: FileReport,
}

/// A photo that joined a set, read back and checked.
#[derive(Debug)]
pub struct Extended {
    file: Vec<u8>,
    report: ExtendReport,
}

impl Extended {
    /// The new photo's bytes.
    #[must_use]
    pub fn file(&self) -> &[u8] {
        &self.file
    }

    /// Takes the new photo's bytes out.
    #[must_use]
    pub fn into_file(self) -> Vec<u8> {
        self.file
    }

    /// What was done.
    #[must_use]
    pub const fn report(&self) -> &ExtendReport {
        &self.report
    }
}

/// One set as the photos given hold it, under one password.
struct Source {
    layer: Layer,
    quorum: Quorum,
}

impl Source {
    /// Opens `photos` with `password`: one set, whole, in one kind of record, or a refusal.
    fn read(photos: &[&Cover], password: &Password) -> Result<Self, StegoError> {
        let mut parts = Vec::new();
        let mut layer = None;
        let mut seen: Vec<&[u8; 32]> = Vec::with_capacity(photos.len());
        for (place, cover) in photos.iter().enumerate() {
            // The same file given twice is read once, as in reading.
            if seen.contains(&cover.sha256()) {
                continue;
            }
            seen.push(cover.sha256());
            let Some(found) = open_one(cover, password)? else {
                continue;
            };
            if layer.is_some_and(|known| known != found.layer) {
                return Err(SetError::Several.into());
            }
            layer = Some(found.layer);
            let part = Part::parse(&found.plain).ok_or(SetError::Unsupported)?;
            parts.push(part.at(place));
        }
        let quorum = quorum(parts)?;
        let layer = layer.ok_or(SetError::Nothing)?;
        Ok(Self { layer, quorum })
    }

    /// The number, from 0, that `place` gives the new photo, and the count it declares.
    fn number(&self, place: Place) -> Result<(u16, u16), SetError> {
        let issued = self.quorum.issued();
        let index = match place {
            Place::Next => issued,
            Place::Number(number) => number.checked_sub(1).ok_or(SetError::Number)?,
        };
        if usize::from(index) >= THRESHOLD_MAX {
            return Err(match place {
                Place::Next => SetError::Full,
                Place::Number(_) => SetError::Number,
            });
        }
        Ok((index, issued.max(index + 1)))
    }

    /// The part the new photo holds, and its place in this set.
    fn join(&self, place: Place) -> Result<(Plain, Membership), StegoError> {
        let (index, count) = self.number(place)?;
        let part = self
            .quorum
            .part(index, count)
            .map_err(|refused| match refused {
                Refused::Memory => StegoError::Memory,
                Refused::Number => SetError::Number.into(),
                Refused::Inconsistent => SetError::Conflict.into(),
                Refused::Malformed | Refused::TooFew => SetError::Unsupported.into(),
            })?;
        let known = self.quorum.numbers().any(|(number, _)| number == index);
        let membership = Membership {
            number: index + 1,
            at_hand: known,
            needed: self.quorum.needed,
            numbers: self.quorum.numbers().count() + usize::from(!known),
            issued: count,
        };
        Ok((part, membership))
    }

    /// Reads the new photo together with `needed − 1` of the photos given, none of them the
    /// number the new one took: they cannot open without it.
    fn verify(
        &self,
        new: &Cover,
        photos: &[&Cover],
        membership: &Membership,
        password: &Password,
    ) -> Result<(), StegoError> {
        let mut read: Vec<&Cover> = vec![new];
        let others = self
            .quorum
            .numbers()
            .filter(|&(number, _)| number + 1 != membership.number)
            .filter_map(|(_, place)| photos.get(place).copied())
            .take(self.quorum.needed.saturating_sub(1));
        read.extend(others);
        match reveal(&read, password)? {
            Reading::Complete(found)
                if read.len() == self.quorum.needed
                    && found.report().files.len() == self.quorum.needed
                    && found.content().same_as(&self.quorum.content) =>
            {
                Ok(())
            }
            _ => Err(StegoError::Verification),
        }
    }
}

/// Gives a k-of-n set a further photo. `settings` supplies the cost model, site rule and threads;
/// mode and threshold come from the set. Fails when the photos are wrong or are not one set that
/// can grow, when the new photo has no room, or when it doesn't read back with the others.
pub fn extend(
    addition: &Addition<'_>,
    settings: &Settings,
    random: &mut dyn Random,
) -> Result<Extended, StegoError> {
    let (photos, photo) = (addition.photos, addition.photo);
    if photos.is_empty() || photos.len() > CARRIERS_MAX {
        return Err(StegoError::Carriers);
    }
    if photos.iter().any(|given| given.sha256() == photo.sha256()) {
        return Err(StegoError::DuplicatePhoto);
    }
    let front = Source::read(photos, addition.password)?;
    // A secret is behind this decoy only if it sits in photos of this very set, so the second
    // password is tried on the set's own photos and on no other: every copy of every part,
    // since of two copies of one decoy part only one may carry the secret's.
    let members: Vec<&Cover> = front
        .quorum
        .members()
        .iter()
        .filter_map(|&place| photos.get(place).copied())
        .collect();
    let behind = match (front.layer, addition.behind) {
        (Layer::Hidden, _) => return Err(SetError::DecoyPassword.into()),
        (Layer::Standard, Some(_)) => return Err(SetError::NothingBehind.into()),
        (Layer::Standard | Layer::Decoy, None) => None,
        (Layer::Decoy, Some(password)) => {
            let source = match Source::read(&members, password) {
                Err(StegoError::Set(SetError::Nothing)) => {
                    return Err(SetError::NothingBehind.into());
                }
                other => other?,
            };
            if source.layer != Layer::Hidden {
                return Err(SetError::NothingBehind.into());
            }
            Some((password, source))
        }
    };
    let (front_part, front_place) = front.join(addition.place)?;
    let behind_part = behind
        .as_ref()
        .map(|(_, source)| source.join(addition.place))
        .transpose()?;
    let written = write(
        addition,
        settings,
        front.layer,
        &front_part,
        &behind_part,
        random,
    )?;
    let new = Cover::new(written.bytes.clone())?;
    front.verify(&new, photos, &front_place, addition.password)?;
    if let (Some((password, source)), Some((_, place))) = (&behind, &behind_part) {
        source.verify(&new, &members, place, password)?;
    }
    let report = describe(
        addition,
        &written,
        &new,
        (front_place, behind_part.map(|(_, place)| place)),
    );
    Ok(Extended {
        file: written.bytes,
        report,
    })
}

/// Writes the new photo: the set's part in the kind of record the set uses, and the secret's
/// part behind it when one was asked for.
fn write(
    addition: &Addition<'_>,
    settings: &Settings,
    layer: Layer,
    part: &[u8],
    behind: &Option<(Plain, Membership)>,
    random: &mut dyn Random,
) -> Result<Written, StegoError> {
    let photo = addition.photo;
    let keys = Keys::derive(addition.password, photo.context())?;
    if layer == Layer::Standard {
        let settings = Settings {
            mode: Mode::Standard,
            needed: None,
            ..*settings
        };
        return write_standard(photo, &keys, &settings, part, random);
    }
    let settings = Settings {
        mode: Mode::Decoy,
        needed: None,
        ..*settings
    };
    let secret_keys = addition
        .behind
        .filter(|_| behind.is_some())
        .map(|password| Keys::derive(password, photo.context()))
        .transpose()?;
    let pair = Pair {
        decoy_keys: &keys,
        decoy_part: part,
        behind: secret_keys
            .as_ref()
            .zip(behind.as_ref().map(|(part, _)| part.as_slice())),
    };
    write_decoy(photo, &settings, &pair, random)
}

/// The report of the written photo.
fn describe(
    addition: &Addition<'_>,
    written: &Written,
    new: &Cover,
    (set, behind): (Membership, Option<Membership>),
) -> ExtendReport {
    let record = |record: RecordReport, place: &Membership, password: &Password| RecordReport {
        part: place.number - 1,
        parts: place.issued,
        kdf_memory_kib: password.work().memory_kib(),
        kdf_passes: password.work().passes(),
        ..record
    };
    // With a secret behind it, the writer reports the secret's record first and the decoy's
    // second; alone, the set's record is the only one.
    let (secret, decoy) = match (behind.as_ref().zip(addition.behind), written.decoy) {
        (Some((place, password)), Some(decoy)) => (
            record(written.secret, place, password),
            Some(record(decoy, &set, addition.password)),
        ),
        _ => (record(written.secret, &set, addition.password), None),
    };
    ExtendReport {
        set,
        behind,
        file: FileReport {
            photo: new.info(),
            sites: written.sites,
            changes: written.changes,
            free_changes: written.free,
            bits_per_nonzero_ac: written.coded_bits as f64 / written.nonzero_ac.max(1) as f64,
            secret,
            decoy,
        },
    }
}
