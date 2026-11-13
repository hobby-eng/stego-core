//! Every refusal of the crate, with one stable code and one message each (CORE-23).

use crate::algorithm::model::CostError;
use std::fmt;

/// Why an operation was refused. A wrong password is not an error: reading returns `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StegoError {
    /// The bytes are not a JPEG file this crate can parse.
    Jpeg,
    /// A JPEG feature that is valid but not supported yet, such as progressive coding.
    JpegProfile,
    /// The photo holds bytes after its end marker (extra images, depth maps, trailers).
    TrailingData,
    /// Re-encoding the unchanged photo does not give back its bytes, so a change would show.
    NotReproducible,
    /// The photo has more sites than one record can address (over 4 billion).
    ImageLarge,
    /// The photo has too few usable coefficients for any record.
    ImageSmall,
    /// The password is shorter than the minimum after normalization.
    PasswordShort,
    /// The password is longer than the maximum.
    PasswordLong,
    /// The password holds a control character.
    PasswordCharacter,
    /// The original and the decoy use the same password.
    PasswordsEqual,
    /// A file name is empty, too long or holds a path separator or control character.
    FileName,
    /// The message is empty.
    MessageEmpty,
    /// The message does not fit into this photo with the chosen mode.
    MessageLong,
    /// The secret behind the decoy does not fit into the changes of the decoy.
    HiddenLong,
    /// The mode needs a decoy and none was given, or the mode takes none and one was given.
    DecoyChoice,
    /// No photo, or more than [`crate::CARRIERS_MAX`] photos, were given.
    Carriers,
    /// The threshold is below 2, above the number of photos, or the set has more than 16 photos.
    Threshold,
    /// The host's random source failed.
    Random,
    /// A key derivation or cipher call failed.
    Crypto,
    /// The system refused the memory of the password stretch.
    Memory,
    /// The PIM is above [`crate::WorkFactor::MAX_PIM`].
    Pim,
    /// The memory level is above [`crate::WorkFactor::MAX_MEMORY_LEVEL`].
    MemoryLevel,
    /// A cost model refused its input.
    Costs(CostError),
    /// The syndrome coder could not place the message.
    Coding,
    /// The written photo did not read back with every password and hash.
    Verification,
    /// A [`crate::protect::Secret`] has no room for the bytes pushed; nothing was written.
    SecretFull {
        /// Its capacity in bytes.
        capacity: usize,
    },
}

impl fmt::Display for StegoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Jpeg => "the file is not a readable JPEG photo",
            Self::JpegProfile => {
                "this kind of JPEG is not supported yet (only baseline JPEG with 8-bit samples)"
            }
            Self::TrailingData => {
                "the photo carries extra data after its end (more images or a trailer); not supported yet"
            }
            Self::NotReproducible => {
                "this photo was written in a way the program cannot reproduce exactly; choose another photo"
            }
            Self::ImageLarge => "the photo has more coefficients than a record can address",
            Self::ImageSmall => "the photo is too small to hold a message",
            Self::PasswordShort => "the password is too short (at least 12 bytes)",
            Self::PasswordLong => "the password is too long (at most 1,024 bytes)",
            Self::PasswordCharacter => "the password holds a control character",
            Self::PasswordsEqual => "the decoy password must differ from the secret's password",
            Self::FileName => {
                "the file name is empty, too long or holds a path or control character"
            }
            Self::MessageEmpty => "the message is empty",
            Self::MessageLong => "the message does not fit into this photo in this mode",
            Self::HiddenLong => {
                "the secret does not fit behind this decoy; use a longer decoy or a shorter secret"
            }
            Self::DecoyChoice => "this mode needs a decoy, or takes none",
            Self::Carriers => "choose between 1 and 256 photos",
            Self::Threshold => {
                "the number of photos needed must be from 2 to the number of photos, with at most 16 photos"
            }
            Self::Random => "the system's random source failed",
            Self::Crypto => "a key derivation or cipher step failed",
            Self::Memory => "the system did not give the memory this photo or password needs",
            Self::Pim => "the PIM must be from 0 to 1023",
            Self::MemoryLevel => "the memory level must be from 0 to 29",
            Self::Costs(e) => return write!(f, "the cost model refused the photo: {e}"),
            Self::Coding => "the coder could not place the message; try a shorter message",
            Self::Verification => {
                "the written photo did not read back correctly; nothing was saved"
            }
            Self::SecretFull { capacity } => {
                return write!(f, "a secret buffer of {capacity} bytes is full");
            }
        };
        f.write_str(text)
    }
}

impl std::error::Error for StegoError {}

impl From<CostError> for StegoError {
    fn from(value: CostError) -> Self {
        Self::Costs(value)
    }
}
