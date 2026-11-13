//! The technical record of a hiding or reading job, for the advanced view.

use crate::cover::PhotoInfo;
use crate::keys::KDF_LANES;
use crate::mode::Settings;
use crate::sites::SiteRule;

/// The fixed parameters every record uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    /// Password stretching.
    pub kdf: &'static str,
    /// Argon2id lanes.
    pub kdf_lanes: u32,
    /// Record cipher.
    pub cipher: &'static str,
    /// Constraint height of the syndrome-trellis codes.
    pub stc_height: usize,
    /// Message bits per trellis segment.
    pub stc_segment_bits: usize,
}

/// The parameters of this version.
#[must_use]
pub const fn parameters() -> Parameters {
    Parameters {
        kdf: "Argon2id v1.3; memory and passes from each password's PIM and memory level",
        kdf_lanes: KDF_LANES,
        cipher: "XChaCha20-Poly1305",
        stc_height: crate::algorithm::stc::HEIGHT,
        stc_segment_bits: crate::algorithm::stc::SEGMENT_BITS,
    }
}

/// Which layer of a photo a record sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// The ternary record of the standard mode.
    Standard,
    /// The decoy of the decoy mode.
    Decoy,
    /// The secret behind a decoy.
    Hidden,
}

impl Layer {
    /// The layer's name for the advanced view.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard (ternary STC)",
            Self::Decoy => "binary STC (decoy mode)",
            Self::Hidden => "behind the decoy (wet paper on change directions)",
        }
    }

    /// The byte that separates the layers' keys and binds a record to its layer.
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::Standard => 1,
            Self::Decoy => 2,
            Self::Hidden => 3,
        }
    }
}

/// One photo's record as written or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordReport {
    /// The layer.
    pub layer: Layer,
    /// The site rule the layer used.
    pub site_rule: SiteRule,
    /// Bytes of the padded body.
    pub body_bytes: usize,
    /// Bits the coder placed: nonce, body and tag.
    pub record_bits: usize,
    /// This photo's part number, from 0.
    pub part: u16,
    /// Parts in the set: the number of photos.
    pub parts: u16,
    /// Message bytes this photo carries.
    pub part_bytes: usize,
    /// Argon2id memory of the record's password, in KiB.
    pub kdf_memory_kib: u32,
    /// Argon2id passes of the record's password.
    pub kdf_passes: u32,
}

/// One written photo.
#[derive(Clone, Debug, PartialEq)]
pub struct FileReport {
    /// The written photo.
    pub photo: PhotoInfo,
    /// Sites the coder could use.
    pub sites: usize,
    /// Coefficients changed by ±1.
    pub changes: usize,
    /// Changes free to move either way, which carried the hidden record (decoy mode).
    pub free_changes: Option<usize>,
    /// Coded bits per non-zero AC coefficient, the rate steganalysis papers report.
    pub bits_per_nonzero_ac: f64,
    /// The secret's record.
    pub secret: RecordReport,
    /// The decoy's record, in the decoy mode.
    pub decoy: Option<RecordReport>,
}

/// The result of a hiding job. A report exists only after every photo was read back with each
/// password and each message gave the same SHA-256.
#[derive(Clone, Debug, PartialEq)]
pub struct HideReport {
    /// What was chosen.
    pub settings: Settings,
    /// Each photo, in the order given.
    pub files: Vec<FileReport>,
    /// Size of the secret in bytes.
    pub secret_bytes: usize,
    /// SHA-256 of the secret, equal to the one read back.
    pub secret_sha256: Digest,
    /// Size and SHA-256 of the decoy, in the decoy mode.
    pub decoy: Option<(usize, Digest)>,
    /// The fixed parameters.
    pub parameters: Parameters,
}

/// The result of a reading job.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadReport {
    /// For every photo of the set that was read: its index among the photos given, its facts
    /// and record.
    pub files: Vec<(usize, PhotoInfo, RecordReport)>,
    /// What else the password opened among the photos: other sets, whole or not, and records of
    /// another version. Their photos are not in `files`; read them apart to see them.
    pub other_sets: usize,
    /// Size of the message in bytes.
    pub content_bytes: usize,
    /// SHA-256 of the message.
    pub sha256: Digest,
    /// The fixed parameters.
    pub parameters: Parameters,
}

/// A message's SHA-256, for the person to compare. Unsalted, so a short message can be guessed
/// from it without the password: a host shows it and never logs or stores it, and `Debug`
/// prints it redacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest([u8; 32]);

impl Digest {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The hash.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hexadecimal, for display.
    #[must_use]
    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Digest(redacted)")
    }
}

/// Lower-case hexadecimal of a hash, for display.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
