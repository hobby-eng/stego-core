//! A photo admitted for hiding or reading, with the facts the advanced view shows.

use crate::StegoError;
use crate::algorithm::model::DctPlane;
use crate::coding::{HIDDEN_CAP, HIDDEN_MARGIN};
use crate::content::CONTENT_HEADER;
use crate::jpeg::{COEFFICIENTS, Jpeg};
use crate::keys::KEY_BYTES;
use crate::mode::{Mode, Settings};
use crate::parts::PART_HEADER;
use crate::record::{LENGTH_BYTES, bodies, record_bits};
use crate::sites::Sites;
use sha2::{Digest, Sha256};

/// Most message bits per site a record may use: above it the trellis codes stop finding cheap
/// solutions.
pub(crate) const MAX_BITS_PER_SITE: f64 = 0.5;
/// The rate the simple view recommends, in bits per non-zero AC coefficient. Provisional: the
/// detectability measurements replace it with the largest rate that trained detectors cannot
/// tell from clean photos.
pub const RECOMMENDED_BPNZAC: f64 = 0.05;
/// The share of a decoy's bits the hidden record can expect to use: binary STC changes about
/// one site in nine bits at low rates, and about half of the changed sites can move both ways.
pub(crate) const HIDDEN_SHARE: f64 = 0.05;
const CONTEXT_LABEL: &[u8] = b"stego-core 1 photo";
/// Most luminance AC coefficients of a photo (about 65 megapixels): every rule keeps per-site
/// buffers of some 30 bytes, which must stay within a browser's 4 GiB (CORE-50).
const AC_MAX: usize = 64_000_000;
/// The luminance table of T.81 table K.1 (natural order), the base of the quality estimate.
const STANDARD_LUMA: [u16; COEFFICIENTS] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];

/// Facts about a photo for the advanced view.
#[derive(Clone, Debug, PartialEq)]
pub struct PhotoInfo {
    /// Width in pixels.
    pub width: usize,
    /// Height in pixels.
    pub height: usize,
    /// Colour components: 1 for grayscale, 3 for colour.
    pub components: usize,
    /// Chroma subsampling, such as `4:2:0`.
    pub subsampling: &'static str,
    /// The IJG quality the luminance table corresponds to, when it is a scaled standard table.
    pub quality: Option<u8>,
    /// Number of scans.
    pub scans: usize,
    /// MCUs per restart interval, 0 for none.
    pub restart_interval: usize,
    /// Non-zero AC luminance coefficients of the full blocks.
    pub nonzero_ac: usize,
    /// File size in bytes.
    pub file_bytes: usize,
}

/// How much a photo holds in one mode.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Capacity {
    /// The mode it was computed for.
    pub mode: Mode,
    /// Coefficients that may carry the record.
    pub sites: usize,
    /// Largest message the coder can place, in bytes of text.
    pub max_bytes: usize,
    /// Largest message at the recommended rate, in bytes of text.
    pub recommended_bytes: usize,
    /// In the decoy mode, the expected room for the secret behind a decoy of the recommended
    /// size; the actual room is known only after writing.
    pub hidden_bytes: Option<usize>,
}

/// An admitted baseline JPEG photo.
pub struct Cover {
    jpeg: Jpeg,
    context: [u8; KEY_BYTES],
}

impl Cover {
    /// Parses `bytes` and checks that the photo can be rewritten without any other change.
    ///
    /// # Errors
    ///
    /// [`StegoError::Jpeg`], [`StegoError::JpegProfile`], [`StegoError::TrailingData`],
    /// [`StegoError::NotReproducible`] or [`StegoError::ImageLarge`] for a photo this crate
    /// cannot use.
    pub fn new(bytes: Vec<u8>) -> Result<Self, StegoError> {
        let jpeg = Jpeg::read(bytes)?;
        let (wide, high) = jpeg.frame().full_blocks();
        if wide * high * (COEFFICIENTS - 1) > AC_MAX {
            return Err(StegoError::ImageLarge);
        }
        let context = context(&jpeg)?;
        Ok(Self { jpeg, context })
    }

    /// The photo's file bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.jpeg.bytes()
    }

    /// Facts for the advanced view.
    #[must_use]
    pub fn info(&self) -> PhotoInfo {
        let frame = self.jpeg.frame();
        let sites = Sites::find(&self.jpeg, self.jpeg.luma(), crate::SiteRule::Grow1);
        PhotoInfo {
            width: frame.width,
            height: frame.height,
            components: frame.components.len(),
            subsampling: frame.subsampling(),
            quality: self.jpeg.quant(0).ok().and_then(|table| quality(&table)),
            scans: self.jpeg.scan_count(),
            restart_interval: self.jpeg.restart_interval(),
            nonzero_ac: sites.nonzero_ac,
            file_bytes: self.jpeg.bytes().len(),
        }
    }

    /// The room for a message under `settings`.
    #[must_use]
    pub fn capacity(&self, settings: &Settings) -> Capacity {
        let sites = Sites::find(&self.jpeg, self.jpeg.luma(), settings.rule());
        let n = sites.positions.len();
        let max_bits = (n as f64 * MAX_BITS_PER_SITE) as usize;
        let recommended_bits =
            ((sites.nonzero_ac as f64 * RECOMMENDED_BPNZAC) as usize).min(max_bits);
        let hidden_bytes = (settings.mode == Mode::Decoy).then(|| {
            let bits = ((recommended_bits as f64 * HIDDEN_SHARE) as usize)
                .saturating_sub(HIDDEN_MARGIN)
                .min(HIDDEN_CAP);
            text_bytes(bits)
        });
        Capacity {
            mode: settings.mode,
            sites: n,
            max_bytes: text_bytes(max_bits),
            recommended_bytes: text_bytes(recommended_bits),
            hidden_bytes,
        }
    }

    pub(crate) const fn jpeg(&self) -> &Jpeg {
        &self.jpeg
    }

    pub(crate) const fn context(&self) -> &[u8; KEY_BYTES] {
        &self.context
    }

    /// The luminance as the cost models take it.
    pub(crate) fn plane(&self) -> Result<DctPlane, StegoError> {
        let c = &self.jpeg.frame().components[0];
        Ok(DctPlane {
            blocks_wide: c.stride,
            blocks_high: c.padded_rows,
            coefficients: self.jpeg.luma().to_vec(),
            quant: self.jpeg.quant(0)?,
        })
    }
}

/// Text bytes that fit into a record of at most `bits` bits.
fn text_bytes(bits: usize) -> usize {
    bodies()
        .take_while(|&body| record_bits(body) <= bits)
        .last()
        .map_or(0, |body| {
            body.saturating_sub(LENGTH_BYTES + PART_HEADER + CONTENT_HEADER)
        })
}

/// The salt of every key: a hash of what no rule ever changes (the frame, the tables, the
/// luminance DC and the chroma), so that the original and the changed photo give the same one.
fn context(jpeg: &Jpeg) -> Result<[u8; KEY_BYTES], StegoError> {
    let frame = jpeg.frame();
    let mut hash = Sha256::new();
    hash.update(CONTEXT_LABEL);
    hash.update(&jpeg.bytes()[frame.header.clone()]);
    for index in 0..frame.components.len() {
        for value in jpeg.quant(index)? {
            hash.update(value.to_le_bytes());
        }
    }
    for block in jpeg.luma().as_chunks::<COEFFICIENTS>().0 {
        hash.update(block[0].to_le_bytes());
    }
    for index in 1..frame.components.len() {
        for value in jpeg.plane(index) {
            hash.update(value.to_le_bytes());
        }
    }
    Ok(hash.finalize().into())
}

/// The IJG quality whose scaled table K.1 matches `table` exactly, if any.
fn quality(table: &[u16; COEFFICIENTS]) -> Option<u8> {
    (1..=100_u8).rev().find(|&q| {
        let scale = if q < 50 {
            5000 / u32::from(q)
        } else {
            200 - 2 * u32::from(q)
        };
        table.iter().zip(&STANDARD_LUMA).all(|(&have, &base)| {
            let scaled = ((u32::from(base) * scale + 50) / 100).clamp(1, 255);
            u32::from(have) == scaled
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_standard_table_at_quality_50_and_75_is_recognized() {
        assert_eq!(quality(&STANDARD_LUMA), Some(50));
        // libjpeg at quality 75 halves table K.1 with rounding: 16 -> 8, 11 -> 6, 10 -> 5.
        let q75: Vec<u16> = STANDARD_LUMA
            .iter()
            .map(|&v| ((u32::from(v) * 50 + 50) / 100).max(1) as u16)
            .collect();
        assert_eq!(quality(&q75.try_into().unwrap()), Some(75));
        assert_eq!(quality(&[3; COEFFICIENTS]), None);
    }
}
