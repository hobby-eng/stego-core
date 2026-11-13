//! Everything a file shows about itself, for the details window: never refuses a file, and says
//! whether the core can use it and why not.

use crate::{Cover, PhotoInfo, StegoError};

/// Largest number of segments listed; a longer list is cut and marked.
const SEGMENTS_MAX: usize = 4096;
/// Longest comment or label text shown.
const TEXT_MAX: usize = 512;

/// The JPEG coding process of a frame header (T.81 table B.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    /// Baseline sequential DCT, Huffman coding.
    Baseline,
    /// Extended sequential DCT, Huffman coding.
    Extended,
    /// Progressive DCT, Huffman coding.
    Progressive,
    /// Lossless, Huffman coding.
    Lossless,
    /// A hierarchical or arithmetic-coded process.
    Other,
    /// No frame header was found.
    Unknown,
}

impl Coding {
    /// The name the details window shows.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Extended => "extended sequential",
            Self::Progressive => "progressive",
            Self::Lossless => "lossless",
            Self::Other => "hierarchical or arithmetic",
            Self::Unknown => "unknown",
        }
    }
}

/// One marker segment of the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Byte offset of the marker.
    pub offset: usize,
    /// The marker byte after 0xFF.
    pub marker: u8,
    /// The marker's name, such as `APP1` or `DQT`.
    pub name: &'static str,
    /// Bytes of the segment, marker and length included; for a scan, its entropy-coded data too.
    pub bytes: usize,
    /// For APPn, the identifier it starts with (`Exif`, `JFIF`, XMP's namespace, `ICC_PROFILE`,
    /// `MPF`, …); for COM, the comment text.
    pub label: String,
}

/// What a file is and what it holds.
#[derive(Clone, Debug, PartialEq)]
pub struct Inspection {
    /// File size in bytes.
    pub file_bytes: usize,
    /// Whether it starts like a JPEG file.
    pub jpeg: bool,
    /// The coding process.
    pub coding: Coding,
    /// `Ok` when the core can hide in it; otherwise why not.
    pub usable: Result<(), StegoError>,
    /// The facts of an admitted photo.
    pub photo: Option<PhotoInfo>,
    /// Every segment in file order.
    pub segments: Vec<Segment>,
    /// Bytes after the end-of-image marker: extra images, depth maps, vendor trailers.
    pub trailing_bytes: usize,
    /// Whether the segment list was cut at its limit.
    pub truncated: bool,
}

/// Inspects `bytes`. Cheap for any file; the full admission of a usable photo decodes it.
#[must_use]
pub fn inspect(bytes: &[u8]) -> Inspection {
    let jpeg = bytes.starts_with(&[0xFF, 0xD8]);
    let (segments, end, truncated) = if jpeg {
        walk(bytes)
    } else {
        (Vec::new(), 0, false)
    };
    let coding = segments
        .iter()
        .find_map(|s| coding_of(s.marker))
        .unwrap_or(Coding::Unknown);
    let (usable, photo) = if jpeg {
        match Cover::new(bytes.to_vec()) {
            Ok(cover) => (Ok(()), Some(cover.info())),
            Err(error) => (Err(error), None),
        }
    } else {
        (Err(StegoError::Jpeg), None)
    };
    Inspection {
        file_bytes: bytes.len(),
        jpeg,
        coding,
        usable,
        photo,
        segments,
        trailing_bytes: if end == 0 {
            0
        } else {
            bytes.len().saturating_sub(end)
        },
        truncated,
    }
}

/// The segments up to the end-of-image marker, the offset after it (0 when none), and whether
/// the list was cut.
fn walk(bytes: &[u8]) -> (Vec<Segment>, usize, bool) {
    let mut segments = vec![Segment {
        offset: 0,
        marker: 0xD8,
        name: "SOI",
        bytes: 2,
        label: String::new(),
    }];
    let mut at = 2;
    while segments.len() < SEGMENTS_MAX {
        let offset = at;
        if bytes.get(at) != Some(&0xFF) {
            return (segments, 0, false);
        }
        while bytes.get(at) == Some(&0xFF) {
            at += 1;
        }
        let Some(&marker) = bytes.get(at) else {
            return (segments, 0, false);
        };
        at += 1;
        if marker == 0xD9 {
            segments.push(Segment {
                offset,
                marker,
                name: "EOI",
                bytes: at - offset,
                label: String::new(),
            });
            return (segments, at, false);
        }
        let Some(length) = bytes
            .get(at..at + 2)
            .map(|two| usize::from(u16::from_be_bytes([two[0], two[1]])))
        else {
            return (segments, 0, false);
        };
        let Some(body) = bytes.get(at + 2..at + length.max(2)) else {
            return (segments, 0, false);
        };
        let mut end = at + length.max(2);
        if marker == 0xDA {
            end = entropy_end(bytes, end);
        }
        segments.push(Segment {
            offset,
            marker,
            name: name_of(marker),
            bytes: end - offset,
            label: label_of(marker, body),
        });
        at = end;
    }
    (segments, 0, true)
}

fn entropy_end(bytes: &[u8], mut at: usize) -> usize {
    while at + 1 < bytes.len() {
        if bytes[at] == 0xFF && !matches!(bytes[at + 1], 0 | 0xD0..=0xD7 | 0xFF) {
            return at;
        }
        at += 1;
    }
    bytes.len()
}

const fn coding_of(marker: u8) -> Option<Coding> {
    match marker {
        0xC0 => Some(Coding::Baseline),
        0xC1 => Some(Coding::Extended),
        0xC2 => Some(Coding::Progressive),
        0xC3 => Some(Coding::Lossless),
        0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => Some(Coding::Other),
        _ => None,
    }
}

const fn name_of(marker: u8) -> &'static str {
    match marker {
        0xC0 => "SOF0",
        0xC1 => "SOF1",
        0xC2 => "SOF2",
        0xC3 => "SOF3",
        0xC4 => "DHT",
        0xCC => "DAC",
        0xC5..=0xCF => "SOFn",
        0xDA => "SOS",
        0xDB => "DQT",
        0xDD => "DRI",
        0xE0 => "APP0",
        0xE1 => "APP1",
        0xE2 => "APP2",
        0xE3..=0xEC => "APPn",
        0xED => "APP13",
        0xEE => "APP14",
        0xEF => "APP15",
        0xFE => "COM",
        _ => "other",
    }
}

/// The identifier of an APPn segment, or the text of a comment.
fn label_of(marker: u8, body: &[u8]) -> String {
    let text = |raw: &[u8]| {
        let mut s: String = String::from_utf8_lossy(raw)
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        s.truncate(s.char_indices().nth(TEXT_MAX).map_or(s.len(), |(i, _)| i));
        s
    };
    match marker {
        0xE0..=0xEF => {
            let id_end = body
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(body.len().min(32));
            text(&body[..id_end.min(64)])
        }
        0xFE => text(body),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_jpeg_file_is_described_not_refused() {
        let report = inspect(b"\x89PNG\r\n\x1a\n");
        assert!(!report.jpeg);
        assert_eq!(report.coding, Coding::Unknown);
        assert_eq!(report.usable, Err(StegoError::Jpeg));
    }

    #[test]
    fn a_progressive_header_and_labels_are_named() {
        // SOI, APP1 "Exif", COM "hi", SOF2 (8-bit, 1x1, one component), EOI, then a trailer.
        let mut file = vec![0xFF, 0xD8];
        file.extend_from_slice(&[0xFF, 0xE1, 0, 8, b'E', b'x', b'i', b'f', 0, 0]);
        file.extend_from_slice(&[0xFF, 0xFE, 0, 4, b'h', b'i']);
        file.extend_from_slice(&[0xFF, 0xC2, 0, 11, 8, 0, 1, 0, 1, 1, 1, 0x11, 0]);
        file.extend_from_slice(&[0xFF, 0xD9, 1, 2, 3]);
        let report = inspect(&file);
        assert_eq!(report.coding, Coding::Progressive);
        assert_eq!(report.segments[1].label, "Exif");
        assert_eq!(report.segments[2].label, "hi");
        assert_eq!(report.trailing_bytes, 3);
        assert!(report.usable.is_err());
    }
}
