//! The segment and scan plan of a baseline JPEG file. Tables are read, never synthesized.

use super::huffman::Huffman;
use crate::StegoError;
use std::ops::Range;

/// Side of a DCT block.
pub(crate) const SIDE: usize = 8;
/// Coefficients of a DCT block.
pub(crate) const COEFFICIENTS: usize = SIDE * SIDE;
/// Natural-order index of each zigzag position (ITU T.81 figure A.6).
pub(crate) const ZIGZAG: [usize; COEFFICIENTS] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];
/// Table slots of each kind (T.81 B.2.4).
pub(crate) const TABLES: usize = 4;
const MAX_SCANS: usize = 16;
// Bounds the parsed header before allocation, repeated DRI and DHT segments included.
const MAX_SEGMENTS: usize = 65_536;
const SOF0: u8 = 0xC0;
const SOF1: u8 = 0xC1;
const SOF2: u8 = 0xC2;
const DHT: u8 = 0xC4;
const DQT: u8 = 0xDB;
const DRI: u8 = 0xDD;
const SOS: u8 = 0xDA;
const EOI: u8 = 0xD9;
const APP0: u8 = 0xE0;
const APP15: u8 = 0xEF;
const COM: u8 = 0xFE;

/// One colour component of the frame.
#[derive(Clone, Debug)]
pub(crate) struct Component {
    pub id: u8,
    pub h: usize,
    pub v: usize,
    pub quant: usize,
    /// Blocks per row that hold image samples.
    pub columns: usize,
    /// Block rows that hold image samples.
    pub rows: usize,
    /// Blocks per row of the MCU-padded grid, where coefficients are stored.
    pub stride: usize,
    /// Block rows of the MCU-padded grid.
    pub padded_rows: usize,
}

/// The frame header.
#[derive(Clone, Debug)]
pub(crate) struct Frame {
    pub width: usize,
    pub height: usize,
    pub components: Vec<Component>,
    pub mcu_columns: usize,
    pub mcu_rows: usize,
    /// The header's bytes, for the cover context.
    pub header: Range<usize>,
}

impl Frame {
    fn read(data: &[u8], header: Range<usize>) -> Result<Self, StegoError> {
        if data.len() < 6 || data[0] != 8 {
            return Err(StegoError::JpegProfile);
        }
        let height = usize::from(u16::from_be_bytes([data[1], data[2]]));
        let width = usize::from(u16::from_be_bytes([data[3], data[4]]));
        let count = usize::from(data[5]);
        if width == 0 || height == 0 || !matches!(count, 1 | 3) || data.len() != 6 + count * 3 {
            return Err(StegoError::JpegProfile);
        }
        let mut components: Vec<Component> = Vec::with_capacity(count);
        for triple in data[6..].as_chunks::<3>().0 {
            let h = usize::from(triple[1] >> 4);
            let v = usize::from(triple[1] & 15);
            let quant = usize::from(triple[2]);
            if !(1..=4).contains(&h)
                || !(1..=4).contains(&v)
                || quant >= TABLES
                || components.iter().any(|c| c.id == triple[0])
            {
                return Err(StegoError::Jpeg);
            }
            components.push(Component {
                id: triple[0],
                h,
                v,
                quant,
                columns: 0,
                rows: 0,
                stride: 0,
                padded_rows: 0,
            });
        }
        let mh = components
            .iter()
            .map(|c| c.h)
            .max()
            .ok_or(StegoError::Jpeg)?;
        let mv = components
            .iter()
            .map(|c| c.v)
            .max()
            .ok_or(StegoError::Jpeg)?;
        // The luminance carries the record, so it must have the full sampling.
        if components[0].h != mh
            || components[0].v != mv
            || components.iter().map(|c| c.h * c.v).sum::<usize>() > 10
        {
            return Err(StegoError::JpegProfile);
        }
        let mcu_columns = width.div_ceil(SIDE * mh);
        let mcu_rows = height.div_ceil(SIDE * mv);
        for c in &mut components {
            c.columns = (width * c.h).div_ceil(SIDE * mh);
            c.rows = (height * c.v).div_ceil(SIDE * mv);
            c.stride = mcu_columns * c.h;
            c.padded_rows = mcu_rows * c.v;
        }
        Ok(Self {
            width,
            height,
            components,
            mcu_columns,
            mcu_rows,
            header,
        })
    }

    /// Luminance blocks that lie wholly inside the image, per row and per column.
    pub(crate) const fn full_blocks(&self) -> (usize, usize) {
        (self.width / SIDE, self.height / SIDE)
    }

    /// Chroma subsampling in J:a:b notation for the report, such as `4:2:0`.
    pub(crate) fn subsampling(&self) -> &'static str {
        let Some(chroma) = self.components.get(1) else {
            return "grayscale";
        };
        match (
            self.components[0].h / chroma.h,
            self.components[0].v / chroma.v,
        ) {
            (1, 1) => "4:4:4",
            (2, 1) => "4:2:2",
            (2, 2) => "4:2:0",
            (1, 2) => "4:4:0",
            (4, 1) => "4:1:1",
            _ => "other",
        }
    }
}

/// One component of a scan with its table slots.
#[derive(Clone, Debug)]
pub(crate) struct Selector {
    pub component: usize,
    pub dc: usize,
    pub ac: usize,
}

/// A sequential scan: its components, tables and entropy-coded bytes.
pub(crate) struct Scan {
    pub entropy: Range<usize>,
    pub selectors: Vec<Selector>,
    /// MCUs per restart interval; 0 when there are no restart markers.
    pub restart: usize,
    pub dc: [Option<Huffman>; TABLES],
    pub ac: [Option<Huffman>; TABLES],
}

/// The parsed file: frame, quantization tables, scans and the end of the image.
pub(crate) struct Plan {
    pub frame: Frame,
    pub scans: Vec<Scan>,
    /// Quantization tables in natural order, by slot.
    pub quant: [Option<[u16; COEFFICIENTS]>; TABLES],
    /// One past the end-of-image marker.
    pub end: usize,
}

impl Plan {
    /// The quantization table of `component`.
    pub(crate) fn quant_of(&self, component: usize) -> Result<[u16; COEFFICIENTS], StegoError> {
        let slot = self
            .frame
            .components
            .get(component)
            .ok_or(StegoError::Jpeg)?
            .quant;
        self.quant[slot].ok_or(StegoError::Jpeg)
    }

    /// Reads the segments of `data` up to the end-of-image marker.
    pub(crate) fn read(data: &[u8]) -> Result<Self, StegoError> {
        if !data.starts_with(&[0xFF, 0xD8]) {
            return Err(StegoError::Jpeg);
        }
        let mut frame: Option<Frame> = None;
        let mut scans = Vec::new();
        let mut dc = std::array::from_fn(|_| None);
        let mut ac = std::array::from_fn(|_| None);
        let mut quant: [Option<[u16; COEFFICIENTS]>; TABLES] = [None; TABLES];
        let mut seen = Vec::new();
        let mut restart = 0;
        let mut at = 2;
        for _ in 0..MAX_SEGMENTS {
            if data.get(at) != Some(&0xFF) {
                return Err(StegoError::Jpeg);
            }
            while data.get(at) == Some(&0xFF) {
                at += 1;
            }
            let marker = *data.get(at).ok_or(StegoError::Jpeg)?;
            at += 1;
            if marker == EOI {
                let frame = frame.ok_or(StegoError::Jpeg)?;
                if scans.is_empty() || seen.len() != frame.components.len() {
                    return Err(StegoError::Jpeg);
                }
                return Ok(Self {
                    frame,
                    scans,
                    quant,
                    end: at,
                });
            }
            let length = usize::from(read16(data, at)?);
            if length < 2 || at + length > data.len() {
                return Err(StegoError::Jpeg);
            }
            let body = &data[at + 2..at + length];
            let after = at + length;
            match marker {
                SOF0 | SOF1 => {
                    if frame.is_some() {
                        return Err(StegoError::Jpeg);
                    }
                    frame = Some(Frame::read(body, at + 2..after)?);
                }
                DHT => read_huffman(body, &mut dc, &mut ac)?,
                DQT => read_quant(body, &mut quant)?,
                DRI => {
                    if body.len() != 2 {
                        return Err(StegoError::Jpeg);
                    }
                    restart = usize::from(u16::from_be_bytes([body[0], body[1]]));
                }
                SOS => {
                    let f = frame.as_ref().ok_or(StegoError::Jpeg)?;
                    if scans.len() >= MAX_SCANS {
                        return Err(StegoError::JpegProfile);
                    }
                    let selectors = read_scan(body, f, &mut seen)?;
                    for s in &selectors {
                        if quant[f.components[s.component].quant].is_none()
                            || dc[s.dc].is_none()
                            || ac[s.ac].is_none()
                        {
                            return Err(StegoError::Jpeg);
                        }
                    }
                    let entropy_end = entropy_end(data, after)?;
                    scans.push(Scan {
                        entropy: after..entropy_end,
                        selectors,
                        restart,
                        dc: dc.clone(),
                        ac: ac.clone(),
                    });
                    at = entropy_end;
                    continue;
                }
                SOF2 => return Err(StegoError::JpegProfile),
                APP0..=APP15 | COM => {}
                _ => return Err(StegoError::JpegProfile),
            }
            at = after;
        }
        Err(StegoError::JpegProfile)
    }
}

fn read16(data: &[u8], at: usize) -> Result<u16, StegoError> {
    let two = data.get(at..at + 2).ok_or(StegoError::Jpeg)?;
    Ok(u16::from_be_bytes([two[0], two[1]]))
}

fn read_huffman(
    mut data: &[u8],
    dc: &mut [Option<Huffman>; TABLES],
    ac: &mut [Option<Huffman>; TABLES],
) -> Result<(), StegoError> {
    while let Some(&class) = data.first() {
        let kind = class >> 4;
        let index = usize::from(class & 15);
        if kind > 1 || index >= TABLES {
            return Err(StegoError::Jpeg);
        }
        let (table, used) = Huffman::read(&data[1..])?;
        if kind == 0 {
            dc[index] = Some(table);
        } else {
            ac[index] = Some(table);
        }
        data = &data[1 + used..];
    }
    Ok(())
}

fn read_quant(
    mut data: &[u8],
    tables: &mut [Option<[u16; COEFFICIENTS]>; TABLES],
) -> Result<(), StegoError> {
    while let Some(&class) = data.first() {
        let precision = class >> 4;
        let index = usize::from(class & 15);
        if precision != 0 || index >= TABLES || data.len() < 1 + COEFFICIENTS {
            return Err(StegoError::JpegProfile);
        }
        let mut table = [0; COEFFICIENTS];
        for i in 0..COEFFICIENTS {
            if data[i + 1] == 0 {
                return Err(StegoError::Jpeg);
            }
            table[ZIGZAG[i]] = u16::from(data[i + 1]);
        }
        // A redefined table would make the coefficients of earlier scans mean something else.
        if tables[index].is_some_and(|old| old != table) {
            return Err(StegoError::JpegProfile);
        }
        tables[index] = Some(table);
        data = &data[1 + COEFFICIENTS..];
    }
    Ok(())
}

fn read_scan(
    data: &[u8],
    frame: &Frame,
    seen: &mut Vec<usize>,
) -> Result<Vec<Selector>, StegoError> {
    let count = usize::from(*data.first().ok_or(StegoError::Jpeg)?);
    if count == 0 || count > frame.components.len() || data.len() != 1 + count * 2 + 3 {
        return Err(StegoError::Jpeg);
    }
    let mut selectors = Vec::with_capacity(count);
    for pair in data[1..1 + count * 2].as_chunks::<2>().0 {
        let component = frame
            .components
            .iter()
            .position(|c| c.id == pair[0])
            .ok_or(StegoError::Jpeg)?;
        let dc = usize::from(pair[1] >> 4);
        let ac = usize::from(pair[1] & 15);
        if dc >= TABLES || ac >= TABLES || seen.contains(&component) {
            return Err(StegoError::Jpeg);
        }
        seen.push(component);
        selectors.push(Selector { component, dc, ac });
    }
    let tail = &data[data.len() - 3..];
    // Sequential DCT: spectral selection 0..63, no successive approximation (T.81 B.2.3).
    if tail != [0, 63, 0] {
        return Err(StegoError::JpegProfile);
    }
    Ok(selectors)
}

fn entropy_end(data: &[u8], mut at: usize) -> Result<usize, StegoError> {
    while at < data.len() {
        if data[at] != 0xFF {
            at += 1;
            continue;
        }
        let marker_at = at;
        at += 1;
        while data.get(at) == Some(&0xFF) {
            at += 1;
        }
        match data.get(at) {
            Some(0 | 0xD0..=0xD7) => at += 1,
            Some(_) => return Ok(marker_at),
            None => return Err(StegoError::Jpeg),
        }
    }
    Err(StegoError::Jpeg)
}
