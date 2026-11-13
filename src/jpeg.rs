//! Baseline JPEG at the level of quantized coefficients: every scan is decoded into
//! coefficients and encoded again with the file's own tables, so that changed coefficients are
//! written without touching any other byte of the file.
//!
//! A file is admitted only when encoding its unchanged coefficients gives back its exact bytes:
//! a writer that pads, stuffs or orders symbols differently would otherwise leave a trace.

mod bits;
mod huffman;
mod syntax;

use crate::StegoError;
use bits::{Reader, Writer, category};
use huffman::Huffman;
pub(crate) use syntax::{COEFFICIENTS, Frame, ZIGZAG};
use syntax::{Plan, Scan};

/// Fewest coded bits a block can take: one Huffman code for DC and one for AC.
const MIN_BLOCK_BITS: u128 = 2;
/// What a browser module may plan to use: a 32-bit address space holds 4 GiB.
#[cfg(target_arch = "wasm32")]
const WASM_MEMORY: u64 = 3 << 30;
/// Working bytes per site and per coefficient of a job, as measured (see `estimate`).
const BYTES_PER_SITE: u64 = 40;
const BYTES_PER_COEFFICIENT: u64 = 8;

/// About how much memory a job on this photo takes, from its header alone: every AC coefficient
/// of the full luminance blocks counted as a site (an upper bound), every coefficient of every
/// component, the file three times and the default password stretch.
pub(crate) fn estimate(frame: &Frame, file_bytes: usize) -> u64 {
    let coefficients: u64 = frame
        .components
        .iter()
        .map(|c| (c.stride * c.padded_rows * COEFFICIENTS) as u64)
        .sum();
    let (wide, high) = frame.full_blocks();
    let sites = (wide * high * (COEFFICIENTS - 1)) as u64;
    let stretch = u64::from(crate::WorkFactor::default().memory_kib()) * 1024;
    sites * BYTES_PER_SITE + coefficients * BYTES_PER_COEFFICIENT + 3 * file_bytes as u64 + stretch
}

/// [`estimate`] for a file not yet admitted: the header is read, nothing is decoded.
pub(crate) fn estimate_file(bytes: &[u8]) -> Result<u64, StegoError> {
    Ok(estimate(&Plan::read(bytes)?.frame, bytes.len()))
}

/// Largest category of a DC difference in 8-bit baseline JPEG (T.81 F.1.2.1).
const DC_CATEGORY_MAX: u8 = 11;
/// Largest category of an AC coefficient in 8-bit baseline JPEG.
const AC_CATEGORY_MAX: u8 = 10;
/// Run length that a ZRL symbol stands for.
const ZRL_RUN: usize = 16;
const ZRL: u8 = 0xF0;
const EOB: u8 = 0x00;

/// A parsed baseline JPEG with its coefficients.
pub(crate) struct Jpeg {
    bytes: Vec<u8>,
    plan: Plan,
    /// Per component, the MCU-padded block grid, natural order inside each block.
    planes: Vec<Vec<i16>>,
}

impl Jpeg {
    /// Parses and decodes `bytes` and checks that they re-encode exactly.
    pub(crate) fn read(bytes: Vec<u8>) -> Result<Self, StegoError> {
        let plan = Plan::read(&bytes)?;
        if plan.end != bytes.len() {
            return Err(StegoError::TrailingData);
        }
        // Every block takes at least two bits of coded data (a DC code and an end or an AC code), so
        // a header that claims more blocks than its scans can hold is refused before any plane is
        // allocated: a few bytes cannot ask for gigabytes.
        let coded_bits: u128 = plan.scans.iter().map(|s| s.entropy.len() as u128 * 8).sum();
        let blocks: u128 = plan
            .scans
            .iter()
            .map(|s| units(&plan.frame, s) as u128 * blocks_per_unit(&plan.frame, s) as u128)
            .sum();
        if blocks * MIN_BLOCK_BITS > coded_bits {
            return Err(StegoError::Jpeg);
        }
        #[cfg(target_arch = "wasm32")]
        if estimate(&plan.frame, bytes.len()) > WASM_MEMORY {
            return Err(StegoError::Memory);
        }
        // No size limit: a photo of any size is decoded when the system gives the memory, and a
        // refusal is an error, never an abort.
        let mut planes: Vec<Vec<i16>> = Vec::with_capacity(plan.frame.components.len());
        for c in &plan.frame.components {
            let length = c
                .stride
                .checked_mul(c.padded_rows)
                .and_then(|blocks| blocks.checked_mul(COEFFICIENTS))
                .ok_or(StegoError::Memory)?;
            let mut plane = Vec::new();
            plane
                .try_reserve_exact(length)
                .map_err(|_| StegoError::Memory)?;
            plane.resize(length, 0);
            planes.push(plane);
        }
        for scan in &plan.scans {
            decode_scan(&bytes, &plan.frame, scan, &mut planes)?;
        }
        let jpeg = Self {
            bytes,
            plan,
            planes,
        };
        if jpeg.encode(&jpeg.planes[0])? != jpeg.bytes {
            return Err(StegoError::NotReproducible);
        }
        Ok(jpeg)
    }

    /// The memory estimate of this photo.
    pub(crate) fn estimate(&self) -> u64 {
        estimate(&self.plan.frame, self.bytes.len())
    }

    pub(crate) const fn frame(&self) -> &Frame {
        &self.plan.frame
    }

    /// The luminance coefficients: MCU-padded grid of `stride × padded_rows` blocks.
    pub(crate) fn luma(&self) -> &[i16] {
        &self.planes[0]
    }

    /// Coefficients of component `index`.
    pub(crate) fn plane(&self, index: usize) -> &[i16] {
        &self.planes[index]
    }

    /// Quantization table of component `index`, natural order.
    pub(crate) fn quant(&self, index: usize) -> Result<[u16; COEFFICIENTS], StegoError> {
        self.plan.quant_of(index)
    }

    /// The original file.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Restart interval of the scan that holds the luminance, in MCUs (0 for none).
    pub(crate) fn restart_interval(&self) -> usize {
        self.luma_scan().map_or(0, |scan| scan.restart)
    }

    /// Number of scans.
    pub(crate) fn scan_count(&self) -> usize {
        self.plan.scans.len()
    }

    fn luma_scan(&self) -> Option<&Scan> {
        self.plan
            .scans
            .iter()
            .find(|scan| scan.selectors.iter().any(|s| s.component == 0))
    }

    /// Whether the luminance AC table can code `value` after a run of `run` zeros.
    pub(crate) fn luma_codes(&self, run: usize, value: i32) -> bool {
        let Some(scan) = self.luma_scan() else {
            return false;
        };
        let Some(table) = scan
            .selectors
            .iter()
            .find(|s| s.component == 0)
            .and_then(|s| scan.ac[s.ac].as_ref())
        else {
            return false;
        };
        let size = category(value);
        size <= AC_CATEGORY_MAX && table.has(symbol(run % ZRL_RUN, size))
    }

    /// The file with `luma` in place of the luminance coefficients; every other byte is kept.
    pub(crate) fn encode(&self, luma: &[i16]) -> Result<Vec<u8>, StegoError> {
        if luma.len() != self.planes[0].len() {
            return Err(StegoError::Coding);
        }
        let mut planes: Vec<&[i16]> = self.planes.iter().map(Vec::as_slice).collect();
        planes[0] = luma;
        let mut out = Vec::with_capacity(self.bytes.len() + self.bytes.len() / 64);
        let mut copied = 0;
        for scan in &self.plan.scans {
            out.extend_from_slice(&self.bytes[copied..scan.entropy.start]);
            out.extend(encode_scan(
                &self.plan.frame,
                scan,
                &planes,
                scan.entropy.len(),
            )?);
            copied = scan.entropy.end;
        }
        out.extend_from_slice(&self.bytes[copied..self.plan.end]);
        Ok(out)
    }
}

const fn symbol(run: usize, size: u8) -> u8 {
    // `run` is below 16 here, so the pair fits one byte (T.81 F.1.2.2.1).
    ((run as u8) << 4) | size
}

/// Number of coding units of a scan: MCUs when interleaved, blocks otherwise.
fn units(frame: &Frame, scan: &Scan) -> usize {
    match scan.selectors.as_slice() {
        [single] => {
            let c = &frame.components[single.component];
            c.columns * c.rows
        }
        _ => frame.mcu_columns * frame.mcu_rows,
    }
}

/// Blocks in one coding unit of `scan`.
fn blocks_per_unit(frame: &Frame, scan: &Scan) -> usize {
    match scan.selectors.as_slice() {
        [_] => 1,
        many => many
            .iter()
            .map(|s| frame.components[s.component].h * frame.components[s.component].v)
            .sum(),
    }
}

/// The (selector slot, block index) pairs of coding unit `unit`, in coding order.
fn blocks_of(frame: &Frame, scan: &Scan, unit: usize, out: &mut Vec<(usize, usize)>) {
    out.clear();
    if let [single] = scan.selectors.as_slice() {
        let c = &frame.components[single.component];
        out.push((0, (unit / c.columns) * c.stride + unit % c.columns));
        return;
    }
    let (my, mx) = (unit / frame.mcu_columns, unit % frame.mcu_columns);
    for (slot, s) in scan.selectors.iter().enumerate() {
        let c = &frame.components[s.component];
        for v in 0..c.v {
            for h in 0..c.h {
                out.push((slot, (my * c.v + v) * c.stride + mx * c.h + h));
            }
        }
    }
}

/// The tables of selector `slot`.
fn tables(scan: &Scan, slot: usize) -> Result<(&Huffman, &Huffman), StegoError> {
    let s = scan.selectors.get(slot).ok_or(StegoError::Jpeg)?;
    let dc = scan.dc[s.dc].as_ref().ok_or(StegoError::Jpeg)?;
    let ac = scan.ac[s.ac].as_ref().ok_or(StegoError::Jpeg)?;
    Ok((dc, ac))
}

fn decode_scan(
    bytes: &[u8],
    frame: &Frame,
    scan: &Scan,
    planes: &mut [Vec<i16>],
) -> Result<(), StegoError> {
    let parts = bits::intervals(&bytes[scan.entropy.clone()])?;
    let total = units(frame, scan);
    let per = if scan.restart == 0 {
        total
    } else {
        scan.restart
    };
    if parts.len() != total.div_ceil(per) {
        return Err(StegoError::Jpeg);
    }
    let mut blocks = Vec::new();
    let mut unit = 0;
    for part in &parts {
        let mut reader = Reader::new(part);
        let mut predictions = vec![0_i32; scan.selectors.len()];
        for _ in 0..per.min(total - unit) {
            blocks_of(frame, scan, unit, &mut blocks);
            for &(slot, block) in &blocks {
                let component = scan.selectors[slot].component;
                let (dc, ac) = tables(scan, slot)?;
                let start = block * COEFFICIENTS;
                let target = planes[component]
                    .get_mut(start..start + COEFFICIENTS)
                    .ok_or(StegoError::Jpeg)?;
                decode_block(&mut reader, dc, ac, &mut predictions[slot], target)?;
            }
            unit += 1;
        }
        reader.finish()?;
    }
    Ok(())
}

fn decode_block(
    reader: &mut Reader<'_>,
    dc: &Huffman,
    ac: &Huffman,
    prediction: &mut i32,
    block: &mut [i16],
) -> Result<(), StegoError> {
    let size = dc.decode(reader)?;
    if size > DC_CATEGORY_MAX {
        return Err(StegoError::Jpeg);
    }
    *prediction += reader.amplitude(size)?;
    block[0] = i16::try_from(*prediction).map_err(|_| StegoError::Jpeg)?;
    let mut k = 1;
    while k < COEFFICIENTS {
        let rs = ac.decode(reader)?;
        let (run, size) = (usize::from(rs >> 4), rs & 15);
        if size == 0 {
            if rs != ZRL {
                break;
            }
            k += ZRL_RUN;
            continue;
        }
        k += run;
        if k >= COEFFICIENTS || size > AC_CATEGORY_MAX {
            return Err(StegoError::Jpeg);
        }
        block[ZIGZAG[k]] = i16::try_from(reader.amplitude(size)?).map_err(|_| StegoError::Jpeg)?;
        k += 1;
    }
    Ok(())
}

fn encode_scan(
    frame: &Frame,
    scan: &Scan,
    planes: &[&[i16]],
    size_hint: usize,
) -> Result<Vec<u8>, StegoError> {
    let total = units(frame, scan);
    let mut writer = Writer::with_capacity(size_hint + size_hint / 32);
    let mut predictions = vec![0_i32; scan.selectors.len()];
    let mut blocks = Vec::new();
    for unit in 0..total {
        if scan.restart != 0 && unit != 0 && unit % scan.restart == 0 {
            writer.restart();
            predictions.fill(0);
        }
        blocks_of(frame, scan, unit, &mut blocks);
        for &(slot, block) in &blocks {
            let component = scan.selectors[slot].component;
            let (dc, ac) = tables(scan, slot)?;
            let start = block * COEFFICIENTS;
            let source = planes[component]
                .get(start..start + COEFFICIENTS)
                .ok_or(StegoError::Coding)?;
            encode_block(&mut writer, dc, ac, &mut predictions[slot], source)?;
        }
    }
    Ok(writer.finish())
}

fn put_symbol(writer: &mut Writer, table: &Huffman, symbol: u8) -> Result<(), StegoError> {
    let (code, length) = table.code(symbol).ok_or(StegoError::Coding)?;
    writer.put(u32::from(code), length);
    Ok(())
}

fn encode_block(
    writer: &mut Writer,
    dc: &Huffman,
    ac: &Huffman,
    prediction: &mut i32,
    block: &[i16],
) -> Result<(), StegoError> {
    let difference = i32::from(block[0]) - *prediction;
    *prediction = i32::from(block[0]);
    let size = category(difference);
    if size > DC_CATEGORY_MAX {
        return Err(StegoError::Coding);
    }
    put_symbol(writer, dc, size)?;
    writer.amplitude(difference, size);
    let mut run = 0;
    for &index in &ZIGZAG[1..] {
        let value = i32::from(block[index]);
        if value == 0 {
            run += 1;
            continue;
        }
        while run >= ZRL_RUN {
            put_symbol(writer, ac, ZRL)?;
            run -= ZRL_RUN;
        }
        let size = category(value);
        if size > AC_CATEGORY_MAX {
            return Err(StegoError::Coding);
        }
        put_symbol(writer, ac, symbol(run, size))?;
        writer.amplitude(value, size);
        run = 0;
    }
    if run > 0 {
        put_symbol(writer, ac, EOB)?;
    }
    Ok(())
}
