//! Entropy-coded bits: byte stuffing, restart markers and padding (T.81 F.1.2.3, B.1.1.5).

use crate::StegoError;

const MARKER: u8 = 0xFF;
const RST0: u8 = 0xD0;
/// Restart markers count modulo eight (RST0 to RST7).
const RESTART_CYCLE: u8 = 8;

/// Splits a scan's entropy-coded bytes into its restart intervals, without stuffing.
pub(crate) fn intervals(data: &[u8]) -> Result<Vec<Vec<u8>>, StegoError> {
    let mut out = vec![Vec::new()];
    let mut expected = 0_u8;
    let mut at = 0;
    while at < data.len() {
        let byte = data[at];
        at += 1;
        if byte != MARKER {
            push(&mut out, byte);
            continue;
        }
        match data.get(at) {
            Some(0) => {
                push(&mut out, MARKER);
                at += 1;
            }
            Some(&marker) if marker == RST0 + expected => {
                expected = (expected + 1) % RESTART_CYCLE;
                out.push(Vec::new());
                at += 1;
            }
            _ => return Err(StegoError::Jpeg),
        }
    }
    Ok(out)
}

fn push(out: &mut [Vec<u8>], byte: u8) {
    if let Some(last) = out.last_mut() {
        last.push(byte);
    }
}

/// Reads bits, most significant first, from one restart interval without stuffing.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    pub(crate) fn bit(&mut self) -> Result<u8, StegoError> {
        let byte = self.data.get(self.bit / 8).ok_or(StegoError::Jpeg)?;
        let value = (byte >> (7 - self.bit % 8)) & 1;
        self.bit += 1;
        Ok(value)
    }

    /// The next `count` bits as an unsigned number.
    pub(crate) fn take(&mut self, count: u8) -> Result<u32, StegoError> {
        let mut value = 0;
        for _ in 0..count {
            value = value * 2 + u32::from(self.bit()?);
        }
        Ok(value)
    }

    /// The amplitude of category `size` (T.81 F.2.2.1, EXTEND).
    pub(crate) fn amplitude(&mut self, size: u8) -> Result<i32, StegoError> {
        if size == 0 {
            return Ok(0);
        }
        let raw = i32::try_from(self.take(size)?).map_err(|_| StegoError::Jpeg)?;
        Ok(if raw < 1 << (size - 1) {
            raw - (1 << size) + 1
        } else {
            raw
        })
    }

    /// Checks that only one-bit padding follows the last block of the interval.
    pub(crate) fn finish(mut self) -> Result<(), StegoError> {
        let total = self.data.len() * 8;
        if total - self.bit >= 8 {
            return Err(StegoError::Jpeg);
        }
        while self.bit < total {
            if self.bit()? != 1 {
                return Err(StegoError::NotReproducible);
            }
        }
        Ok(())
    }
}

/// Writes bits with byte stuffing; [`Writer::restart`] closes an interval.
pub(crate) struct Writer {
    out: Vec<u8>,
    accumulator: u32,
    filled: u8,
    marker: u8,
}

impl Writer {
    pub(crate) fn with_capacity(bytes: usize) -> Self {
        Self {
            out: Vec::with_capacity(bytes),
            accumulator: 0,
            filled: 0,
            marker: 0,
        }
    }

    /// Writes the low `count` bits of `value`, most significant first.
    pub(crate) fn put(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            self.accumulator = self.accumulator * 2 + ((value >> shift) & 1);
            self.filled += 1;
            if self.filled == 8 {
                self.flush_byte();
            }
        }
    }

    /// Writes `value` in category `size` (the inverse of [`Reader::amplitude`]).
    pub(crate) fn amplitude(&mut self, value: i32, size: u8) {
        if size == 0 {
            return;
        }
        let bits = if value < 0 { value - 1 } else { value };
        self.put(bits.cast_unsigned() & ((1 << size) - 1), size);
    }

    fn flush_byte(&mut self) {
        // The accumulator holds exactly eight bits here.
        let byte = self.accumulator as u8;
        self.out.push(byte);
        if byte == MARKER {
            self.out.push(0);
        }
        self.accumulator = 0;
        self.filled = 0;
    }

    fn pad(&mut self) {
        while self.filled != 0 {
            self.put(1, 1);
        }
    }

    /// Pads the interval with one-bits and writes the next restart marker.
    pub(crate) fn restart(&mut self) {
        self.pad();
        self.out.push(MARKER);
        self.out.push(RST0 + self.marker);
        self.marker = (self.marker + 1) % RESTART_CYCLE;
    }

    /// Pads the last interval and returns the bytes.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.pad();
        self.out
    }
}

/// The category (number of amplitude bits) of `value` (T.81 F.1.2.1.1).
pub(crate) const fn category(value: i32) -> u8 {
    (u32::BITS - value.unsigned_abs().leading_zeros()) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuffing_and_restart_markers_are_removed_and_written_back() {
        let data = [0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56, 0xFF, 0xD1, 0x78];
        let parts = intervals(&data).unwrap();
        assert_eq!(parts, vec![vec![0x12, 0xFF, 0x34], vec![0x56], vec![0x78]]);
        let mut w = Writer::with_capacity(16);
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                w.restart();
            }
            for byte in part {
                w.put(u32::from(*byte), 8);
            }
        }
        assert_eq!(w.finish(), data);
    }

    #[test]
    fn a_restart_marker_out_of_order_is_refused() {
        assert!(intervals(&[0x12, 0xFF, 0xD1, 0x34]).is_err());
    }

    #[test]
    fn amplitudes_round_trip_in_every_category() {
        for value in [-1023, -512, -3, -1, 0, 1, 2, 3, 255, 1023] {
            let size = category(value);
            let mut w = Writer::with_capacity(4);
            w.amplitude(value, size);
            let parts = intervals(&w.finish()).unwrap();
            let mut r = Reader::new(&parts[0]);
            assert_eq!(r.amplitude(size).unwrap(), value, "value {value}");
        }
        // T.81 table F.1: categories of 1, 3, 4 and 1023.
        assert_eq!(
            [category(1), category(-3), category(4), category(1023)],
            [1, 2, 3, 10]
        );
    }
}
