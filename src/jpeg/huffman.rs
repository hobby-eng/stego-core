//! Canonical Huffman tables of a JPEG file (T.81 annex C), for reading and for writing.

use super::bits::Reader;
use crate::StegoError;

const LENGTHS: usize = 16;

/// One table: the count of codes of each length and the symbols in code order.
#[derive(Clone, Debug)]
pub(crate) struct Huffman {
    counts: [u8; LENGTHS],
    symbols: Vec<u8>,
    /// The code and its length for each symbol, or length 0 for a symbol the table lacks.
    codes: Vec<(u16, u8)>,
}

impl Huffman {
    /// Reads a table from a DHT body after its class byte; returns it and the bytes used.
    pub(crate) fn read(bytes: &[u8]) -> Result<(Self, usize), StegoError> {
        if bytes.len() < LENGTHS {
            return Err(StegoError::Jpeg);
        }
        let mut counts = [0; LENGTHS];
        counts.copy_from_slice(&bytes[..LENGTHS]);
        let count = counts.iter().map(|v| usize::from(*v)).sum::<usize>();
        if count == 0 || count > 256 || bytes.len() < LENGTHS + count {
            return Err(StegoError::Jpeg);
        }
        let mut available = 1_i32;
        for n in counts {
            available = available * 2 - i32::from(n);
            if available < 0 {
                return Err(StegoError::Jpeg);
            }
        }
        // A complete tree would assign the all-ones code that T.81 reserves for padding.
        if available == 0 {
            return Err(StegoError::Jpeg);
        }
        let symbols = bytes[LENGTHS..LENGTHS + count].to_vec();
        let mut codes = vec![(0_u16, 0_u8); 256];
        let mut code = 0_u16;
        let mut next = symbols.iter();
        for (length, &n) in (1_u8..).zip(&counts) {
            for _ in 0..n {
                let symbol = *next.next().ok_or(StegoError::Jpeg)?;
                // A symbol listed twice would decode one way and encode another.
                if codes[usize::from(symbol)].1 != 0 {
                    return Err(StegoError::Jpeg);
                }
                codes[usize::from(symbol)] = (code, length);
                code += 1;
            }
            code <<= 1;
        }
        Ok((
            Self {
                counts,
                symbols,
                codes,
            },
            LENGTHS + count,
        ))
    }

    /// Decodes one symbol.
    pub(crate) fn decode(&self, bits: &mut Reader<'_>) -> Result<u8, StegoError> {
        let mut code = 0_usize;
        let mut first = 0;
        let mut base = 0;
        for count in self.counts {
            code = code * 2 + usize::from(bits.bit()?);
            let count = usize::from(count);
            if code >= first && code < first + count {
                return Ok(self.symbols[base + code - first]);
            }
            base += count;
            first = (first + count) * 2;
        }
        Err(StegoError::Jpeg)
    }

    /// The code and its length for `symbol`; `None` when the table has no code for it.
    pub(crate) fn code(&self, symbol: u8) -> Option<(u16, u8)> {
        let found = self.codes[usize::from(symbol)];
        (found.1 != 0).then_some(found)
    }

    /// Whether the table has a code for `symbol`.
    pub(crate) fn has(&self, symbol: u8) -> bool {
        self.codes[usize::from(symbol)].1 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The luminance DC table of T.81 table K.3.
    const K3: [u8; 28] = [
        0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    ];

    #[test]
    fn codes_follow_table_k3() {
        let (table, used) = Huffman::read(&K3).unwrap();
        assert_eq!(used, 28);
        // T.81 table K.3: category 0 is 00, category 5 is 110, category 11 is 111111110.
        assert_eq!(table.code(0), Some((0b00, 2)));
        assert_eq!(table.code(5), Some((0b110, 3)));
        assert_eq!(table.code(11), Some((0b1_1111_1110, 9)));
        assert_eq!(table.code(12), None);
    }

    #[test]
    fn a_complete_tree_and_a_repeated_symbol_are_refused() {
        let complete = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2];
        assert!(Huffman::read(&complete).is_err());
        let repeated = [0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1];
        assert!(Huffman::read(&repeated).is_err());
    }
}
