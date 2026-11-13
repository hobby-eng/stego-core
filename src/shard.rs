//! Reed–Solomon erasure coding over GF(2^8): `k` data pieces become `n` pieces, any `k` of which
//! rebuild the data.
//!
//! The code is systematic: the first `k` pieces are the data itself. Parity row `i` is row `i` of
//! the Vandermonde matrix `V[r][c] = r^c` times the inverse of `V`'s top `k` rows, in the field
//! with polynomial `x^8 + x^4 + x^3 + x^2 + 1` (0x11D): the construction of Backblaze's and
//! klauspost's codes and of the `reed-solomon-erasure` crate, so their pieces and these agree
//! byte for byte. A row depends only on its number and `k`, so pieces can be added to a set later
//! without touching the existing ones.
//!
//! Only missing pieces are rebuilt: a piece that is present must be right. Every piece of this
//! crate sits inside a record whose tag was checked before it reaches the decoder.

mod field;
mod matrix;

use field::add_scaled;
use matrix::Matrix;

/// Most pieces of a set: the field has 256 elements.
pub(crate) const PIECES_MAX: usize = 256;

/// Why coding was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShardError {
    /// `k` is 0, or above `n`, or `n` above [`PIECES_MAX`].
    Shape,
    /// The pieces are not all of the same length, or a number repeats or is out of range.
    Pieces,
    /// Fewer than `k` pieces are present.
    TooFew,
}

/// A code of `k` data pieces in a set of up to [`PIECES_MAX`] pieces.
pub(crate) struct Code {
    k: usize,
    /// Rows of the inverse of the Vandermonde top `k` rows: the factor that makes rows systematic.
    top_inverse: Matrix,
}

impl Code {
    pub(crate) fn new(k: usize) -> Result<Self, ShardError> {
        if k == 0 || k > PIECES_MAX {
            return Err(ShardError::Shape);
        }
        let top = Matrix::vandermonde(0..k, k);
        let top_inverse = top.inverse().ok_or(ShardError::Shape)?;
        Ok(Self { k, top_inverse })
    }

    /// Row `index` of the systematic encoding matrix: the unit row for a data piece, the
    /// Vandermonde row times the top inverse for a parity piece.
    fn row(&self, index: usize) -> Vec<u8> {
        if index < self.k {
            let mut unit = vec![0; self.k];
            unit[index] = 1;
            return unit;
        }
        Matrix::vandermonde(index..index + 1, self.k)
            .multiply(&self.top_inverse)
            .row(0)
            .to_vec()
    }

    /// Piece `index` (0 to 255) of `data`'s `k` equal pieces: a copy for a data piece, a parity
    /// piece otherwise. It is how a set is written, how a lost piece is made again and how a set
    /// grows later.
    pub(crate) fn piece(&self, data: &[&[u8]], index: usize) -> Result<Vec<u8>, ShardError> {
        if data.len() != self.k || index >= PIECES_MAX {
            return Err(ShardError::Shape);
        }
        let length = data[0].len();
        if data.iter().any(|piece| piece.len() != length) {
            return Err(ShardError::Pieces);
        }
        let mut out = vec![0; length];
        for (&factor, source) in self.row(index).iter().zip(data) {
            add_scaled(&mut out, source, factor);
        }
        Ok(out)
    }

    /// The `k` data pieces from any `k` or more of the set's pieces, given as `(number, piece)`.
    pub(crate) fn rebuild(&self, pieces: &[(usize, &[u8])]) -> Result<Vec<Vec<u8>>, ShardError> {
        let mut numbers: Vec<usize> = pieces.iter().map(|&(number, _)| number).collect();
        numbers.sort_unstable();
        numbers.dedup();
        if numbers.len() != pieces.len() || numbers.last().is_some_and(|&n| n >= PIECES_MAX) {
            return Err(ShardError::Pieces);
        }
        let length = pieces.first().map_or(0, |(_, piece)| piece.len());
        if pieces.iter().any(|(_, piece)| piece.len() != length) {
            return Err(ShardError::Pieces);
        }
        if pieces.len() < self.k {
            return Err(ShardError::TooFew);
        }
        // Data pieces that are present are taken as they are; the rest need k pieces in all.
        let chosen = &pieces[..self.k];
        let mut rows = Matrix::zero(self.k, self.k);
        for (r, &(number, _)) in chosen.iter().enumerate() {
            rows.set_row(r, &self.row(number));
        }
        let decode = rows.inverse().ok_or(ShardError::Pieces)?;
        let mut data = vec![vec![0; length]; self.k];
        for (d, out) in data.iter_mut().enumerate() {
            if let Some(&(_, piece)) = pieces.iter().find(|&&(number, _)| number == d) {
                out.copy_from_slice(piece);
                continue;
            }
            for (c, &(_, piece)) in chosen.iter().enumerate() {
                add_scaled(out, piece, decode.get(d, c));
            }
        }
        Ok(data)
    }

    /// Whether `pieces`, given as `(number, piece)`, all belong to one set: the data their first
    /// `k` give produce every other piece.
    pub(crate) fn consistent(&self, pieces: &[(usize, &[u8])]) -> Result<bool, ShardError> {
        let data = self.rebuild(pieces)?;
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        for &(number, piece) in pieces {
            if self.piece(&refs, number)? != piece {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// The multiplicative inverse in the field, for tests of the field itself.
#[cfg(test)]
pub(crate) fn field_inverse(value: u8) -> Option<u8> {
    field::inverse(value)
}

#[cfg(test)]
mod tests;
