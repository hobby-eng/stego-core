//! Small matrices over GF(2^8), row-major.

use super::field::{inverse, multiply, power};
use std::ops::Range;

pub(super) struct Matrix {
    rows: usize,
    columns: usize,
    cells: Vec<u8>,
}

impl Matrix {
    pub(super) fn zero(rows: usize, columns: usize) -> Self {
        Self {
            rows,
            columns,
            cells: vec![0; rows * columns],
        }
    }

    /// Rows `r` of the Vandermonde matrix `V[r][c] = r^c` with `columns` columns.
    pub(super) fn vandermonde(rows: Range<usize>, columns: usize) -> Self {
        let mut m = Self::zero(rows.len(), columns);
        for (i, r) in rows.enumerate() {
            for c in 0..columns {
                // Row numbers stop at 255, which fits a field element.
                m.cells[i * columns + c] = power(r as u8, c);
            }
        }
        m
    }

    pub(super) fn get(&self, r: usize, c: usize) -> u8 {
        self.cells[r * self.columns + c]
    }

    pub(super) fn row(&self, r: usize) -> &[u8] {
        &self.cells[r * self.columns..(r + 1) * self.columns]
    }

    pub(super) fn set_row(&mut self, r: usize, values: &[u8]) {
        self.cells[r * self.columns..(r + 1) * self.columns].copy_from_slice(values);
    }

    pub(super) fn multiply(&self, other: &Self) -> Self {
        let mut out = Self::zero(self.rows, other.columns);
        for r in 0..self.rows {
            for c in 0..other.columns {
                let mut sum = 0;
                for i in 0..self.columns {
                    sum ^= multiply(self.get(r, i), other.get(i, c));
                }
                out.cells[r * other.columns + c] = sum;
            }
        }
        out
    }

    /// The inverse by Gauss–Jordan elimination; `None` for a singular or non-square matrix.
    pub(super) fn inverse(&self) -> Option<Self> {
        let n = self.rows;
        if n != self.columns {
            return None;
        }
        let mut work = Self::zero(n, 2 * n);
        for r in 0..n {
            for c in 0..n {
                work.cells[r * 2 * n + c] = self.get(r, c);
            }
            work.cells[r * 2 * n + n + r] = 1;
        }
        for col in 0..n {
            let pivot = (col..n).find(|&r| work.get(r, col) != 0)?;
            if pivot != col {
                for c in 0..2 * n {
                    work.cells.swap(pivot * 2 * n + c, col * 2 * n + c);
                }
            }
            let scale = inverse(work.get(col, col))?;
            for c in 0..2 * n {
                let cell = &mut work.cells[col * 2 * n + c];
                *cell = multiply(*cell, scale);
            }
            for r in (0..n).filter(|&r| r != col) {
                let factor = work.get(r, col);
                if factor != 0 {
                    for c in 0..2 * n {
                        let value = multiply(factor, work.get(col, c));
                        work.cells[r * 2 * n + c] ^= value;
                    }
                }
            }
        }
        let mut out = Self::zero(n, n);
        for r in 0..n {
            out.set_row(r, &work.cells[r * 2 * n + n..(r + 1) * 2 * n]);
        }
        Some(out)
    }
}
