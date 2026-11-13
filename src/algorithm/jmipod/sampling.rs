//! Position bookkeeping, tiles, the JPEG DCT and the decoded raster used by the statistics pass.

use crate::algorithm::model::{BLOCK, CostError, DctPlane, Permitted};

pub(crate) const SIDE: usize = 8;
pub(crate) const TILE_BLOCKS: usize = 64;

/// Validated positions with the permutation that sorts them.
pub(crate) struct Selection<'a> {
    positions: &'a [usize],
    permitted: &'a [Permitted],
    /// Indexes into `positions` in ascending position order; `None` when already ascending.
    order: Option<Vec<u32>>,
    capacity: usize,
    /// Coefficient count of the plane: ascending distinct positions of this length are `0..N`.
    dense_len: usize,
}

impl<'a> Selection<'a> {
    pub(crate) fn new(
        plane: &DctPlane,
        positions: &'a [usize],
        permitted: &'a [Permitted],
    ) -> Result<Self, CostError> {
        // The shared validator currently leaves this last multiplication unchecked.
        // Check the caller-controlled dimensions before entering that validator.
        plane
            .blocks_wide
            .checked_mul(plane.blocks_high)
            .and_then(|n| n.checked_mul(BLOCK))
            .ok_or(CostError::Shape)?;
        plane.validate()?;
        if positions.len() != permitted.len()
            || positions.iter().any(|&p| p >= plane.coefficients.len())
        {
            return Err(CostError::Permission);
        }
        // The sorting permutation is stored as u32 (4 bytes per position); 200 MP is 2e8.
        let count = u32::try_from(positions.len()).map_err(|_| CostError::Unsupported)?;
        let sorted = positions.windows(2).all(|p| p[0] < p[1]);
        let order = if sorted {
            None
        } else {
            let mut indexes: Vec<u32> = (0..count).collect();
            indexes.sort_unstable_by_key(|&i| positions[i as usize]);
            if indexes
                .windows(2)
                .any(|p| positions[p[0] as usize] == positions[p[1] as usize])
            {
                return Err(CostError::Permission);
            }
            Some(indexes)
        };
        if permitted
            .iter()
            .any(|p| matches!(p, Permitted::Plus | Permitted::Minus))
        {
            return Err(CostError::Unsupported);
        }
        let capacity = permitted.iter().filter(|&&p| p == Permitted::Both).count();
        Ok(Self {
            positions,
            permitted,
            order,
            capacity,
            dense_len: plane.coefficients.len(),
        })
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }
    pub(crate) fn len(&self) -> usize {
        self.positions.len()
    }
    /// Indexes into `positions` in ascending position order, `None` when already ascending.
    pub(crate) fn order(&self) -> Option<&[u32]> {
        self.order.as_deref()
    }
    fn original(&self, rank: usize) -> usize {
        self.order
            .as_ref()
            .map_or(rank, |order| order[rank] as usize)
    }
    fn lower_bound(&self, position: usize) -> usize {
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let middle = low + (high - low) / 2;
            if self.positions[self.original(middle)] < position {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low
    }
    /// Index into `positions` of `position`, if it is selected (any permission).
    pub(crate) fn index_of(&self, position: usize) -> Option<usize> {
        if self.order.is_none() && self.len() == self.dense_len {
            return Some(position);
        }
        let rank = self.lower_bound(position);
        (rank < self.len() && self.positions[self.original(rank)] == position)
            .then(|| self.original(rank))
    }
    /// Permission of the position at `index` into `positions`.
    pub(crate) fn permission(&self, index: usize) -> Permitted {
        self.permitted[index]
    }
    pub(crate) fn visit(
        &self,
        tile: BlockRect,
        blocks_wide: usize,
        mut f: impl FnMut(usize, usize),
    ) {
        for by in tile.y..tile.y + tile.height {
            let start = (by * blocks_wide + tile.x) * BLOCK;
            let end = start + tile.width * BLOCK;
            for rank in self.lower_bound(start)..self.lower_bound(end) {
                let index = self.original(rank);
                if self.permitted[index] == Permitted::Both {
                    f(self.positions[index], index);
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BlockRect {
    pub(crate) x: usize,
    pub(crate) y: usize,
    pub(crate) width: usize,
    pub(crate) height: usize,
}

impl BlockRect {
    pub(crate) fn tile(plane: &DctPlane, x: usize, y: usize, side: usize) -> Self {
        Self {
            x,
            y,
            width: side.min(plane.blocks_wide - x),
            height: side.min(plane.blocks_high - y),
        }
    }
    pub(crate) fn expanded(self, plane: &DctPlane) -> Self {
        let x = self.x.saturating_sub(1);
        let y = self.y.saturating_sub(1);
        Self {
            x,
            y,
            width: (self.x + self.width)
                .saturating_add(1)
                .min(plane.blocks_wide)
                - x,
            height: (self.y + self.height)
                .saturating_add(1)
                .min(plane.blocks_high)
                - y,
        }
    }
    pub(crate) fn index(self, x: usize, y: usize) -> usize {
        (y - self.y) * self.width + x - self.x
    }
    pub(crate) fn neighbors(self, x: usize, y: usize, mut f: impl FnMut(usize, usize, usize)) {
        for dy in [-1isize, 0, 1] {
            let by = y
                .saturating_add_signed(dy)
                .clamp(self.y, self.y + self.height - 1);
            for dx in [-1isize, 0, 1] {
                let bx = x
                    .saturating_add_signed(dx)
                    .clamp(self.x, self.x + self.width - 1);
                // Eq. (27), before division by 20. Duplicate edge blocks to keep
                // the same symmetric extension used for residual patches.
                let weight = match (dx == 0, dy == 0) {
                    (true, true) => 4,
                    (false, false) => 1,
                    _ => 3,
                };
                f(bx, by, weight);
            }
        }
    }
}

pub(crate) struct Dct {
    pub(crate) basis: [[f64; SIDE]; SIDE],
}

impl Dct {
    pub(crate) fn new() -> Self {
        let mut basis = [[0.0; SIDE]; SIDE];
        for (frequency, row) in basis.iter_mut().enumerate() {
            let scale = if frequency == 0 {
                1.0 / (SIDE as f64).sqrt()
            } else {
                0.5
            };
            for (pixel, value) in row.iter_mut().enumerate() {
                *value = scale
                    * (std::f64::consts::PI * (pixel as f64 + 0.5) * frequency as f64
                        / SIDE as f64)
                        .cos();
            }
        }
        Self { basis }
    }
    /// Dequantized inverse DCT of one block. Zero coefficients and empty columns are skipped
    /// (adding a zero term is exact), which pays off in the sparse high frequencies of JPEG.
    pub(crate) fn inverse(&self, coefficients: &[i16], quant: &[u16; BLOCK]) -> [f64; BLOCK] {
        let mut intermediate = [0.0; BLOCK];
        let mut used = [false; SIDE];
        for (k, (&level, &step)) in coefficients.iter().zip(quant).enumerate() {
            if level == 0 {
                continue;
            }
            let (u, v) = (k / SIDE, k % SIDE);
            used[v] = true;
            let value = f64::from(level) * f64::from(step);
            for y in 0..SIDE {
                intermediate[y * SIDE + v] += self.basis[u][y] * value;
            }
        }
        // Retain JPEG's centered domain. Zero-padded Wiener boundaries make an
        // added constant affect the globally estimated noise, not only the edges.
        let mut output = [0.0; BLOCK];
        for y in 0..SIDE {
            for x in 0..SIDE {
                for v in (0..SIDE).filter(|&v| used[v]) {
                    output[y * SIDE + x] += intermediate[y * SIDE + v] * self.basis[v][x];
                }
            }
        }
        output
    }
    pub(crate) fn variance(&self, pixels: &[f64; BLOCK], mask: u64) -> [f64; BLOCK] {
        let mut intermediate = [0.0; BLOCK];
        let mut result = [0.0; BLOCK];
        for u in 0..SIDE {
            if mask & (255u64 << (u * SIDE)) == 0 {
                continue;
            }
            for x in 0..SIDE {
                for y in 0..SIDE {
                    intermediate[u * SIDE + x] += self.basis[u][y].powi(2) * pixels[y * SIDE + x];
                }
            }
            for v in 0..SIDE {
                if mask & (1u64 << (u * SIDE + v)) == 0 {
                    continue;
                }
                let mut value = 0.0;
                for x in 0..SIDE {
                    value += intermediate[u * SIDE + x] * self.basis[v][x].powi(2);
                }
                // Variance is in the unquantized DCT domain, TIFS Eq. (25).
                result[u * SIDE + v] = value.max(1e-10);
            }
        }
        result
    }
}

pub(crate) struct Raster {
    pub(crate) x: usize,
    pub(crate) y: usize,
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) full_width: usize,
    pub(crate) full_height: usize,
    pub(crate) values: Vec<f64>,
}

impl Raster {
    pub(crate) fn reconstruct(
        plane: &DctPlane,
        rect: BlockRect,
        dct: &Dct,
        needed: Option<&[bool]>,
    ) -> Self {
        let width = rect.width * SIDE;
        let height = rect.height * SIDE;
        let mut values = vec![0.0; width * height];
        for by in rect.y..rect.y + rect.height {
            for bx in rect.x..rect.x + rect.width {
                if needed.is_some_and(|mask| !mask[rect.index(bx, by)]) {
                    continue;
                }
                let start = (by * plane.blocks_wide + bx) * BLOCK;
                let pixels = dct.inverse(&plane.coefficients[start..start + BLOCK], &plane.quant);
                for y in 0..SIDE {
                    let offset = ((by - rect.y) * SIDE + y) * width + (bx - rect.x) * SIDE;
                    values[offset..offset + SIDE]
                        .copy_from_slice(&pixels[y * SIDE..(y + 1) * SIDE]);
                }
            }
        }
        Self {
            x: rect.x * SIDE,
            y: rect.y * SIDE,
            width,
            height,
            full_width: plane.blocks_wide * SIDE,
            full_height: plane.blocks_high * SIDE,
            values,
        }
    }
    pub(crate) fn at(&self, x: usize, y: usize) -> f64 {
        if x < self.x || y < self.y || x >= self.x + self.width || y >= self.y + self.height {
            return 0.0;
        }
        self.values[(y - self.y) * self.width + x - self.x]
    }
    pub(crate) fn moments(&self, x: usize, y: usize) -> (f64, f64) {
        let window = [
            self.at(x, y),
            self.at(x + 1, y),
            self.at(x, y + 1),
            self.at(x + 1, y + 1),
        ];
        let mean = window.iter().sum::<f64>() / 4.0;
        let variance = (window.iter().map(|v| v * v).sum::<f64>() / 4.0 - mean * mean).max(0.0);
        (mean, variance)
    }
    pub(crate) fn residual(mut self, noise: f64) -> Self {
        let mut values = Vec::with_capacity(self.values.len());
        for y in self.y..self.y + self.height {
            for x in self.x..self.x + self.width {
                let (mean, variance) = self.moments(x, y);
                let attenuation = if variance > noise {
                    noise / variance
                } else {
                    1.0
                };
                values.push((self.at(x, y) - mean) * attenuation);
            }
        }
        self.values = values;
        self
    }
    pub(crate) fn mirror(&self, x: isize, y: isize) -> f64 {
        fn coordinate(value: isize, size: usize) -> usize {
            if value < 0 {
                (-value - 1) as usize
            } else if value as usize >= size {
                2 * size - value as usize - 1
            } else {
                value as usize
            }
        }
        self.at(
            coordinate(x, self.full_width),
            coordinate(y, self.full_height),
        )
    }
}

pub(crate) struct Sum {
    total: f64,
    correction: f64,
}
impl Sum {
    pub(crate) fn new() -> Self {
        Self {
            total: 0.0,
            correction: 0.0,
        }
    }
    pub(crate) fn add(&mut self, value: f64) {
        let adjusted = value - self.correction;
        let next = self.total + adjusted;
        self.correction = (next - self.total) - adjusted;
        self.total = next;
    }
    pub(crate) fn value(&self) -> f64 {
        self.total
    }
}
