//! The hidden record of the decoy mode: a wet-paper code (Fridrich, Goljan, Soukal 2004) on the
//! second bit of |q| at the sites the decoy changes. The sender picks a random solution among all
//! that give the message, so the changed bits look like coin flips, as in a file without a hidden
//! record.

/// The second bit of |q|: `⌊|q| / 2⌋ mod 2`. The two neighbours of any |q| >= 2 differ in it.
#[must_use]
pub fn magnitude_bit(q: i32) -> u8 {
    ((q.unsigned_abs() >> 1) & 1) as u8
}

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Words of a k-bit vector.
fn words(bits: usize) -> usize {
    bits.div_ceil(64)
}

/// XORs the keyed column of `position` (k bits) into `acc`.
fn add_column(acc: &mut [u64], key: u64, position: u64, bits: usize) {
    let base = mix(key ^ mix(position.wrapping_add(0x9E37_79B9_7F4A_7C15)));
    let last = acc.len().saturating_sub(1);
    for (w, word) in acc.iter_mut().enumerate() {
        let mut value = mix(base.wrapping_add((w as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        if w == last && !bits.is_multiple_of(64) {
            value &= (1u64 << (bits % 64)) - 1;
        }
        *word ^= value;
    }
}

/// The syndrome of k bits over sites `(position, bit)`: the XOR of the columns of the sites whose
/// bit is 1.
#[must_use]
pub fn syndrome(sites: impl Iterator<Item = (u64, u8)>, key: u64, bits: usize) -> Vec<u64> {
    let mut acc = vec![0u64; words(bits)];
    for (position, bit) in sites {
        if bit == 1 {
            add_column(&mut acc, key, position, bits);
        }
    }
    acc
}

/// The k-bit vector of a message given as one bit per byte.
#[must_use]
pub fn pack(message: &[u8]) -> Vec<u64> {
    let mut out = vec![0u64; words(message.len())];
    for (i, &bit) in message.iter().enumerate() {
        out[i / 64] |= u64::from(bit & 1) << (i % 64);
    }
    out
}

fn bit(row: &[u64], i: usize) -> bool {
    (row[i / 64] >> (i % 64)) & 1 == 1
}

/// Solves `H_free · x = target` for the free sites' bits `x` (one per position of `free`, in that
/// order) with k = `bits` equations, choosing the variables outside the pivots from `coins`, so
/// that the solution is uniform among all solutions. Returns None when the system has no solution
/// (rank below k and the target outside the span), which with at least 64 more free sites than
/// bits happens with probability below 2^-64.
#[must_use]
pub fn solve(
    free: &[u64],
    key: u64,
    bits: usize,
    target: &[u64],
    coins: &mut impl FnMut() -> u64,
) -> Option<Vec<u8>> {
    let f = free.len();
    let row_words = words(f);
    // Row r of the system holds bit r of every free column.
    let mut rows = vec![vec![0u64; row_words]; bits];
    let mut column = vec![0u64; words(bits)];
    for (c, &position) in free.iter().enumerate() {
        column.iter_mut().for_each(|w| *w = 0);
        add_column(&mut column, key, position, bits);
        for (r, row) in rows.iter_mut().enumerate() {
            if bit(&column, r) {
                row[c / 64] |= 1u64 << (c % 64);
            }
        }
    }
    let mut rhs: Vec<bool> = (0..bits).map(|r| bit(target, r)).collect();
    // Reduced row echelon form; `pivots[r]` is the column of row r's leading one.
    let mut pivots = Vec::with_capacity(bits);
    let mut next = 0;
    for c in 0..f {
        if next == bits {
            break;
        }
        let Some(found) = (next..bits).find(|&r| bit(&rows[r], c)) else {
            continue;
        };
        rows.swap(next, found);
        rhs.swap(next, found);
        let (pivot_row, pivot_rhs) = (rows[next].clone(), rhs[next]);
        for r in 0..bits {
            if r != next && bit(&rows[r], c) {
                for (a, b) in rows[r].iter_mut().zip(&pivot_row) {
                    *a ^= b;
                }
                rhs[r] ^= pivot_rhs;
            }
        }
        pivots.push(c);
        next += 1;
    }
    // Rows without a pivot are zero: their target bit must be zero too.
    if rhs[next..].iter().any(|&b| b) {
        return None;
    }
    // Variables outside the pivots from the coins, then each pivot from its row.
    let mut x = vec![0u64; row_words];
    let mut is_pivot = vec![false; f];
    for &c in &pivots {
        is_pivot[c] = true;
    }
    for c in (0..f).filter(|&c| !is_pivot[c]) {
        if coins() & 1 == 1 {
            x[c / 64] |= 1u64 << (c % 64);
        }
    }
    for (r, &c) in pivots.iter().enumerate() {
        let others = rows[r]
            .iter()
            .zip(&x)
            .fold(0u32, |acc, (a, b)| acc ^ (a & b).count_ones())
            & 1;
        if u32::from(rhs[r]) ^ others == 1 {
            x[c / 64] |= 1u64 << (c % 64);
        }
    }
    Some((0..f).map(|c| u8::from(bit(&x, c))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(seed: u64) -> impl FnMut() -> u64 {
        let mut s = seed;
        move || {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            mix(s)
        }
    }

    #[test]
    fn neighbours_of_two_and_up_differ_in_the_magnitude_bit() {
        for q in [-9, -4, -3, -2, 2, 3, 4, 5, 8, 9] {
            assert_ne!(magnitude_bit(q + 1), magnitude_bit(q - 1), "q = {q}");
        }
    }

    #[test]
    fn a_solved_record_reads_back_over_all_sites() {
        let key = 0x1234;
        let mut next = stream(7);
        // 3,000 sites, of which 400 free; 300 hidden bits.
        let mut sites: Vec<(u64, u8)> = (0..3000u64)
            .map(|p| (p * 7 + 3, (next() & 1) as u8))
            .collect();
        let free: Vec<usize> = (0..3000).filter(|i| i % 7 == 0).take(400).collect();
        let bits = 300;
        let message: Vec<u8> = (0..bits).map(|_| (next() & 1) as u8).collect();
        let rest = syndrome(
            sites
                .iter()
                .enumerate()
                .filter(|(i, _)| !free.contains(i))
                .map(|(_, &s)| s),
            key,
            bits,
        );
        let target: Vec<u64> = pack(&message)
            .iter()
            .zip(&rest)
            .map(|(a, b)| a ^ b)
            .collect();
        let positions: Vec<u64> = free.iter().map(|&i| sites[i].0).collect();
        let x = solve(&positions, key, bits, &target, &mut stream(9)).unwrap_or_default();
        assert_eq!(x.len(), free.len());
        for (&i, &b) in free.iter().zip(&x) {
            sites[i].1 = b;
        }
        assert_eq!(syndrome(sites.iter().copied(), key, bits), pack(&message));
    }

    #[test]
    fn different_coins_give_different_solutions_of_one_system() {
        let positions: Vec<u64> = (0..200).collect();
        let target = pack(&[1u8; 100]);
        let a = solve(&positions, 5, 100, &target, &mut stream(1)).unwrap_or_default();
        let b = solve(&positions, 5, 100, &target, &mut stream(2)).unwrap_or_default();
        assert_ne!(a, b);
        assert_eq!(syndrome(positions.iter().copied().zip(a), 5, 100), target);
        assert_eq!(syndrome(positions.iter().copied().zip(b), 5, 100), target);
    }
}
