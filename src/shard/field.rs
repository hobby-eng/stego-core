//! GF(2^8) with the polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D) and generator 2.

/// The reduction polynomial without its x^8 term.
const POLYNOMIAL: u16 = 0x11D;

/// `EXP[i]` is 2^i for i in 0..510, twice round the group so that `EXP[log a + log b]` needs
/// no reduction; `LOG[a]` is the discrete logarithm of a nonzero `a`.
const TABLES: ([u8; 510], [u8; 256]) = tables();

const fn tables() -> ([u8; 510], [u8; 256]) {
    let mut exp = [0_u8; 510];
    let mut log = [0_u8; 256];
    let mut value: u16 = 1;
    let mut i = 0;
    while i < 255 {
        // `value` stays below 256 after each reduction.
        exp[i] = value as u8;
        exp[i + 255] = value as u8;
        log[value as usize] = i as u8;
        value <<= 1;
        if value & 0x100 != 0 {
            value ^= POLYNOMIAL;
        }
        i += 1;
    }
    (exp, log)
}

/// The product of `a` and `b`.
pub(super) const fn multiply(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = (&TABLES.0, &TABLES.1);
    exp[log[a as usize] as usize + log[b as usize] as usize]
}

/// The inverse of a nonzero `a`.
pub(super) const fn inverse(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    let (exp, log) = (&TABLES.0, &TABLES.1);
    Some(exp[255 - log[a as usize] as usize])
}

/// `a` to the power `n`, with 0^0 = 1.
pub(super) const fn power(a: u8, n: usize) -> u8 {
    if n == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let (exp, log) = (&TABLES.0, &TABLES.1);
    exp[(log[a as usize] as usize * n) % 255]
}

/// `out += factor * source`, byte by byte.
pub(super) fn add_scaled(out: &mut [u8], source: &[u8], factor: u8) {
    match factor {
        0 => {}
        1 => out.iter_mut().zip(source).for_each(|(o, &s)| *o ^= s),
        _ => out
            .iter_mut()
            .zip(source)
            .for_each(|(o, &s)| *o ^= multiply(factor, s)),
    }
}
