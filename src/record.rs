//! The encrypted record a layer carries: a random nonce, the padded body and its tag.
//!
//! The body holds the length and bytes of one part of the content, padded with random bytes to
//! one of a fixed list of sizes, so that the number of changed coefficients tells only the size class.
//! A reader does not know the size and tries each class; a wrong password or a wrong class fails
//! the tag.

use crate::StegoError;
use crate::keys::KEY_BYTES;
use crate::random::Random;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
pub(crate) const LENGTH_BYTES: usize = 4;
const AAD_LABEL: &[u8] = b"stego-core 1 record";
/// Smallest body.
const FIRST_BODY: usize = 64;
/// Largest body: 64 MiB, more than any photo carries.
const LAST_BODY: usize = 64 << 20;

/// Body sizes: four steps per doubling (64, 80, 96, 112, 128, 160, …), so padding wastes at
/// most a quarter.
pub(crate) fn bodies() -> impl Iterator<Item = usize> {
    (0..)
        .map(|octave| FIRST_BODY << octave)
        .take_while(|&base| base <= LAST_BODY)
        .flat_map(|base| (0..4).map(move |quarter| base + base / 4 * quarter))
}

/// The smallest body that holds `plain` bytes.
pub(crate) fn body_for(plain: usize) -> Result<usize, StegoError> {
    let needed = LENGTH_BYTES + plain;
    bodies()
        .find(|&body| body >= needed)
        .ok_or(StegoError::MessageLong)
}

/// Bits of a record whose body has `body` bytes.
pub(crate) const fn record_bits(body: usize) -> usize {
    (NONCE_BYTES + body + TAG_BYTES) * 8
}

/// What a record is bound to: the photo, the layer and the site rule, and its size.
pub(crate) fn associated(context: &[u8; KEY_BYTES], layer: u8, rule: u8, body: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LABEL.len() + KEY_BYTES + 6);
    aad.extend_from_slice(AAD_LABEL);
    aad.extend_from_slice(context);
    aad.push(layer);
    aad.push(rule);
    // Bodies stop at 64 MiB, below `u32::MAX`.
    aad.extend_from_slice(&(body as u32).to_be_bytes());
    aad
}

/// Encrypts `plain` into a record with a body of `body` bytes.
pub(crate) fn seal(
    plain_in: &[u8],
    body: usize,
    key: &[u8; KEY_BYTES],
    aad: &[u8],
    random: &mut dyn Random,
) -> Result<Zeroizing<Vec<u8>>, StegoError> {
    let length = plain_in.len();
    if LENGTH_BYTES + length > body {
        return Err(StegoError::MessageLong);
    }
    let mut record = Zeroizing::new(vec![0_u8; NONCE_BYTES + body + TAG_BYTES]);
    random.fill(&mut record[..NONCE_BYTES + body])?;
    let plain = &mut record[NONCE_BYTES..NONCE_BYTES + body];
    plain[..LENGTH_BYTES].copy_from_slice(&(length as u32).to_be_bytes());
    plain[LENGTH_BYTES..LENGTH_BYTES + length].copy_from_slice(plain_in);
    let (head, rest) = record.split_at_mut(NONCE_BYTES);
    let nonce = XNonce::try_from(&head[..]).map_err(|_| StegoError::Crypto)?;
    let (plain, tag_out) = rest.split_at_mut(body);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StegoError::Crypto)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, plain.into())
        .map_err(|_| StegoError::Crypto)?;
    tag_out.copy_from_slice(&tag);
    Ok(record)
}

/// Decrypts a record; `None` when the key, the size class or the photo does not match.
pub(crate) fn open(record: &[u8], key: &[u8; KEY_BYTES], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let body = record.len().checked_sub(NONCE_BYTES + TAG_BYTES)?;
    let nonce = XNonce::try_from(&record[..NONCE_BYTES]).ok()?;
    let tag = Tag::try_from(&record[NONCE_BYTES + body..]).ok()?;
    let mut plain = Zeroizing::new(record[NONCE_BYTES..NONCE_BYTES + body].to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher
        .decrypt_inout_detached(&nonce, aad, plain.as_mut_slice().into(), &tag)
        .ok()?;
    let length = usize::try_from(u32::from_be_bytes(
        plain.get(..LENGTH_BYTES)?.try_into().ok()?,
    ))
    .ok()?;
    Some(Zeroizing::new(
        plain
            .get(LENGTH_BYTES..LENGTH_BYTES.checked_add(length)?)?
            .to_vec(),
    ))
}

/// Bits of `bytes`, most significant first, one per byte, as the coders take them.
pub(crate) fn to_bits(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        bytes
            .iter()
            .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect(),
    )
}

/// Bytes of `bits` (one per byte, most significant first); the length is a multiple of eight.
pub(crate) fn from_bits(bits: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        bits.as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| chunk.iter().fold(0_u8, |acc, &bit| acc << 1 | (bit & 1)))
            .collect(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A deterministic source for tests only.
    pub(crate) struct Counter(pub u8);

    impl Random for Counter {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), StegoError> {
            for b in bytes {
                self.0 = self.0.wrapping_mul(197).wrapping_add(31);
                *b = self.0;
            }
            Ok(())
        }
    }

    #[test]
    fn bodies_grow_by_quarters_from_64_bytes() {
        let first: Vec<usize> = bodies().take(9).collect();
        assert_eq!(first, [64, 80, 96, 112, 128, 160, 192, 224, 256]);
        assert_eq!(bodies().last(), Some(LAST_BODY + LAST_BODY / 4 * 3));
    }

    #[test]
    fn a_record_opens_only_with_its_key_and_binding() {
        let content = b"abandon ability able";
        let body = body_for(content.len()).unwrap();
        let key = [9; KEY_BYTES];
        let aad = associated(&[1; KEY_BYTES], 1, 3, body);
        let record = seal(content, body, &key, &aad, &mut Counter(5)).unwrap();
        assert_eq!(record.len() * 8, record_bits(body));
        assert_eq!(open(&record, &key, &aad).unwrap()[..], content[..]);
        assert!(open(&record, &[8; KEY_BYTES], &aad).is_none());
        let other = associated(&[1; KEY_BYTES], 2, 3, body);
        assert!(open(&record, &key, &other).is_none());
        let bytes = from_bits(&to_bits(&record));
        assert_eq!(bytes[..], record[..]);
    }
}
