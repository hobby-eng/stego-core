//! Any k of n photos: the message is encrypted once with a random key, every photo carries the
//! ciphertext and one SSKR share of the key, and any k shares restore the key.

use crate::StegoError;
use crate::random::Random;
use bc_rand::RandomNumberGenerator;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sskr::{GroupSpec, Secret, Spec, sskr_combine, sskr_generate_using};
use zeroize::{Zeroize, Zeroizing};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const AAD_LABEL: &[u8] = b"stego-core 1 threshold";
/// Bytes of an SSKR share of a 32-byte key: five bytes of metadata and the share value.
const SHARE_BYTES: usize = 5 + KEY_BYTES;
/// Bytes a threshold payload adds to the encoded message: the threshold, the share's length,
/// the share, the nonce and the tag.
pub(crate) const PAYLOAD_OVERHEAD: usize = 1 + 2 + SHARE_BYTES + NONCE_BYTES + TAG_BYTES;
/// Most photos of a threshold set: SSKR's limit of members in a group.
pub const THRESHOLD_MAX: usize = 16;

/// The split's generator, seeded with the host's fresh randomness and reset when dropped.
struct Seeded(ChaCha20Rng);

impl RngCore for Seeded {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.0.fill_bytes(destination);
    }
}

impl CryptoRng for Seeded {}
impl RandomNumberGenerator for Seeded {}

impl Drop for Seeded {
    fn drop(&mut self) {
        self.0 = ChaCha20Rng::from_seed([0; KEY_BYTES]);
    }
}

/// The payloads of a k-of-n set, one per photo: `needed`, the share's length, the share, the
/// nonce and the ciphertext with its tag. `set` binds the ciphertext to its set.
pub(crate) fn split(
    encoded: &[u8],
    needed: u8,
    count: usize,
    set: &[u8],
    random: &mut dyn Random,
) -> Result<Vec<Zeroizing<Vec<u8>>>, StegoError> {
    if needed < 2 || usize::from(needed) > count || count > THRESHOLD_MAX {
        return Err(StegoError::Threshold);
    }
    let mut key = Zeroizing::new([0; KEY_BYTES]);
    random.fill(key.as_mut())?;
    let mut nonce = [0; NONCE_BYTES];
    random.fill(&mut nonce)?;
    let mut sealed = Zeroizing::new(encoded.to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| StegoError::Crypto)?;
    let tag = cipher
        .encrypt_inout_detached(
            &XNonce::from(nonce),
            &aad(set),
            sealed.as_mut_slice().into(),
        )
        .map_err(|_| StegoError::Crypto)?;
    sealed.extend_from_slice(&tag);
    let mut seed = Zeroizing::new([0; KEY_BYTES]);
    random.fill(seed.as_mut())?;
    let mut generator = Seeded(ChaCha20Rng::from_seed(*seed));
    let group = GroupSpec::new(usize::from(needed), count).map_err(|_| StegoError::Threshold)?;
    let spec = Spec::new(1, vec![group]).map_err(|_| StegoError::Threshold)?;
    let secret = Secret::new(key.as_ref()).map_err(|_| StegoError::Crypto)?;
    let mut groups =
        sskr_generate_using(&spec, &secret, &mut generator).map_err(|_| StegoError::Crypto)?;
    let mut out = Vec::with_capacity(count);
    for share in groups.iter().flatten() {
        let length = u16::try_from(share.len()).map_err(|_| StegoError::Crypto)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(
            3 + share.len() + NONCE_BYTES + sealed.len(),
        ));
        payload.push(needed);
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(share);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&sealed);
        out.push(payload);
    }
    groups.iter_mut().flatten().for_each(Zeroize::zeroize);
    Ok(out)
}

/// The number of shares a payload says its set needs.
pub(crate) fn needed(payload: &[u8]) -> Option<u8> {
    payload.first().copied()
}

/// Restores the encoded message from payloads of one set; `None` when the shares do not
/// restore a key that opens the ciphertext.
pub(crate) fn join(payloads: &[&[u8]], set: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut shares = Vec::with_capacity(payloads.len());
    let mut rest = None;
    for payload in payloads {
        let length = usize::from(u16::from_be_bytes([*payload.get(1)?, *payload.get(2)?]));
        shares.push(Zeroizing::new(payload.get(3..3 + length)?.to_vec()));
        rest.get_or_insert(payload.get(3 + length..)?);
    }
    let shares: Vec<Vec<u8>> = shares.iter().map(|s| s.to_vec()).collect();
    let key = sskr_combine(&shares).ok()?;
    let rest = rest?;
    let nonce = XNonce::try_from(rest.get(..NONCE_BYTES)?).ok()?;
    let body = rest.get(NONCE_BYTES..rest.len().checked_sub(TAG_BYTES)?)?;
    let tag = Tag::try_from(rest.get(rest.len() - TAG_BYTES..)?).ok()?;
    let mut plain = Zeroizing::new(body.to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(key.data()).ok()?;
    cipher
        .decrypt_inout_detached(&nonce, &aad(set), plain.as_mut_slice().into(), &tag)
        .ok()?;
    let mut shares = shares;
    shares.iter_mut().for_each(Zeroize::zeroize);
    Some(plain)
}

fn aad(set: &[u8]) -> Vec<u8> {
    [AAD_LABEL, set].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::Counter;

    #[test]
    fn any_two_of_three_restore_and_one_does_not() {
        let set = [5; 16];
        let parts = split(b"abandon ability able", 2, 3, &set, &mut Counter(3)).unwrap();
        for (a, b) in [(0, 1), (0, 2), (2, 1)] {
            let joined = join(&[&parts[a], &parts[b]], &set).unwrap();
            assert_eq!(&joined[..], b"abandon ability able");
        }
        assert!(join(&[&parts[1]], &set).is_none());
        assert_eq!(
            parts[0].len(),
            PAYLOAD_OVERHEAD + b"abandon ability able".len()
        );
        assert!(join(&[&parts[0], &parts[1]], &[6; 16]).is_none());
    }

    #[test]
    fn thresholds_outside_two_to_the_count_are_refused() {
        assert_eq!(
            split(b"x", 1, 3, &[0; 16], &mut Counter(1)).unwrap_err(),
            StegoError::Threshold
        );
        assert_eq!(
            split(b"x", 4, 3, &[0; 16], &mut Counter(1)).unwrap_err(),
            StegoError::Threshold
        );
    }
}
