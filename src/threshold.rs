//! Any k of n photos (Krawczyk, "Secret sharing made short", CRYPTO 1993): the message is
//! encrypted once with a random key; the ciphertext is cut into n Reed–Solomon shards of which
//! any k rebuild it, so each photo carries about 1/k of it; the key is shared with SSKR
//! (Shamir), so fewer than k photos say nothing about it.

use crate::StegoError;
use crate::random::Random;
use bc_rand::RandomNumberGenerator;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sskr::{GroupSpec, Secret, Spec, sskr_combine, sskr_generate_using};
use zeroize::{Zeroize, Zeroizing};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
pub(crate) const TAG_BYTES: usize = 16;
const LENGTH_BYTES: usize = 4;
const AAD_LABEL: &[u8] = b"stego-core 1 threshold";
/// Bytes of an SSKR share of a 32-byte key: five bytes of metadata and the share value.
const SHARE_BYTES: usize = 5 + KEY_BYTES;
/// Bytes a threshold payload adds to its shard: the threshold, the share's length, the share,
/// the nonce and the ciphertext's length.
pub(crate) const PAYLOAD_OVERHEAD: usize = 1 + 2 + SHARE_BYTES + NONCE_BYTES + LENGTH_BYTES;
/// Most photos of a threshold set: SSKR's limit of members in a group.
pub const THRESHOLD_MAX: usize = 16;

/// Bytes of each shard of an encoded message of `length` bytes split for `needed` photos.
#[cfg(test)]
pub(crate) const fn shard_bytes(length: usize, needed: usize) -> usize {
    (length + TAG_BYTES).div_ceil(needed)
}

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

/// The payloads of a k-of-n set, photo `i` getting shard `i`: the threshold, the share's
/// length, the share, the nonce, the ciphertext's length and the shard. `set` binds the
/// ciphertext to its set.
pub(crate) fn split(
    encoded: &[u8],
    needed: u8,
    count: usize,
    set: &[u8],
    random: &mut dyn Random,
) -> Result<Vec<Zeroizing<Vec<u8>>>, StegoError> {
    let k = usize::from(needed);
    if k < 2 || k > count || count > THRESHOLD_MAX {
        return Err(StegoError::Threshold);
    }
    let mut key = Zeroizing::new([0; KEY_BYTES]);
    random.fill(key.as_mut())?;
    let mut nonce = [0; NONCE_BYTES];
    random.fill(&mut nonce)?;
    let mut sealed = encoded.to_vec();
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| StegoError::Crypto)?;
    let tag = cipher
        .encrypt_inout_detached(
            &XNonce::from(nonce),
            &aad(set),
            sealed.as_mut_slice().into(),
        )
        .map_err(|_| StegoError::Crypto)?;
    sealed.extend_from_slice(&tag);
    let sealed_length = u32::try_from(sealed.len()).map_err(|_| StegoError::MessageLong)?;
    let shards = shards(&sealed, k, count)?;
    let shares = shares(&key, needed, count, random)?;
    Ok(shares
        .iter()
        .zip(&shards)
        .map(|(share, shard)| {
            let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_OVERHEAD + shard.len()));
            payload.push(needed);
            // SSKR shares of a 32-byte key are 37 bytes.
            payload.extend_from_slice(&(share.len() as u16).to_be_bytes());
            payload.extend_from_slice(share);
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&sealed_length.to_be_bytes());
            payload.extend_from_slice(shard);
            payload
        })
        .collect())
}

/// The ciphertext cut into `k` data shards and `count - k` parity shards of equal size.
fn shards(sealed: &[u8], k: usize, count: usize) -> Result<Vec<Vec<u8>>, StegoError> {
    let size = sealed.len().div_ceil(k);
    let mut shards: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let start = (i * size).min(sealed.len());
            let mut shard = sealed[start..(start + size).min(sealed.len())].to_vec();
            shard.resize(size, 0);
            if i >= k {
                shard.fill(0);
            }
            shard
        })
        .collect();
    if count > k {
        ReedSolomon::new(k, count - k)
            .and_then(|code| code.encode(&mut shards))
            .map_err(|_| StegoError::Threshold)?;
    }
    Ok(shards)
}

/// One SSKR share of `key` per photo, any `needed` of which restore it.
fn shares(
    key: &[u8; KEY_BYTES],
    needed: u8,
    count: usize,
    random: &mut dyn Random,
) -> Result<Vec<Zeroizing<Vec<u8>>>, StegoError> {
    let mut seed = Zeroizing::new([0; KEY_BYTES]);
    random.fill(seed.as_mut())?;
    let mut generator = Seeded(ChaCha20Rng::from_seed(*seed));
    let group = GroupSpec::new(usize::from(needed), count).map_err(|_| StegoError::Threshold)?;
    let spec = Spec::new(1, vec![group]).map_err(|_| StegoError::Threshold)?;
    let secret = Secret::new(key).map_err(|_| StegoError::Crypto)?;
    let mut groups =
        sskr_generate_using(&spec, &secret, &mut generator).map_err(|_| StegoError::Crypto)?;
    let shares = groups
        .iter()
        .flatten()
        .map(|s| Zeroizing::new(s.clone()))
        .collect();
    groups.iter_mut().flatten().for_each(Zeroize::zeroize);
    Ok(shares)
}

/// The number of photos a payload says its set needs.
pub(crate) fn needed(payload: &[u8]) -> Option<u8> {
    payload.first().copied()
}

/// A payload's parts.
struct Fields<'a> {
    share: &'a [u8],
    nonce: &'a [u8],
    sealed_length: usize,
    shard: &'a [u8],
}

fn fields(payload: &[u8]) -> Option<Fields<'_>> {
    let share_length = usize::from(u16::from_be_bytes([*payload.get(1)?, *payload.get(2)?]));
    let share = payload.get(3..3 + share_length)?;
    let nonce = payload.get(3 + share_length..3 + share_length + NONCE_BYTES)?;
    let at = 3 + share_length + NONCE_BYTES;
    let length: [u8; LENGTH_BYTES] = payload.get(at..at + LENGTH_BYTES)?.try_into().ok()?;
    let sealed_length = usize::try_from(u32::from_be_bytes(length)).ok()?;
    Some(Fields {
        share,
        nonce,
        sealed_length,
        shard: payload.get(at + LENGTH_BYTES..)?,
    })
}

/// Restores the encoded message from `(photo number, payload)` pairs of one set of `count`
/// photos; `None` when they do not rebuild a ciphertext that opens.
pub(crate) fn join(
    payloads: &[(usize, &[u8])],
    count: usize,
    set: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let k = usize::from(needed(payloads.first()?.1)?);
    let parsed: Vec<(usize, Fields<'_>)> = payloads
        .iter()
        .map(|&(i, p)| fields(p).map(|f| (i, f)))
        .collect::<Option<_>>()?;
    let first = &parsed.first()?.1;
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; count];
    for (index, f) in &parsed {
        *slots.get_mut(*index)? = Some(f.shard.to_vec());
    }
    if count > k {
        ReedSolomon::new(k, count - k)
            .ok()?
            .reconstruct_data(&mut slots)
            .ok()?;
    }
    let data: Vec<&[u8]> = slots
        .iter()
        .take(k)
        .map(Option::as_deref)
        .collect::<Option<_>>()?;
    let mut sealed = data.concat();
    sealed.truncate(first.sealed_length);
    let body_length = sealed.len().checked_sub(TAG_BYTES)?;
    let tag = Tag::try_from(&sealed[body_length..]).ok()?;
    let nonce = XNonce::try_from(first.nonce).ok()?;
    let mut shares: Vec<Vec<u8>> = parsed.iter().map(|(_, f)| f.share.to_vec()).collect();
    let key = sskr_combine(&shares).ok();
    shares.iter_mut().for_each(Zeroize::zeroize);
    let key = key?;
    let mut plain = Zeroizing::new(sealed[..body_length].to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(key.data()).ok()?;
    cipher
        .decrypt_inout_detached(&nonce, &aad(set), plain.as_mut_slice().into(), &tag)
        .ok()?;
    Some(plain)
}

fn aad(set: &[u8]) -> Vec<u8> {
    [AAD_LABEL, set].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::Counter;

    const MESSAGE: &[u8] = b"abandon ability able about above absent absorb abstract";

    fn pairs<'a>(parts: &'a [Zeroizing<Vec<u8>>], pick: &[usize]) -> Vec<(usize, &'a [u8])> {
        pick.iter().map(|&i| (i, parts[i].as_slice())).collect()
    }

    #[test]
    fn any_two_of_three_restore_and_each_carries_half() {
        let set = [5; 16];
        let parts = split(MESSAGE, 2, 3, &set, &mut Counter(3)).unwrap();
        assert_eq!(
            parts[0].len(),
            PAYLOAD_OVERHEAD + shard_bytes(MESSAGE.len(), 2)
        );
        for pick in [[0, 1], [0, 2], [2, 1]] {
            let joined = join(&pairs(&parts, &pick), 3, &set).unwrap();
            assert_eq!(&joined[..], MESSAGE);
        }
        assert!(join(&pairs(&parts, &[1]), 3, &set).is_none());
        assert!(join(&pairs(&parts, &[0, 1]), 3, &[6; 16]).is_none());
    }

    #[test]
    fn three_of_five_need_three() {
        let set = [7; 16];
        let parts = split(MESSAGE, 3, 5, &set, &mut Counter(9)).unwrap();
        assert_eq!(
            &join(&pairs(&parts, &[4, 1, 3]), 5, &set).unwrap()[..],
            MESSAGE
        );
        assert!(join(&pairs(&parts, &[4, 1]), 5, &set).is_none());
    }

    #[test]
    fn thresholds_outside_two_to_the_count_are_refused() {
        let error = split(b"x", 1, 3, &[0; 16], &mut Counter(1)).unwrap_err();
        assert_eq!(error, StegoError::Threshold);
        let error = split(b"x", 4, 3, &[0; 16], &mut Counter(1)).unwrap_err();
        assert_eq!(error, StegoError::Threshold);
    }
}
