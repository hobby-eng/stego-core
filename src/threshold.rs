//! Any k of n photos (Krawczyk, "Secret sharing made short", CRYPTO 1993): the message is
//! encrypted once with a random key; the ciphertext is cut into n Reed–Solomon shards of which
//! any k rebuild it, so each photo carries about 1/k of it; the key is shared with Shamir's scheme
//! over GF(256) (vsss-rs, constant time), so fewer than k photos say nothing about it.

use crate::StegoError;
use crate::random::Random;
use crate::shard::Code;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use vsss_rs::Gf256;
use zeroize::{Zeroize, Zeroizing};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
pub(crate) const TAG_BYTES: usize = 16;
const LENGTH_BYTES: usize = 4;
const AAD_LABEL: &[u8] = b"stego-core 1 threshold";
/// Bytes of a share of a 32-byte key: the share's number and the value.
const SHARE_BYTES: usize = 1 + KEY_BYTES;
/// Bytes a threshold payload adds to its shard: the threshold, the share's length, the share,
/// the nonce and the ciphertext's length.
pub(crate) const PAYLOAD_OVERHEAD: usize = 1 + 2 + SHARE_BYTES + NONCE_BYTES + LENGTH_BYTES;
/// Most photos of a threshold set: kept at 16 so that every choice of pieces can be tested.
pub const THRESHOLD_MAX: usize = 16;

/// Bytes of each shard of an encoded message of `length` bytes split for `needed` photos.
#[cfg(test)]
pub(crate) const fn shard_bytes(length: usize, needed: usize) -> usize {
    (length + TAG_BYTES).div_ceil(needed)
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
    let data: Vec<Vec<u8>> = (0..k)
        .map(|i| {
            let start = (i * size).min(sealed.len());
            let mut shard = sealed[start..(start + size).min(sealed.len())].to_vec();
            shard.resize(size, 0);
            shard
        })
        .collect();
    let code = Code::new(k).map_err(|_| StegoError::Threshold)?;
    let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    (0..count)
        .map(|i| code.piece(&refs, i).map_err(|_| StegoError::Threshold))
        .collect()
}

/// One share of `key` per photo, any `needed` of which restore it. The polynomial's
/// coefficients come from a generator seeded with the host's fresh randomness.
fn shares(
    key: &[u8; KEY_BYTES],
    needed: u8,
    count: usize,
    random: &mut dyn Random,
) -> Result<Vec<Zeroizing<Vec<u8>>>, StegoError> {
    let mut seed = Zeroizing::new([0; KEY_BYTES]);
    random.fill(seed.as_mut())?;
    let mut generator = ChaCha20Rng::from_seed(*seed);
    let mut shares = Gf256::split_bytes(usize::from(needed), count, key, &mut generator)
        .map_err(|_| StegoError::Threshold)?;
    let out = shares.iter().map(|s| Zeroizing::new(s.clone())).collect();
    shares.iter_mut().for_each(Zeroize::zeroize);
    // The generator's state could make the coefficients again: it is wiped too.
    generator = ChaCha20Rng::from_seed([0; KEY_BYTES]);
    drop(generator);
    Ok(out)
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

/// What the parts of a k-of-n set give.
pub(crate) enum Joined {
    /// The encoded message.
    Message(Zeroizing<Vec<u8>>),
    /// More than k pieces were given and they do not all belong to one set.
    Inconsistent,
    /// The pieces do not rebuild a ciphertext that opens.
    Unreadable,
}

/// Restores the encoded message from `(photo number, payload)` pairs of one set of `count`
/// photos.
pub(crate) fn join(payloads: &[(usize, &[u8])], count: usize, set: &[u8]) -> Joined {
    join_checked(payloads, count, set).unwrap_or(Joined::Unreadable)
}

fn join_checked(payloads: &[(usize, &[u8])], count: usize, set: &[u8]) -> Option<Joined> {
    let k = usize::from(needed(payloads.first()?.1)?);
    let parsed: Vec<(usize, Fields<'_>)> = payloads
        .iter()
        .map(|&(i, p)| fields(p).map(|f| (i, f)))
        .collect::<Option<_>>()?;
    let first = &parsed.first()?.1;
    if parsed.iter().any(|(index, _)| *index >= count) {
        return None;
    }
    let pieces: Vec<(usize, &[u8])> = parsed.iter().map(|(i, f)| (*i, f.shard)).collect();
    let code = Code::new(k).ok()?;
    // Every piece beyond k must agree with the others, or the set is mixed.
    if pieces.len() > k && !code.consistent(&pieces).ok()? {
        return Some(Joined::Inconsistent);
    }
    let mut sealed = code.rebuild(&pieces).ok()?.concat();
    sealed.truncate(first.sealed_length);
    let body_length = sealed.len().checked_sub(TAG_BYTES)?;
    let tag = Tag::try_from(&sealed[body_length..]).ok()?;
    let nonce = XNonce::try_from(first.nonce).ok()?;
    // Wiped on every return, early ones included.
    let shares: Zeroizing<Vec<Vec<u8>>> =
        Zeroizing::new(parsed.iter().map(|(_, f)| f.share.to_vec()).collect());
    let key = Zeroizing::new(Gf256::combine_bytes(&*shares).ok()?);
    let mut plain = Zeroizing::new(sealed[..body_length].to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(&key).ok()?;
    cipher
        .decrypt_inout_detached(&nonce, &aad(set), plain.as_mut_slice().into(), &tag)
        .ok()?;
    Some(Joined::Message(plain))
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
            let Joined::Message(joined) = join(&pairs(&parts, &pick), 3, &set) else {
                panic!("{pick:?} did not join");
            };
            assert_eq!(&joined[..], MESSAGE);
        }
        assert!(matches!(
            join(&pairs(&parts, &[1]), 3, &set),
            Joined::Unreadable
        ));
        assert!(matches!(
            join(&pairs(&parts, &[0, 1]), 3, &[6; 16]),
            Joined::Unreadable
        ));
    }

    #[test]
    fn three_of_five_need_three() {
        let set = [7; 16];
        let parts = split(MESSAGE, 3, 5, &set, &mut Counter(9)).unwrap();
        let Joined::Message(joined) = join(&pairs(&parts, &[4, 1, 3]), 5, &set) else {
            panic!("three of five did not join");
        };
        assert_eq!(&joined[..], MESSAGE);
        assert!(matches!(
            join(&pairs(&parts, &[4, 1]), 5, &set),
            Joined::Unreadable
        ));
        let mut forged = parts[2].to_vec();
        if let Some(last) = forged.last_mut() {
            *last ^= 1;
        }
        let mixed = [
            (4, parts[4].as_slice()),
            (1, parts[1].as_slice()),
            (3, parts[3].as_slice()),
            (2, forged.as_slice()),
        ];
        assert!(matches!(join(&mixed, 5, &set), Joined::Inconsistent));
    }

    #[test]
    fn thresholds_outside_two_to_the_count_are_refused() {
        let error = split(b"x", 1, 3, &[0; 16], &mut Counter(1)).unwrap_err();
        assert_eq!(error, StegoError::Threshold);
        let error = split(b"x", 4, 3, &[0; 16], &mut Counter(1)).unwrap_err();
        assert_eq!(error, StegoError::Threshold);
    }
}
