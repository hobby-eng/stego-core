//! Any k of n photos (Krawczyk, "Secret sharing made short", CRYPTO 1993): the message is
//! encrypted once with a random key; the ciphertext is cut into n Reed–Solomon shards of which
//! any k rebuild it, so each photo carries about 1/k of it; the key is shared with Shamir's scheme
//! over GF(256) (vsss-rs, constant time), so fewer than k photos say nothing about it.

use crate::StegoError;
use crate::random::Random;
use crate::shard::Code;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
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
    // The message until it is encrypted in place: wiped if the encryption is refused, and with
    // room for the tag so that it is never copied to a larger buffer.
    let mut sealed = Zeroizing::new(Vec::with_capacity(encoded.len() + TAG_BYTES));
    sealed.extend_from_slice(encoded);
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
            // A share of a 32-byte key is 33 bytes.
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

/// One share of `key` per photo, any `needed` of which restore it; photo `i` gets the share
/// numbered `i + 1`. The polynomial's coefficients come from a ChaCha20 generator seeded with the
/// host's fresh randomness; the generator wipes its state and its buffer when dropped (chacha20's
/// `zeroize` feature), so nothing that could make the coefficients again stays behind.
fn shares(
    key: &[u8; KEY_BYTES],
    needed: u8,
    count: usize,
    random: &mut dyn Random,
) -> Result<Vec<Zeroizing<Vec<u8>>>, StegoError> {
    let mut seed = Zeroizing::new([0; KEY_BYTES]);
    random.fill(seed.as_mut())?;
    let mut generator = ChaCha20Rng::from_seed(*seed);
    // vsss-rs shares a secret byte by byte and frees the last byte's polynomial without wiping
    // it. A public zero byte after the key takes that place; its share byte is cut off again, and
    // the shares of the key are what they would have been without it.
    let mut padded = Zeroizing::new([0_u8; KEY_BYTES + 1]);
    padded[..KEY_BYTES].copy_from_slice(key);
    let split = Gf256::split_bytes(
        usize::from(needed),
        count,
        padded.as_slice(),
        &mut generator,
    );
    drop(generator);
    let mut shares = split.map_err(|_| StegoError::Threshold)?;
    // The reader holds every share to its photo's number, so the writer checks the same.
    let out = shares
        .iter()
        .zip(1_u8..)
        .map(|(share, number)| {
            (share.len() == SHARE_BYTES + 1 && share[0] == number)
                .then(|| Zeroizing::new(share[..SHARE_BYTES].to_vec()))
        })
        .collect::<Option<Vec<_>>>();
    shares.iter_mut().for_each(Zeroize::zeroize);
    out.ok_or(StegoError::Threshold)
}

/// A payload's fields.
struct Fields<'a> {
    needed: u8,
    share: &'a [u8],
    nonce: &'a [u8],
    sealed_length: usize,
    shard: &'a [u8],
}

/// The fields of the payload of photo `index`, each held to what this version writes: a
/// threshold from 2 to [`THRESHOLD_MAX`], a share of a 32-byte key that carries this photo's
/// number (`index + 1`: vsss-rs numbers the shares from 1), a ciphertext long enough for its tag
/// and a shard of exactly the length that ciphertext gives. `None` for anything else.
fn fields(index: usize, payload: &[u8]) -> Option<Fields<'_>> {
    let needed = *payload.first()?;
    let k = usize::from(needed);
    if !(2..=THRESHOLD_MAX).contains(&k) {
        return None;
    }
    let share_length = usize::from(u16::from_be_bytes([*payload.get(1)?, *payload.get(2)?]));
    if share_length != SHARE_BYTES {
        return None;
    }
    let share = payload.get(3..3 + SHARE_BYTES)?;
    if usize::from(share[0]) != index + 1 {
        return None;
    }
    let at = 3 + SHARE_BYTES;
    let nonce = payload.get(at..at + NONCE_BYTES)?;
    let at = at + NONCE_BYTES;
    let length: [u8; LENGTH_BYTES] = payload.get(at..at + LENGTH_BYTES)?.try_into().ok()?;
    let sealed_length = usize::try_from(u32::from_be_bytes(length)).ok()?;
    let shard = payload.get(at + LENGTH_BYTES..)?;
    if sealed_length < TAG_BYTES || shard.len() != sealed_length.div_ceil(k) {
        return None;
    }
    Some(Fields {
        needed,
        share,
        nonce,
        sealed_length,
        shard,
    })
}

/// What the payloads of one set say before any piece is used.
pub(crate) enum Form {
    /// A payload is not in the form this version writes.
    Malformed,
    /// The payloads name different thresholds, nonces or ciphertext lengths: they are not parts
    /// of one message.
    Inconsistent,
    /// Every payload is well formed and they agree: the set needs this many photos.
    Agreed {
        /// Photos needed to read the set.
        needed: usize,
    },
}

/// Checks `(photo number, payload)` pairs of one set without opening anything.
pub(crate) fn form(payloads: &[(usize, &[u8])]) -> Form {
    match parse(payloads) {
        Ok(parsed) => Form::Agreed {
            needed: usize::from(parsed.needed),
        },
        Err(Flaw::Malformed) => Form::Malformed,
        Err(Flaw::Inconsistent) => Form::Inconsistent,
    }
}

/// Why payloads cannot be parts of one set.
enum Flaw {
    Malformed,
    Inconsistent,
}

/// The payloads of one set, all well formed and in agreement.
struct Parsed<'a> {
    needed: u8,
    nonce: &'a [u8],
    sealed_length: usize,
    /// Per photo: its number, its share and its shard.
    parts: Vec<(usize, &'a [u8], &'a [u8])>,
}

fn parse<'a>(payloads: &[(usize, &'a [u8])]) -> Result<Parsed<'a>, Flaw> {
    let all: Vec<(usize, Fields<'a>)> = payloads
        .iter()
        .map(|&(i, p)| fields(i, p).map(|f| (i, f)))
        .collect::<Option<_>>()
        .ok_or(Flaw::Malformed)?;
    let (_, first) = all.first().ok_or(Flaw::Malformed)?;
    let (needed, nonce, sealed_length) = (first.needed, first.nonce, first.sealed_length);
    if all
        .iter()
        .any(|(_, f)| (f.needed, f.nonce, f.sealed_length) != (needed, nonce, sealed_length))
    {
        return Err(Flaw::Inconsistent);
    }
    Ok(Parsed {
        needed,
        nonce,
        sealed_length,
        parts: all.iter().map(|(i, f)| (*i, f.share, f.shard)).collect(),
    })
}

/// What the parts of a k-of-n set give.
pub(crate) enum Joined {
    /// The encoded message.
    Message(Zeroizing<Vec<u8>>),
    /// A payload is not in the form this version writes.
    Malformed,
    /// The parts are not of one message: their fields differ, or more than k pieces were given
    /// and they do not all belong to one code word.
    Inconsistent,
    /// The parts agree in form but do not rebuild a ciphertext that opens. With exactly k parts
    /// nothing but the final tag can tell: the pieces have no spare to check each other.
    Unreadable,
}

/// Restores the encoded message from `(photo number, payload)` pairs of one set. How many
/// photos were issued is not needed, so a set that was given more photos later reads the same.
/// The message is taken as genuine only because its tag opens under the key the shares give;
/// the agreement of the pieces alone proves nothing.
pub(crate) fn join(payloads: &[(usize, &[u8])], set: &[u8]) -> Joined {
    match parse(payloads) {
        Ok(parsed) => open(&parsed, set).unwrap_or(Joined::Unreadable),
        Err(Flaw::Malformed) => Joined::Malformed,
        Err(Flaw::Inconsistent) => Joined::Inconsistent,
    }
}

fn open(parsed: &Parsed<'_>, set: &[u8]) -> Option<Joined> {
    let k = usize::from(parsed.needed);
    let pieces: Vec<(usize, &[u8])> = parsed
        .parts
        .iter()
        .map(|&(i, _, shard)| (i, shard))
        .collect();
    let code = Code::new(k).ok()?;
    // Every piece beyond k must agree with the others, or the set is mixed.
    if pieces.len() > k && !code.consistent(&pieces).ok()? {
        return Some(Joined::Inconsistent);
    }
    // `fields` held every shard to the ciphertext's length over k, so the k data pieces hold it.
    let mut sealed = code.rebuild(&pieces).ok()?.concat();
    sealed.truncate(parsed.sealed_length);
    let body_length = sealed.len().checked_sub(TAG_BYTES)?;
    let tag = Tag::try_from(&sealed[body_length..]).ok()?;
    let nonce = XNonce::try_from(parsed.nonce).ok()?;
    // Wiped on every return, early ones included.
    let shares: Zeroizing<Vec<Vec<u8>>> = Zeroizing::new(
        parsed
            .parts
            .iter()
            .map(|&(_, share, _)| share.to_vec())
            .collect(),
    );
    let key = Zeroizing::new(Gf256::combine_bytes(&*shares).ok()?);
    let mut plain = Zeroizing::new(sealed[..body_length].to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(&key).ok()?;
    cipher
        .decrypt_inout_detached(&nonce, &aad(set), plain.as_mut_slice().into(), &tag)
        .ok()?;
    Some(Joined::Message(plain))
}

/// Why a set cannot be given the photo asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// A payload is not in the form this version writes.
    Malformed,
    /// The payloads are not parts of one message: their fields differ, or a piece or a key
    /// share beyond the first k does not lie with those k.
    Inconsistent,
    /// Fewer payloads than the set needs.
    TooFew,
    /// The number is not one a photo of a set can have.
    Number,
}

/// The payload of photo `index` of a set: its ciphertext piece, made from any k pieces, and its key
/// share. Nothing is re-encrypted, so the same number always gets the same bytes. The caller must
/// open the set first; payloads are not checked here.
pub(crate) fn issue(
    payloads: &[(usize, &[u8])],
    index: usize,
) -> Result<Zeroizing<Vec<u8>>, Refused> {
    let parsed = parse(payloads).map_err(|flaw| match flaw {
        Flaw::Malformed => Refused::Malformed,
        Flaw::Inconsistent => Refused::Inconsistent,
    })?;
    let k = usize::from(parsed.needed);
    if parsed.parts.len() < k {
        return Err(Refused::TooFew);
    }
    // A set has at most `THRESHOLD_MAX` numbers, so the share's number fits its byte.
    let number = u8::try_from(index + 1)
        .ok()
        .filter(|_| index < THRESHOLD_MAX)
        .ok_or(Refused::Number)?;
    let pieces: Vec<(usize, &[u8])> = parsed
        .parts
        .iter()
        .map(|&(i, _, shard)| (i, shard))
        .collect();
    let code = Code::new(k).map_err(|_| Refused::Malformed)?;
    if pieces.len() > k
        && !code
            .consistent(&pieces)
            .map_err(|_| Refused::Inconsistent)?
    {
        return Err(Refused::Inconsistent);
    }
    // The key shares beyond the first k must lie on the polynomials those k fix. Opening the
    // message shows only that all the shares agree at the point 0, which does not prove it.
    let (first, further) = parsed.parts.split_at(k);
    let sources: Vec<&[u8]> = first.iter().map(|&(_, share, _)| share).collect();
    for &(_, share, _) in further {
        let point = share.first().copied().unwrap_or(0);
        if !same(&share_at(&sources, point), share) {
            return Err(Refused::Inconsistent);
        }
    }
    if let Some(&(_, payload)) = payloads.iter().find(|&&(i, _)| i == index) {
        return Ok(Zeroizing::new(payload.to_vec()));
    }
    let data = code.rebuild(&pieces).map_err(|_| Refused::Inconsistent)?;
    let data: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    let shard = code.piece(&data, index).map_err(|_| Refused::Number)?;
    let share = share_at(&sources, number);
    let length = u32::try_from(parsed.sealed_length).map_err(|_| Refused::Malformed)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_OVERHEAD + shard.len()));
    payload.push(parsed.needed);
    payload.extend_from_slice(&(SHARE_BYTES as u16).to_be_bytes());
    payload.extend_from_slice(&share);
    payload.extend_from_slice(parsed.nonce);
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(&shard);
    Ok(payload)
}

/// The share at point `x` of the polynomials that `shares` lie on, each share a point and then
/// one value per key byte: Lagrange's formula byte by byte, with the field arithmetic of
/// vsss-rs, which shared the key. The points of `shares` are different; at one of them the
/// result is that share.
pub(crate) fn share_at(shares: &[&[u8]], x: u8) -> Zeroizing<Vec<u8>> {
    let point = |share: &[u8]| Gf256(share.first().copied().unwrap_or(0));
    let target = Gf256(x);
    let mut out = Zeroizing::new(vec![0; SHARE_BYTES]);
    if let Some(first) = out.first_mut() {
        *first = x;
    }
    for (position, share) in shares.iter().enumerate() {
        // This share's weight, Π (x − x_m) / (x_j − x_m) over the other shares; the points are
        // public.
        let own = point(share);
        let (mut numerator, mut denominator) = (Gf256(1), Gf256(1));
        for (other, share) in shares.iter().enumerate() {
            if other != position {
                numerator *= target - point(share);
                denominator *= own - point(share);
            }
        }
        let weight = numerator * inverse(denominator);
        for (sum, &value) in out.iter_mut().zip(share.iter()).skip(1) {
            *sum ^= (Gf256(value) * weight).0;
        }
    }
    out
}

/// The inverse of a nonzero element: its 254th power, by the chain of squarings and
/// multiplications vsss-rs's own inversion takes, with its constant-time multiplication. Its
/// division panics on zero and `Gf256::pow` of version 6.0.1 multiplies as integers, so neither
/// is used; zero gives zero here.
fn inverse(element: Gf256) -> Gf256 {
    let mut power = element;
    for _ in 0..6 {
        power = power * power * element;
    }
    power * power
}

/// Whether two shares are the same, looking at every byte.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |differs, (x, y)| differs | (x ^ y)) == 0
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
            let Joined::Message(joined) = join(&pairs(&parts, &pick), &set) else {
                panic!("{pick:?} did not join");
            };
            assert_eq!(&joined[..], MESSAGE);
        }
        assert!(matches!(
            join(&pairs(&parts, &[1]), &set),
            Joined::Unreadable
        ));
        assert!(matches!(
            join(&pairs(&parts, &[0, 1]), &[6; 16]),
            Joined::Unreadable
        ));
    }

    #[test]
    fn three_of_five_need_three() {
        let set = [7; 16];
        let parts = split(MESSAGE, 3, 5, &set, &mut Counter(9)).unwrap();
        let Joined::Message(joined) = join(&pairs(&parts, &[4, 1, 3]), &set) else {
            panic!("three of five did not join");
        };
        assert_eq!(&joined[..], MESSAGE);
        assert!(matches!(
            join(&pairs(&parts, &[4, 1]), &set),
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
        assert!(matches!(join(&mixed, &set), Joined::Inconsistent));
    }

    /// Where a payload keeps its share and its nonce.
    const SHARE: std::ops::Range<usize> = 3..3 + SHARE_BYTES;
    const NONCE: std::ops::Range<usize> = 3 + SHARE_BYTES..3 + SHARE_BYTES + NONCE_BYTES;

    #[test]
    fn a_share_under_another_photos_number_is_refused() {
        let set = [8; 16];
        let parts = split(MESSAGE, 2, 3, &set, &mut Counter(11)).unwrap();
        // Photos 0 and 1 with each other's whole shares: the same two points and so the same key,
        // which the tag alone would accept.
        let mut first = parts[0].to_vec();
        let mut second = parts[1].to_vec();
        first[SHARE].copy_from_slice(&parts[1][SHARE]);
        second[SHARE].copy_from_slice(&parts[0][SHARE]);
        let swapped = [(0, first.as_slice()), (1, second.as_slice())];
        assert!(matches!(form(&swapped), Form::Malformed));
        assert!(matches!(join(&swapped, &set), Joined::Malformed));
    }

    #[test]
    fn parts_of_two_messages_under_one_set_number_do_not_join() {
        let set = [9; 16];
        let one = split(MESSAGE, 2, 3, &set, &mut Counter(12)).unwrap();
        let other = split(MESSAGE, 2, 3, &set, &mut Counter(13)).unwrap();
        // Exactly k parts, one of each message: their nonces differ, so they are told apart
        // before any piece is used.
        let mixed = [(0, one[0].as_slice()), (1, other[1].as_slice())];
        assert!(matches!(form(&mixed), Form::Inconsistent));
        assert!(matches!(join(&mixed, &set), Joined::Inconsistent));
        // With the nonce copied over, the fields agree and only the tag can tell.
        let mut forged = other[1].to_vec();
        forged[NONCE].copy_from_slice(&one[1][NONCE]);
        let mixed = [(0, one[0].as_slice()), (1, forged.as_slice())];
        assert!(matches!(form(&mixed), Form::Agreed { needed: 2 }));
        assert!(matches!(join(&mixed, &set), Joined::Unreadable));
    }

    #[test]
    fn payloads_this_version_does_not_write_are_malformed() {
        let set = [10; 16];
        let parts = split(MESSAGE, 2, 3, &set, &mut Counter(14)).unwrap();
        let malformed = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut payload = parts[0].to_vec();
            change(&mut payload);
            let pair = [(0, payload.as_slice()), (1, parts[1].as_slice())];
            matches!(form(&pair), Form::Malformed) && matches!(join(&pair, &set), Joined::Malformed)
        };
        // A threshold of 1, or above the most photos of a set.
        assert!(malformed(&|p| p[0] = 1));
        assert!(malformed(&|p| p[0] = 17));
        // A share of another length: the drafts that shared the key with SSKR wrote 37 bytes.
        assert!(malformed(&|p| {
            p[2] = 37;
            p.splice(3..3, [0; 4]);
        }));
        // A shard one byte short or long for its ciphertext.
        assert!(malformed(&|p| {
            p.pop();
        }));
        assert!(malformed(&|p| p.push(0)));
        // A ciphertext too short to hold its tag.
        let length = NONCE.end..NONCE.end + LENGTH_BYTES;
        assert!(malformed(
            &|p| p[length.clone()].copy_from_slice(&15_u32.to_be_bytes())
        ));
        // Unchanged, the same payloads agree.
        assert!(matches!(
            form(&pairs(&parts, &[0, 1])),
            Form::Agreed { needed: 2 }
        ));
    }

    #[test]
    fn a_set_of_three_of_five_grows_to_seven() {
        let set = [11; 16];
        let mut parts = split(MESSAGE, 3, 5, &set, &mut Counter(15)).unwrap();
        // Photo 5 from the first three photos; photo 6 from three others, the new one among them.
        let fifth = issue(&pairs(&parts, &[0, 1, 2]), 5).unwrap();
        parts.push(fifth);
        let sixth = issue(&pairs(&parts, &[5, 3, 1]), 6).unwrap();
        parts.push(sixth);
        // Every three of the seven open the message and no two do.
        for a in 0..7 {
            for b in a + 1..7 {
                assert!(matches!(
                    join(&pairs(&parts, &[a, b]), &set),
                    Joined::Unreadable
                ));
                for c in b + 1..7 {
                    let Joined::Message(joined) = join(&pairs(&parts, &[c, a, b]), &set) else {
                        panic!("{a} {b} {c} did not join");
                    };
                    assert_eq!(&joined[..], MESSAGE);
                }
            }
        }
        // All seven together agree, pieces and shares.
        assert!(matches!(
            join(&pairs(&parts, &[0, 1, 2, 3, 4, 5, 6]), &set),
            Joined::Message(_)
        ));
        assert!(issue(&pairs(&parts, &[6, 5, 4, 3, 2, 1, 0]), 7).is_ok());
    }

    #[test]
    fn the_payload_of_a_number_depends_on_the_set_alone() {
        let set = [12; 16];
        let parts = split(MESSAGE, 3, 5, &set, &mut Counter(16)).unwrap();
        // A lost photo made again from the other four: the bytes it had.
        assert_eq!(issue(&pairs(&parts, &[4, 0, 3, 1]), 2).unwrap(), parts[2]);
        // Two additions made apart, from different photos, give one and the same payload.
        assert_eq!(
            issue(&pairs(&parts, &[0, 1, 2]), 5).unwrap(),
            issue(&pairs(&parts, &[4, 3, 2]), 5).unwrap()
        );
        // A number that is among the payloads is given back as it is.
        assert_eq!(issue(&pairs(&parts, &[0, 1, 2]), 1).unwrap(), parts[1]);
    }

    #[test]
    fn a_set_gets_no_photo_from_parts_that_do_not_belong_together() {
        let set = [13; 16];
        let parts = split(MESSAGE, 3, 5, &set, &mut Counter(17)).unwrap();
        assert_eq!(issue(&pairs(&parts, &[0, 1]), 5), Err(Refused::TooFew));
        assert_eq!(issue(&pairs(&parts, &[0, 1, 2]), 16), Err(Refused::Number));
        // A fourth photo whose key share was changed in one byte: the pieces still agree and
        // the first three alone would open the message, but the share is off its polynomial.
        let mut forged = parts[3].to_vec();
        forged[SHARE.start + 9] ^= 1;
        let given = [
            (0, parts[0].as_slice()),
            (1, parts[1].as_slice()),
            (2, parts[2].as_slice()),
            (3, forged.as_slice()),
        ];
        assert_eq!(issue(&given, 5), Err(Refused::Inconsistent));
        // The same with a changed piece.
        let mut forged = parts[3].to_vec();
        if let Some(last) = forged.last_mut() {
            *last ^= 1;
        }
        let given = [
            (0, parts[0].as_slice()),
            (1, parts[1].as_slice()),
            (2, parts[2].as_slice()),
            (3, forged.as_slice()),
        ];
        assert_eq!(issue(&given, 5), Err(Refused::Inconsistent));
    }

    #[test]
    fn thresholds_outside_two_to_the_count_are_refused() {
        let error = split(b"x", 1, 3, &[0; 16], &mut Counter(1)).unwrap_err();
        assert_eq!(error, StegoError::Threshold);
        let error = split(b"x", 4, 3, &[0; 16], &mut Counter(1)).unwrap_err();
        assert_eq!(error, StegoError::Threshold);
    }
}
