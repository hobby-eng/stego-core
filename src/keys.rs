//! One Argon2id stretch per password and photo; separate keys for each layer's order, coder and
//! cipher.

use crate::protect::{Secret, WorkArea};
use crate::report::Layer;
use crate::{Password, StegoError};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Argon2id lanes; one, so that a browser without threads computes the same key.
pub const KDF_LANES: u32 = 1;
/// Argon2id passes at PIM 0.
const BASE_PASSES: u32 = 3;

/// The two settings a person may choose for a password: the PIM multiplies the
/// Argon2id passes and the memory level sets its memory. Both default to 0: 3 passes and
/// 128 MiB. Neither is stored in the photo; whoever reads must enter the same two numbers.
///
/// Level 0 opens on phones and in browsers; a browser cannot go past about 2 GiB (level 8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkFactor {
    pim: u32,
    memory_level: u32,
}

impl WorkFactor {
    /// The highest PIM. A factor of 1,024 already adds only ten bits while it turns seconds into
    /// hours.
    pub const MAX_PIM: u32 = 1023;
    /// The highest memory level: 3 TiB. Level 30 would need 2^32 KiB, one more than Argon2
    /// accepts.
    pub const MAX_MEMORY_LEVEL: u32 = 29;

    /// Accepts a PIM up to [`WorkFactor::MAX_PIM`] and a memory level up to
    /// [`WorkFactor::MAX_MEMORY_LEVEL`]; fails with [`StegoError::Pim`], then [`StegoError::MemoryLevel`].
    pub const fn new(pim: u32, memory_level: u32) -> Result<Self, StegoError> {
        if pim > Self::MAX_PIM {
            return Err(StegoError::Pim);
        }
        if memory_level > Self::MAX_MEMORY_LEVEL {
            return Err(StegoError::MemoryLevel);
        }
        Ok(Self { pim, memory_level })
    }

    /// The PIM.
    #[must_use]
    pub const fn pim(self) -> u32 {
        self.pim
    }

    /// The memory level.
    #[must_use]
    pub const fn memory_level(self) -> u32 {
        self.memory_level
    }

    /// The Argon2id passes `t(PIM) = 3 * (PIM + 1)`.
    #[must_use]
    pub const fn passes(self) -> u32 {
        BASE_PASSES * (self.pim + 1)
    }

    /// The Argon2id memory `m(MEM) = (2 + MEM mod 2) * 2^(16 + floor(MEM / 2))` in KiB: 128,
    /// 192, 256, 384, 512, 768 MiB, 1 GiB and so on, up to 3 TiB at level 29.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        (2 + self.memory_level % 2) << (16 + self.memory_level / 2)
    }
}

/// Bytes of every key.
pub(crate) const KEY_BYTES: usize = 32;

const ROOT_LABEL: &[u8] = b"stego-core 1 root";
const ORDER_LABEL: &[u8] = b"stego-core 1 order";
const CODER_LABEL: &[u8] = b"stego-core 1 coder";
const CIPHER_LABEL: &[u8] = b"stego-core 1 cipher";

/// The root key of one password in one photo.
pub(crate) struct Keys {
    root: Secret,
}

/// The keys of one layer.
pub(crate) struct LayerKeys {
    order: Secret,
    /// Seed of the syndrome coder's matrix columns or of the wet-paper columns.
    pub coder: u64,
    cipher: Secret,
}

impl Keys {
    /// Stretches `password` with the photo's `context` as salt, so that a guess made for one
    /// photo is worthless for another.
    pub(crate) fn derive(
        password: &Password,
        context: &[u8; KEY_BYTES],
    ) -> Result<Self, StegoError> {
        let work = password.work();
        let mut root = Secret::zeroed(KEY_BYTES);
        crate::plain::note(root.is_locked());
        stretch(
            password.bytes(),
            context,
            (work.memory_kib(), work.passes()),
            root.as_mut_bytes(),
        )?;
        Ok(Self { root })
    }

    /// The keys of `layer` with site rule byte `rule`.
    pub(crate) fn layer(&self, layer: Layer, rule: u8) -> Result<LayerKeys, StegoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(ROOT_LABEL), self.root.as_bytes());
        let info = [layer.id(), rule];
        let mut order = Secret::zeroed(KEY_BYTES);
        let mut coder = Zeroizing::new([0; 8]);
        let mut cipher = Secret::zeroed(KEY_BYTES);
        crate::plain::note(order.is_locked() && cipher.is_locked());
        hkdf.expand_multi_info(&[ORDER_LABEL, &info], order.as_mut_bytes())
            .map_err(|_| StegoError::Crypto)?;
        hkdf.expand_multi_info(&[CODER_LABEL, &info], coder.as_mut())
            .map_err(|_| StegoError::Crypto)?;
        hkdf.expand_multi_info(&[CIPHER_LABEL, &info], cipher.as_mut_bytes())
            .map_err(|_| StegoError::Crypto)?;
        Ok(LayerKeys {
            order,
            coder: u64::from_le_bytes(*coder),
            cipher,
        })
    }

    /// The root key, for the self-test's known answer.
    pub(crate) fn root_bytes(&self) -> &[u8] {
        self.root.as_bytes()
    }
}

impl LayerKeys {
    /// The record cipher's key.
    pub(crate) fn cipher(&self) -> &[u8] {
        self.cipher.as_bytes()
    }

    /// A keyed shuffle of `0..count`: the order in which the coder visits the sites, so that
    /// the changes spread over the whole photo.
    pub(crate) fn order(&self, count: usize) -> Result<Vec<u32>, StegoError> {
        let count32 = u32::try_from(count).map_err(|_| StegoError::ImageLarge)?;
        let mut order: Vec<u32> = (0..count32).collect();
        let mut stream = ChaCha20::new_from_slices(self.order.as_bytes(), &[0; 12])
            .map_err(|_| StegoError::Crypto)?;
        let mut buffer = [0_u8; 8];
        for i in (1..order.len()).rev() {
            // Rejection sampling keeps every permutation equally likely.
            let bound = i as u64 + 1;
            let zone = u64::MAX - u64::MAX % bound;
            let j = loop {
                buffer.fill(0);
                stream.apply_keystream(&mut buffer);
                let value = u64::from_le_bytes(buffer);
                if value < zone {
                    break value % bound;
                }
            };
            // `j <= i < count`, which fits `usize`.
            order.swap(i, j as usize);
        }
        Ok(order)
    }
}

/// Argon2id of `password` with `salt` at `(memory KiB, passes)` and [`KDF_LANES`] lanes into
/// `out`. The work area holds every intermediate block of the stretch: pages of its own, locked
/// where the limit allows and wiped before they are given back. The self-test runs this same
/// path at a small memory.
pub(crate) fn stretch(
    password: &[u8],
    salt: &[u8],
    (memory_kib, passes): (u32, u32),
    out: &mut [u8],
) -> Result<(), StegoError> {
    let parameters = Params::new(memory_kib, passes, KDF_LANES, Some(out.len()))
        .map_err(|_| StegoError::Crypto)?;
    let area_bytes = parameters
        .block_count()
        .checked_mul(Block::SIZE)
        .ok_or(StegoError::Memory)?;
    let mut area = WorkArea::new(area_bytes).ok_or(StegoError::Memory)?;
    crate::plain::note_stretch(area.is_locked());
    let stretched = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
        .hash_password_into_with_memory(password, salt, out, blocks(&mut area));
    area.as_mut_slice().zeroize();
    stretched.map_err(|_| StegoError::Crypto)
}

/// The work area as Argon2 blocks (a deliberate copy of `blocks` in mhfe_core's
/// `src/engine/native.rs`, CORE-10: a change goes to both).
#[allow(
    unsafe_code,
    reason = "RustCrypto takes its memory as Blocks, and bytes become Blocks through a raw pointer"
)]
fn blocks(work_area: &mut WorkArea) -> &mut [Block] {
    let area = work_area.as_mut_slice();
    let count = area.len() / Block::SIZE;
    // SAFETY: pages start on a page boundary, which meets a Block's alignment of 64; `count`
    // Blocks fit in the area; a Block is 128 u64, of which every bit pattern is valid; and the
    // result borrows the pages exclusively, as `area` did.
    unsafe { std::slice::from_raw_parts_mut(area.as_mut_ptr().cast::<Block>(), count) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_key_matches_an_independent_argon2id() {
        // RFC 9106 reference implementation (phc-winner-argon2, argon2 -id -m 17 -t 3 -p 1 -l 32)
        // with password "public-test-password" and salt 32 × 0x2a: the module this crate grew
        // from recorded the same value for the same parameters.
        let password = Password::new("public-test-password").unwrap();
        let keys = Keys::derive(&password, &[42; KEY_BYTES]).unwrap();
        assert_eq!(
            keys.root_bytes()[..],
            [
                0xab, 0x8b, 0x46, 0xa3, 0x6a, 0x02, 0x35, 0x9e, 0xbd, 0xb2, 0xaa, 0xdc, 0xf6, 0x0c,
                0x6d, 0xf1, 0x46, 0x41, 0xda, 0x5d, 0x69, 0xf7, 0x81, 0xdc, 0x64, 0xa6, 0x30, 0x79,
                0x63, 0xc7, 0xc7, 0x1d
            ]
        );
    }

    #[test]
    fn layers_and_rules_get_different_keys_and_orders() {
        let keys = Keys {
            root: {
                let mut root = Secret::with_capacity(KEY_BYTES);
                root.push(&[7; KEY_BYTES]).unwrap();
                root
            },
        };
        let a = keys.layer(Layer::Standard, 1).unwrap();
        let b = keys.layer(Layer::Standard, 2).unwrap();
        let c = keys.layer(Layer::Hidden, 1).unwrap();
        assert_ne!(a.coder, b.coder);
        assert_ne!(a.cipher(), c.cipher());
        let order = a.order(1000).unwrap();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..1000).collect::<Vec<u32>>());
        assert_ne!(order, b.order(1000).unwrap());
    }

    #[test]
    fn memory_levels_follow_the_series_from_128_mib() {
        let mib = [128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072];
        for (level, expected) in (0..).zip(mib) {
            assert_eq!(
                WorkFactor::new(0, level).unwrap().memory_kib(),
                expected * 1024
            );
        }
        let top = WorkFactor::new(WorkFactor::MAX_PIM, WorkFactor::MAX_MEMORY_LEVEL).unwrap();
        assert_eq!(u64::from(top.memory_kib()), 3 << 30);
        assert_eq!(top.passes(), 3 * 1024);
        assert_eq!(WorkFactor::new(1024, 0).unwrap_err(), StegoError::Pim);
        assert_eq!(WorkFactor::new(0, 30).unwrap_err(), StegoError::MemoryLevel);
    }
}
