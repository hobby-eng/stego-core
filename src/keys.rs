//! One Argon2id stretch per password and photo; separate keys for each layer's order, coder and
//! cipher.

use crate::report::Layer;
use crate::{Password, StegoError};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Argon2id memory in KiB: 128 MiB, the cost an attacker pays for every guess.
pub const KDF_MEMORY_KIB: u32 = 128 * 1024;
/// Argon2id passes.
pub const KDF_PASSES: u32 = 3;
/// Argon2id lanes; one, so that a browser without threads computes the same key.
pub const KDF_LANES: u32 = 1;
/// Bytes of every key.
pub(crate) const KEY_BYTES: usize = 32;

const ROOT_LABEL: &[u8] = b"stego-core 1 root";
const ORDER_LABEL: &[u8] = b"stego-core 1 order";
const CODER_LABEL: &[u8] = b"stego-core 1 coder";
const CIPHER_LABEL: &[u8] = b"stego-core 1 cipher";

/// The root key of one password in one photo.
pub(crate) struct Keys {
    root: Zeroizing<[u8; KEY_BYTES]>,
}

/// The keys of one layer.
pub(crate) struct LayerKeys {
    order: Zeroizing<[u8; KEY_BYTES]>,
    /// Seed of the syndrome coder's matrix columns or of the wet-paper columns.
    pub coder: u64,
    pub cipher: Zeroizing<[u8; KEY_BYTES]>,
}

impl Keys {
    /// Stretches `password` with the photo's `context` as salt, so that a guess made for one
    /// photo is worthless for another.
    pub(crate) fn derive(
        password: &Password,
        context: &[u8; KEY_BYTES],
    ) -> Result<Self, StegoError> {
        let parameters = Params::new(KDF_MEMORY_KIB, KDF_PASSES, KDF_LANES, Some(KEY_BYTES))
            .map_err(|_| StegoError::Crypto)?;
        let mut memory = Zeroizing::new(vec![Block::default(); parameters.block_count()]);
        let mut root = Zeroizing::new([0; KEY_BYTES]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
            .hash_password_into_with_memory(password.bytes(), context, root.as_mut(), &mut memory)
            .map_err(|_| StegoError::Crypto)?;
        Ok(Self { root })
    }

    /// The keys of `layer` with site rule byte `rule`.
    pub(crate) fn layer(&self, layer: Layer, rule: u8) -> Result<LayerKeys, StegoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(ROOT_LABEL), self.root.as_ref());
        let info = [layer.id(), rule];
        let mut order = Zeroizing::new([0; KEY_BYTES]);
        let mut coder = Zeroizing::new([0; 8]);
        let mut cipher = Zeroizing::new([0; KEY_BYTES]);
        hkdf.expand_multi_info(&[ORDER_LABEL, &info], order.as_mut())
            .map_err(|_| StegoError::Crypto)?;
        hkdf.expand_multi_info(&[CODER_LABEL, &info], coder.as_mut())
            .map_err(|_| StegoError::Crypto)?;
        hkdf.expand_multi_info(&[CIPHER_LABEL, &info], cipher.as_mut())
            .map_err(|_| StegoError::Crypto)?;
        Ok(LayerKeys {
            order,
            coder: u64::from_le_bytes(*coder),
            cipher,
        })
    }

    #[cfg(test)]
    pub(crate) fn root(&self) -> &[u8; KEY_BYTES] {
        &self.root
    }
}

impl LayerKeys {
    /// A keyed shuffle of `0..count`: the order in which the coder visits the sites, so that
    /// the changes spread over the whole photo.
    pub(crate) fn order(&self, count: usize) -> Result<Vec<u32>, StegoError> {
        let count32 = u32::try_from(count).map_err(|_| StegoError::ImageLarge)?;
        let mut order: Vec<u32> = (0..count32).collect();
        let mut stream = ChaCha20::new_from_slices(self.order.as_ref(), &[0; 12])
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
            keys.root()[..],
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
            root: Zeroizing::new([7; KEY_BYTES]),
        };
        let a = keys.layer(Layer::Standard, 1).unwrap();
        let b = keys.layer(Layer::Standard, 2).unwrap();
        let c = keys.layer(Layer::Hidden, 1).unwrap();
        assert_ne!(a.coder, b.coder);
        assert_ne!(a.cipher[..], c.cipher[..]);
        let order = a.order(1000).unwrap();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..1000).collect::<Vec<u32>>());
        assert_ne!(order, b.order(1000).unwrap());
    }
}
