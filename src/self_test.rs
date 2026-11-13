//! Known answers of every part (CORE-27): a host runs [`startup_self_test`] before it opens its
//! controls and keeps them closed when a check fails; [`full_self_test`] adds the slow checks on
//! request (CORE-30). Expected values come from published vectors where they exist; the rest
//! are round trips through the code under test, named as such.

mod sample;

use crate::algorithm::stc::{
    HEIGHT, SEGMENT_BITS, binary_embed, binary_extract, column_prefix, columns, prefix_extract,
};
use crate::random::Random;
use crate::shard::Code;
use crate::{Content, Cover, Password, Reading, Secret, Settings, StegoError, hide, reveal};
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// One check: its name and whether it passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Check {
    /// What was checked and against which source.
    pub name: &'static str,
    /// Whether the answer was the expected one.
    pub passed: bool,
}

/// The checks of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTest {
    checks: Vec<Check>,
}

impl SelfTest {
    /// Whether every check passed. A host opens its controls only then.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    /// Every check, in the order run.
    #[must_use]
    pub fn checks(&self) -> &[Check] {
        &self.checks
    }
}

/// The fast checks, run at every start: milliseconds each.
#[must_use]
pub fn startup_self_test() -> SelfTest {
    let checks = [
        ("SHA-256: FIPS 180-2 B.1", sha256 as fn() -> bool),
        ("HKDF-SHA-256: RFC 5869 A.1", hkdf_sha256),
        ("XChaCha20-Poly1305: draft-irtf-cfrg-xchacha A.1", xchacha),
        ("Argon2id: RFC 9106 5.3", argon2id),
        ("Reed–Solomon: 01 02 03 04 gives parity 45 5E", reed_solomon),
        (
            "Shamir (SSKR) and dispersal: 2 of 3 open, 1 does not (round trip)",
            threshold,
        ),
        (
            "Syndrome-trellis code: embeds and reads back, prefix reader agrees (round trip)",
            trellis,
        ),
        (
            "JPEG: an independent encoder's photo re-encodes to its exact bytes",
            jpeg,
        ),
    ];
    SelfTest {
        checks: checks
            .iter()
            .map(|&(name, run)| Check {
                name,
                passed: run(),
            })
            .collect(),
    }
}

/// Every startup check, then the slow ones: the password stretch at its default 128 MiB and a
/// whole hiding job read back. Seconds, and 128 MiB of memory.
#[must_use]
pub fn full_self_test() -> SelfTest {
    let mut all = startup_self_test();
    all.checks.push(Check {
        name: "Argon2id at the default 128 MiB: the reference implementation's answer",
        passed: default_stretch(),
    });
    all.checks.push(Check {
        name: "A whole job: hide in the sample photo and read back (round trip)",
        passed: whole_job(),
    });
    all
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn sha256() -> bool {
    Sha256::digest(b"abc").as_slice()
        == hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
}

fn hkdf_sha256() -> bool {
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let mut okm = [0_u8; 42];
    Hkdf::<Sha256>::new(Some(&salt), &[0x0b; 22])
        .expand(&info, &mut okm)
        .is_ok()
        && okm.as_slice()
            == hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            )
}

fn xchacha() -> bool {
    let key: Vec<u8> = (0x80..=0x9f).collect();
    let nonce: Vec<u8> = (0x40..=0x57).collect();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let mut text = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
    let expected = hex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39",
        "ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52e"
    ));
    let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&key) else {
        return false;
    };
    let Ok(nonce) = XNonce::try_from(nonce.as_slice()) else {
        return false;
    };
    let Ok(tag) = cipher.encrypt_inout_detached(&nonce, &aad, text.as_mut_slice().into()) else {
        return false;
    };
    let mut forged = text.clone();
    forged[0] ^= 1;
    text == expected
        && tag.as_slice() == hex("c0875924c1c7987947deafd8780acf49")
        && cipher
            .decrypt_inout_detached(&nonce, &aad, forged.as_mut_slice().into(), &tag)
            .is_err()
}

fn argon2id() -> bool {
    let Ok(data) = AssociatedData::new(&[4; 12]) else {
        return false;
    };
    let Ok(params) = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(data)
        .output_len(32)
        .build()
    else {
        return false;
    };
    let Ok(argon) = Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params)
    else {
        return false;
    };
    let mut tag = [0_u8; 32];
    argon
        .hash_password_into(&[1; 32], &[2; 16], &mut tag)
        .is_ok()
        && tag.as_slice() == hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
}

fn reed_solomon() -> bool {
    let Ok(code) = Code::new(4) else {
        return false;
    };
    let data: [&[u8]; 4] = [&[1], &[2], &[3], &[4]];
    let (Ok(p4), Ok(p5)) = (code.piece(&data, 4), code.piece(&data, 5)) else {
        return false;
    };
    let rebuilt = code.rebuild(&[(5, &p5), (1, &[2]), (4, &p4), (3, &[4])]);
    p4 == [0x45] && p5 == [0x5E] && rebuilt.is_ok_and(|d| d == [[1], [2], [3], [4]])
}

fn threshold() -> bool {
    let set = [9; 16];
    let Ok(parts) = crate::threshold::split(b"self-test key share", 2, 3, &set, &mut Fixed(1))
    else {
        return false;
    };
    let pair = [(2, parts[2].as_slice()), (0, parts[0].as_slice())];
    let one = [(1, parts[1].as_slice())];
    matches!(
        crate::threshold::join(&pair, 3, &set),
        crate::threshold::Joined::Message(m) if &m[..] == b"self-test key share"
    ) && matches!(
        crate::threshold::join(&one, 3, &set),
        crate::threshold::Joined::Unreadable
    )
}

fn trellis() -> bool {
    let n = 3000;
    let mut random = Fixed(5);
    let mut cover = vec![0_u8; n];
    let mut costs = vec![0_u8; n];
    let mut message = vec![0_u8; 300];
    if random.fill(&mut cover).is_err()
        || random.fill(&mut costs).is_err()
        || random.fill(&mut message).is_err()
    {
        return false;
    }
    let cover: Vec<u8> = cover.iter().map(|b| b & 1).collect();
    let costs: Vec<f64> = costs.iter().map(|&b| f64::from(b) + 1.0).collect();
    let message: Vec<u8> = message.iter().map(|b| b & 1).collect();
    let cols = columns(n, HEIGHT, 77);
    let Ok(stego) = binary_embed(&cover, &costs, &message, &cols, HEIGHT, SEGMENT_BITS) else {
        return false;
    };
    let read = binary_extract(&stego, message.len(), &cols, HEIGHT, SEGMENT_BITS);
    let prefix = prefix_extract(
        &column_prefix(&stego, &cols, HEIGHT),
        message.len(),
        HEIGHT,
        SEGMENT_BITS,
    );
    read == message && prefix == message
}

fn jpeg() -> bool {
    Cover::new(sample::SAMPLE.to_vec()).is_ok_and(|cover| cover.bytes() == sample::SAMPLE)
}

fn default_stretch() -> bool {
    // The PHC reference implementation (argon2 -id -m 17 -t 3 -p 1 -l 32), password
    // "public-test-password", salt 32 × 0x2a.
    let Ok(password) = Password::new("public-test-password") else {
        return false;
    };
    crate::keys::Keys::derive(&password, &[42; 32]).is_ok_and(|keys| {
        keys.root_bytes() == hex("ab8b46a36a02359ebdb2aadcf60c6df14641da5d69f781dc64a6307963c7c71d")
    })
}

fn whole_job() -> bool {
    let (Ok(cover), Ok(text), Ok(key)) = (
        Cover::new(sample::SAMPLE.to_vec()),
        Content::text("self-test"),
        Password::new("self-test password"),
    ) else {
        return false;
    };
    let Ok(result) = hide(
        &[&cover],
        &Settings::default(),
        Secret {
            content: &text,
            password: &key,
        },
        None,
        &mut Fixed(3),
    ) else {
        return false;
    };
    let Ok(written) = Cover::new(result.files()[0].clone()) else {
        return false;
    };
    matches!(reveal(&[&written], &key), Ok(Reading::Complete(found)) if found.content().bytes() == b"self-test")
}

/// A fixed source for the self-test's own inputs: the checks need repeatable data, never secret.
struct Fixed(u64);

impl Random for Fixed {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), StegoError> {
        for b in bytes {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            // The high byte of the state.
            *b = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_startup_check_passes() {
        let run = startup_self_test();
        for check in run.checks() {
            assert!(check.passed, "{}", check.name);
        }
        assert!(run.passed());
    }

    #[test]
    fn the_full_self_test_passes() {
        assert!(full_self_test().passed());
    }
}
