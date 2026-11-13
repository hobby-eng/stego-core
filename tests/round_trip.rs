//! Whole jobs on synthetic photos: hide, save, read back with every password.

#![allow(
    clippy::unwrap_used,
    reason = "the helpers fail the test on a broken fixture"
)]

use jpeg_encoder::{ColorType, Encoder, SamplingFactor};
use stego_core::{
    Content, Cover, Mode, Password, Random, Reading, Secret, Settings, StegoError, WorkFactor,
    hide, reveal,
};

/// A deterministic source for tests only (SplitMix64).
struct TestRandom(u64);

impl Random for TestRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), StegoError> {
        for chunk in bytes.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// A textured colour photo: gradients plus noise, so that most blocks have AC coefficients.
fn photo(width: u16, height: u16, seed: u64) -> Cover {
    styled(width, height, seed, SamplingFactor::F_1_1, 0)
}

/// [`photo`] with chroma subsampling and restart markers.
fn styled(width: u16, height: u16, seed: u64, sampling: SamplingFactor, restart: u16) -> Cover {
    let mut noise = TestRandom(seed);
    let mut pixels = vec![0_u8; usize::from(width) * usize::from(height) * 3];
    noise.fill(&mut pixels).unwrap();
    for (i, pixel) in pixels.as_chunks_mut::<3>().0.iter_mut().enumerate() {
        let x = (i % usize::from(width)) as u32;
        let y = (i / usize::from(width)) as u32;
        let base = ((x * 3 + y * 2) % 200) as u8;
        for channel in pixel.iter_mut() {
            *channel = base.saturating_add(*channel / 3);
        }
    }
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes, 90);
    encoder.set_sampling_factor(sampling);
    if restart > 0 {
        encoder.set_restart_interval(restart);
    }
    encoder
        .encode(&pixels, width, height, ColorType::Rgb)
        .unwrap();
    Cover::new(bytes).unwrap()
}

fn password(text: &str) -> Password {
    Password::new(text).unwrap()
}

fn reread(files: &[Vec<u8>], pick: &[usize]) -> Vec<Cover> {
    pick.iter()
        .map(|&i| Cover::new(files[i].clone()).unwrap())
        .collect()
}

fn read_text(covers: &[Cover], key: &Password) -> Option<String> {
    let refs: Vec<&Cover> = covers.iter().collect();
    match reveal(&refs, key).unwrap() {
        Reading::Complete(found) => Some(found.content().as_text().unwrap().to_owned()),
        _ => None,
    }
}

#[test]
fn photos_of_every_subsampling_and_restart_interval_are_admitted() {
    // Odd sizes leave partial MCUs at the right and bottom edges.
    for (sampling, name, restart) in [
        (SamplingFactor::F_1_1, "4:4:4", 0),
        (SamplingFactor::F_2_2, "4:2:0", 0),
        (SamplingFactor::F_2_1, "4:2:2", 7),
        (SamplingFactor::F_2_2, "4:2:0", 3),
    ] {
        let cover = styled(333, 227, 1, sampling, restart);
        let info = cover.info();
        assert_eq!(
            (info.width, info.height, info.subsampling),
            (333, 227, name)
        );
        assert_eq!(info.restart_interval, usize::from(restart));
        assert_eq!(info.quality, Some(90));
    }
}

#[test]
fn a_subsampled_photo_with_restarts_carries_a_record() {
    let cover = styled(641, 479, 15, SamplingFactor::F_2_2, 5);
    let secret = Content::text("restart markers and 4:2:0").unwrap();
    let key = password("correct horse battery");
    let result = hide(
        &[&cover],
        &Settings::default(),
        Secret {
            content: &secret,
            password: &key,
        },
        None,
        &mut TestRandom(16),
    )
    .unwrap();
    assert_eq!(
        read_text(&reread(result.files(), &[0]), &key).as_deref(),
        Some("restart markers and 4:2:0")
    );
}

#[test]
fn the_standard_mode_reads_back_with_its_password_only() {
    let cover = photo(640, 480, 2);
    let secret = Content::text("abandon ability able about above absent").unwrap();
    let key = password("correct horse battery");
    let result = hide(
        &[&cover],
        &Settings::default(),
        Secret {
            content: &secret,
            password: &key,
        },
        None,
        &mut TestRandom(7),
    )
    .unwrap();
    let report = result.report();
    assert_eq!(*report.secret_sha256.bytes(), secret.sha256());
    assert!(report.files[0].changes > 0);
    let covers = reread(result.files(), &[0]);
    assert_eq!(
        read_text(&covers, &key).as_deref(),
        Some("abandon ability able about above absent")
    );
    let refs: Vec<&Cover> = covers.iter().collect();
    assert!(matches!(
        reveal(&refs, &password("wrong horse battery")).unwrap(),
        Reading::Nothing
    ));
}

#[test]
fn a_decoy_and_its_secret_open_with_their_own_passwords() {
    let cover = photo(800, 600, 3);
    let secret = Content::text("the real seed words").unwrap();
    let decoy = Content::text(&"shopping list: milk, bread, eggs. ".repeat(20)).unwrap();
    let (secret_key, decoy_key) = (password("secret password 1"), password("decoy password 22"));
    let settings = Settings {
        mode: Mode::Decoy,
        ..Settings::default()
    };
    let result = hide(
        &[&cover],
        &settings,
        Secret {
            content: &secret,
            password: &secret_key,
        },
        Some(Secret {
            content: &decoy,
            password: &decoy_key,
        }),
        &mut TestRandom(8),
    )
    .unwrap();
    let covers = reread(result.files(), &[0]);
    assert_eq!(
        read_text(&covers, &secret_key).as_deref(),
        Some("the real seed words")
    );
    assert!(
        read_text(&covers, &decoy_key)
            .unwrap()
            .starts_with("shopping list")
    );
}

#[test]
fn any_two_of_three_photos_open_both_the_decoy_and_the_secret() {
    let covers = [photo(800, 600, 4), photo(800, 600, 5), photo(800, 600, 6)];
    let refs: Vec<&Cover> = covers.iter().collect();
    let secret = Content::file("seed.txt", b"abandon ability able about".to_vec()).unwrap();
    let decoy = Content::text(&"an ordinary note ".repeat(30)).unwrap();
    let (secret_key, decoy_key) = (password("secret password 1"), password("decoy password 22"));
    let settings = Settings {
        mode: Mode::Decoy,
        needed: Some(2),
        ..Settings::default()
    };
    let result = hide(
        &refs,
        &settings,
        Secret {
            content: &secret,
            password: &secret_key,
        },
        Some(Secret {
            content: &decoy,
            password: &decoy_key,
        }),
        &mut TestRandom(9),
    )
    .unwrap();
    for pick in [[0, 1], [1, 2], [2, 0]] {
        let two = reread(result.files(), &pick);
        let two_refs: Vec<&Cover> = two.iter().collect();
        let Reading::Complete(found) = reveal(&two_refs, &secret_key).unwrap() else {
            panic!("two photos {pick:?} did not open the secret");
        };
        assert_eq!(found.content().bytes(), b"abandon ability able about");
        assert_eq!(found.content().name(), "seed.txt");
        assert!(
            read_text(&two, &decoy_key)
                .unwrap()
                .starts_with("an ordinary note")
        );
    }
    let one = reread(result.files(), &[1]);
    let one_refs: Vec<&Cover> = one.iter().collect();
    assert!(matches!(
        reveal(&one_refs, &secret_key).unwrap(),
        Reading::Incomplete {
            found: 1,
            needed: 2
        }
    ));
}

#[test]
fn a_split_message_needs_every_photo() {
    let covers = [photo(640, 480, 10), photo(320, 240, 11)];
    let refs: Vec<&Cover> = covers.iter().collect();
    let secret = Content::text(&"split over two photos ".repeat(10)).unwrap();
    let key = password("correct horse battery");
    let result = hide(
        &refs,
        &Settings::default(),
        Secret {
            content: &secret,
            password: &key,
        },
        None,
        &mut TestRandom(12),
    )
    .unwrap();
    assert!(
        read_text(&reread(result.files(), &[1, 0]), &key)
            .unwrap()
            .starts_with("split over")
    );
    let one = reread(result.files(), &[0]);
    let one_refs: Vec<&Cover> = one.iter().collect();
    assert!(matches!(
        reveal(&one_refs, &key).unwrap(),
        Reading::Incomplete {
            found: 1,
            needed: 2
        }
    ));
}

#[test]
fn a_message_larger_than_the_photo_is_refused() {
    let cover = photo(160, 120, 13);
    let secret = Content::text(&"x".repeat(20_000)).unwrap();
    let key = password("correct horse battery");
    let error = hide(
        &[&cover],
        &Settings::default(),
        Secret {
            content: &secret,
            password: &key,
        },
        None,
        &mut TestRandom(14),
    )
    .unwrap_err();
    assert_eq!(error, StegoError::MessageLong);
}

#[test]
fn the_room_the_core_reports_is_the_room_writing_finds() {
    let cover = photo(640, 480, 17);
    let key = password("correct horse battery");
    let probe = Content::text("x").unwrap();
    let room = stego_core::fit(&[&cover], &Settings::default(), &probe, None)
        .unwrap()
        .secret;
    assert!(room.fits() && room.recommended < room.maximum);
    let exact = Content::text(&"y".repeat(room.recommended)).unwrap();
    let exact_room = stego_core::fit(&[&cover], &Settings::default(), &exact, None)
        .unwrap()
        .secret;
    assert_eq!(exact_room.spare(), 0);
    hide(
        &[&cover],
        &Settings::default(),
        Secret {
            content: &exact,
            password: &key,
        },
        None,
        &mut TestRandom(18),
    )
    .unwrap();
    let over = Content::text(&"z".repeat(room.maximum + 1)).unwrap();
    let error = hide(
        &[&cover],
        &Settings::default(),
        Secret {
            content: &over,
            password: &key,
        },
        None,
        &mut TestRandom(19),
    )
    .unwrap_err();
    assert_eq!(error, StegoError::MessageLong);
}

#[test]
fn the_decoy_password_sees_the_same_record_with_or_without_a_secret_behind_it() {
    let cover = photo(800, 600, 20);
    let decoy = Content::text("an ordinary note").unwrap();
    let secret = Content::text("the real seed words").unwrap();
    let (decoy_key, secret_key) = (password("decoy password 22"), password("secret password 1"));
    let settings = Settings {
        mode: Mode::Decoy,
        ..Settings::default()
    };
    let with_secret = hide(
        &[&cover],
        &settings,
        Secret {
            content: &secret,
            password: &secret_key,
        },
        Some(Secret {
            content: &decoy,
            password: &decoy_key,
        }),
        &mut TestRandom(21),
    )
    .unwrap();
    let alone = hide(
        &[&cover],
        &settings,
        Secret {
            content: &decoy,
            password: &decoy_key,
        },
        None,
        &mut TestRandom(22),
    )
    .unwrap();
    let seen = |files: &[Vec<u8>]| {
        let covers = reread(files, &[0]);
        let refs: Vec<&Cover> = covers.iter().collect();
        let Reading::Complete(found) = reveal(&refs, &decoy_key).unwrap() else {
            panic!("the decoy did not open");
        };
        let (_, _, record) = found.report().files[0];
        (record.layer, record.body_bytes, record.record_bits)
    };
    assert_eq!(seen(with_secret.files()), seen(alone.files()));
}

#[test]
fn a_record_opens_only_with_the_pim_and_memory_level_it_was_written_with() {
    let cover = photo(640, 480, 23);
    let secret = Content::text("stretched harder").unwrap();
    let work = WorkFactor::new(1, 1).unwrap();
    assert_eq!((work.passes(), work.memory_kib()), (6, 192 * 1024));
    let key = password("correct horse battery").with_work(work);
    let result = hide(
        &[&cover],
        &Settings::default(),
        Secret {
            content: &secret,
            password: &key,
        },
        None,
        &mut TestRandom(24),
    )
    .unwrap();
    assert_eq!(result.report().files[0].secret.kdf_passes, 6);
    let covers = reread(result.files(), &[0]);
    assert_eq!(
        read_text(&covers, &key).as_deref(),
        Some("stretched harder")
    );
    let refs: Vec<&Cover> = covers.iter().collect();
    assert!(matches!(
        reveal(&refs, &password("correct horse battery")).unwrap(),
        Reading::Nothing
    ));
}

#[test]
fn a_photo_given_twice_is_read_once_and_refused_for_writing() {
    let cover = photo(640, 480, 25);
    let secret = Content::text("only once").unwrap();
    let key = password("correct horse battery");
    let error = hide(
        &[&cover, &cover],
        &Settings::default(),
        Secret {
            content: &secret,
            password: &key,
        },
        None,
        &mut TestRandom(26),
    )
    .unwrap_err();
    assert_eq!(error, StegoError::DuplicatePhoto);
    let other = photo(640, 480, 27);
    let result = hide(
        &[&cover, &other],
        &Settings::default(),
        Secret {
            content: &secret,
            password: &key,
        },
        None,
        &mut TestRandom(28),
    )
    .unwrap();
    // Photo 0 twice and photo 1: the copy counts once, so the set is complete.
    let covers = reread(result.files(), &[0, 0, 1]);
    assert_eq!(read_text(&covers, &key).as_deref(), Some("only once"));
}
