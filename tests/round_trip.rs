//! Whole jobs on synthetic photos: hide, save, read back with every password.

#![allow(
    clippy::unwrap_used,
    reason = "the helpers fail the test on a broken fixture"
)]

use jpeg_encoder::{ColorType, Encoder, SamplingFactor};
use stego_core::{
    Addition, Content, Cover, Mode, Password, Place, Random, Reading, Secret, SetError, Settings,
    StegoError, WorkFactor, extend, fit, hide, reveal,
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
    assert_eq!(room.limiting, Some(0));
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
fn a_photo_given_twice_is_read_once_and_refused_for_room_and_writing() {
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
    // The room refuses what writing refuses: A, B, A for 2 of 3 is not a set of three photos.
    let two_of_three = Settings {
        needed: Some(2),
        ..Settings::default()
    };
    assert_eq!(
        fit(&[&cover, &other, &cover], &two_of_three, &secret, None).unwrap_err(),
        StegoError::DuplicatePhoto
    );
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

/// A JPEG whose header claims 65535 × 65535 pixels with one byte of coded data.
fn claims_huge_size() -> Vec<u8> {
    let mut file = vec![0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43, 0x00];
    file.extend([1_u8; 64]);
    file.extend([
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x01, 0x11, 0x00,
    ]);
    for class in [0x00, 0x10] {
        file.extend([0xFF, 0xC4, 0x00, 0x14, class, 1]);
        file.extend([0_u8; 15]);
        file.push(0);
    }
    file.extend([
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x00, 0xFF, 0xD9,
    ]);
    file
}

#[test]
fn a_header_that_claims_more_blocks_than_its_data_holds_is_refused_at_once() {
    let file = claims_huge_size();
    // The header alone already tells a host the job would be enormous.
    assert!(stego_core::memory_estimate(&file).unwrap() > 100 << 30);
    assert_eq!(Cover::new(file).err(), Some(StegoError::Jpeg));
}

#[test]
fn of_two_sets_under_one_password_the_larger_is_read_and_the_other_counted() {
    let key = password("correct horse battery");
    let write = |seeds: &[u64], text: &str, needed: Option<u8>, random: u64| {
        let covers: Vec<Cover> = seeds.iter().map(|&seed| photo(320, 240, seed)).collect();
        let refs: Vec<&Cover> = covers.iter().collect();
        let content = Content::text(text).unwrap();
        let settings = Settings {
            needed,
            ..Settings::default()
        };
        let secret = Secret {
            content: &content,
            password: &key,
        };
        let result = hide(&refs, &settings, secret, None, &mut TestRandom(random)).unwrap();
        result.files().to_vec()
    };
    let two = write(&[40, 41], "in two photos", None, 42);
    let three = write(&[43, 44, 45], "in three photos", Some(2), 46);
    // Photos 0 and 1 hold one whole set, photos 2 to 4 another: the larger is read, its photos
    // are named and the other set is counted, not passed over in silence.
    let files: Vec<Vec<u8>> = two.iter().chain(&three).cloned().collect();
    let covers = reread(&files, &[0, 1, 2, 3, 4]);
    let refs: Vec<&Cover> = covers.iter().collect();
    let Reading::Complete(found) = reveal(&refs, &key).unwrap() else {
        panic!("no set was read");
    };
    assert_eq!(found.content().as_text(), Some("in three photos"));
    let photos: Vec<usize> = found.report().files.iter().map(|file| file.0).collect();
    assert_eq!(photos, [2, 3, 4]);
    assert_eq!(found.report().other_sets, 1);
    // Without the larger set's photos the smaller one is read, and nothing else is there.
    let covers = reread(&files, &[0, 1]);
    let refs: Vec<&Cover> = covers.iter().collect();
    let Reading::Complete(found) = reveal(&refs, &key).unwrap() else {
        panic!("the smaller set was not read");
    };
    assert_eq!(found.content().as_text(), Some("in two photos"));
    assert_eq!(found.report().other_sets, 0);
}

/// Hides `text` under `key` in fresh photos made from `seeds`, any `needed` of them enough when
/// given, and returns the written photos.
fn written(seeds: &[u64], text: &str, key: &Password, needed: Option<u8>) -> Vec<Cover> {
    let covers: Vec<Cover> = seeds.iter().map(|&seed| photo(320, 240, seed)).collect();
    let refs: Vec<&Cover> = covers.iter().collect();
    let content = Content::text(text).unwrap();
    let settings = Settings {
        needed,
        ..Settings::default()
    };
    let secret = Secret {
        content: &content,
        password: key,
    };
    let result = hide(&refs, &settings, secret, None, &mut TestRandom(seeds[0])).unwrap();
    reread(result.files(), &(0..seeds.len()).collect::<Vec<_>>())
}

/// A further photo for the set in `photos`, made from a fresh photo of `seed`.
fn added(
    photos: &[&Cover],
    seed: u64,
    key: &Password,
    place: Place,
) -> Result<(Cover, stego_core::Membership), StegoError> {
    let fresh = photo(320, 240, seed);
    let addition = Addition {
        photos,
        photo: &fresh,
        password: key,
        behind: None,
        place,
    };
    let extended = extend(&addition, &Settings::default(), &mut TestRandom(seed))?;
    let set = extended.report().set;
    Ok((Cover::new(extended.into_file()).unwrap(), set))
}

/// Two photos read again from their bytes, as a reader gets them.
fn reread_pair(first: &Cover, second: &Cover) -> Vec<Cover> {
    reread(&[first.bytes().to_vec(), second.bytes().to_vec()], &[0, 1])
}

#[test]
fn a_set_of_three_of_five_photos_grows_to_seven() {
    let key = password("correct horse battery");
    let text = "three of five, then seven";
    let old = written(&[50, 51, 52, 53, 54], text, &key, Some(3));
    let before: Vec<Vec<u8>> = old.iter().map(|cover| cover.bytes().to_vec()).collect();
    // A sixth photo from the first three; a seventh from three others, the sixth among them.
    let (sixth, place) = added(&[&old[0], &old[1], &old[2]], 56, &key, Place::Next).unwrap();
    assert_eq!(
        (
            place.number,
            place.replaces,
            place.needed,
            place.numbers,
            place.issued
        ),
        (6, false, 3, 4, 6)
    );
    let (seventh, place) = added(&[&sixth, &old[4], &old[1]], 58, &key, Place::Next).unwrap();
    assert_eq!((place.number, place.replaces, place.issued), (7, false, 7));
    // The five photos the set had are what they were.
    for (cover, bytes) in old.iter().zip(&before) {
        assert_eq!(cover.bytes(), bytes.as_slice());
    }
    // Every three of the seven open the message; no two do.
    let mut all = old;
    all.push(sixth);
    all.push(seventh);
    for a in 0..7 {
        for b in a + 1..7 {
            assert!(
                matches!(
                    reveal(&[&all[a], &all[b]], &key).unwrap(),
                    Reading::Incomplete {
                        found: 2,
                        needed: 3
                    }
                ),
                "photos {a} and {b} opened"
            );
            for c in b + 1..7 {
                let Reading::Complete(found) = reveal(&[&all[c], &all[a], &all[b]], &key).unwrap()
                else {
                    panic!("photos {a}, {b} and {c} did not open");
                };
                assert_eq!(found.content().as_text(), Some(text));
            }
        }
    }
}

#[test]
fn a_lost_photo_is_replaced_and_additions_made_apart_are_one_piece() {
    let key = password("correct horse battery");
    let text = "two of three";
    let old = written(&[60, 61, 62], text, &key, Some(2));
    // Photo 2 is lost: a new photo takes its number, made from the other two.
    let (again, place) = added(&[&old[0], &old[2]], 63, &key, Place::Number(2)).unwrap();
    assert_eq!(
        (place.number, place.replaces, place.numbers, place.issued),
        (2, true, 3, 3)
    );
    assert_eq!(
        read_text(&reread_pair(&again, &old[0]), &key).as_deref(),
        Some(text)
    );
    assert_eq!(
        read_text(&reread_pair(&again, &old[2]), &key).as_deref(),
        Some(text)
    );
    // The lost photo turns up: it and its replacement hold one piece and count once.
    assert!(matches!(
        reveal(&[&again, &old[1]], &key).unwrap(),
        Reading::Incomplete {
            found: 1,
            needed: 2
        }
    ));
    // Two photos added apart, from different old photos, take the same new number and hold
    // the same piece: together they are one photo, not two that may be lost.
    let (one, first) = added(&[&old[0], &old[1]], 64, &key, Place::Next).unwrap();
    let (other, second) = added(&[&old[2], &old[1]], 65, &key, Place::Next).unwrap();
    assert_eq!((first.number, second.number), (4, 4));
    assert_ne!(one.bytes(), other.bytes());
    assert!(matches!(
        reveal(&[&one, &other], &key).unwrap(),
        Reading::Incomplete {
            found: 1,
            needed: 2
        }
    ));
    assert_eq!(
        read_text(&reread_pair(&other, &old[2]), &key).as_deref(),
        Some(text)
    );
}

#[test]
fn a_set_is_given_no_photo_unless_the_photos_are_one_whole_set() {
    let key = password("correct horse battery");
    let set = written(&[70, 71, 72], "two of three", &key, Some(2));
    let other = written(&[73, 74, 75], "another two of three", &key, Some(2));
    let split = written(&[76, 77], "every photo needed", &key, None);
    let refused = |photos: &[&Cover], key: &Password, place: Place| {
        added(photos, 78, key, place).map(|_| ()).unwrap_err()
    };
    let whole = [&set[0], &set[1], &set[2]];
    // A wrong password, too few photos, two sets at once, a set that needs every photo.
    let wrong = password("another public password");
    assert_eq!(
        refused(&whole, &wrong, Place::Next),
        StegoError::Set(SetError::Nothing)
    );
    assert_eq!(
        refused(&[&set[1]], &key, Place::Next),
        StegoError::Set(SetError::Incomplete {
            found: 1,
            needed: 2
        })
    );
    assert_eq!(
        refused(&[&set[0], &set[1], &other[0], &other[1]], &key, Place::Next),
        StegoError::Set(SetError::Several)
    );
    assert_eq!(
        refused(&[&split[0], &split[1]], &key, Place::Next),
        StegoError::Set(SetError::EveryPhotoNeeded)
    );
    // Numbers a set does not have.
    for number in [0, 17] {
        assert_eq!(
            refused(&whole, &key, Place::Number(number)),
            StegoError::Set(SetError::Number)
        );
    }
    // The new photo is one of the photos given.
    let addition = Addition {
        photos: &whole,
        photo: &set[0],
        password: &key,
        behind: None,
        place: Place::Next,
    };
    let error = extend(&addition, &Settings::default(), &mut TestRandom(79)).unwrap_err();
    assert_eq!(error, StegoError::DuplicatePhoto);
    // The last number a set has, and then none is left.
    let (last, place) = added(&whole, 80, &key, Place::Number(16)).unwrap();
    assert_eq!(
        (place.number, place.replaces, place.issued),
        (16, false, 16)
    );
    assert_eq!(
        refused(&[&last, &set[0]], &key, Place::Next),
        StegoError::Set(SetError::Full)
    );
}

#[test]
fn a_set_with_a_decoy_grows_under_one_password_or_both() {
    let covers = [
        photo(800, 600, 84),
        photo(800, 600, 85),
        photo(800, 600, 86),
    ];
    let refs: Vec<&Cover> = covers.iter().collect();
    let secret = Content::text("the secret behind").unwrap();
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
        &mut TestRandom(87),
    )
    .unwrap();
    let old = reread(result.files(), &[0, 1, 2]);
    let whole = [&old[0], &old[1], &old[2]];
    let add = |seed: u64, password: &Password, behind: Option<&Password>| {
        let fresh = photo(800, 600, seed);
        let addition = Addition {
            photos: &whole,
            photo: &fresh,
            password,
            behind,
            place: Place::Next,
        };
        extend(&addition, &Settings::default(), &mut TestRandom(seed))
    };
    // Both passwords: the new photo carries its part of the decoy and of the secret.
    let both = add(88, &decoy_key, Some(&secret_key)).unwrap();
    assert_eq!(both.report().set.number, 4);
    assert_eq!(both.report().behind.map(|place| place.number), Some(4));
    let both = Cover::new(both.into_file()).unwrap();
    let pair = reread_pair(&both, &old[1]);
    assert!(
        read_text(&pair, &decoy_key)
            .unwrap()
            .starts_with("an ordinary note")
    );
    assert_eq!(
        read_text(&pair, &secret_key).as_deref(),
        Some("the secret behind")
    );
    // The decoy's password alone: the decoy grows, the secret stays in the photos that had it.
    let alone = add(89, &decoy_key, None).unwrap();
    assert_eq!(alone.report().behind, None);
    let alone = Cover::new(alone.into_file()).unwrap();
    let pair = reread_pair(&alone, &old[2]);
    assert!(
        read_text(&pair, &decoy_key)
            .unwrap()
            .starts_with("an ordinary note")
    );
    assert!(matches!(
        reveal(&[&alone, &old[2]], &secret_key).unwrap(),
        Reading::Incomplete {
            found: 1,
            needed: 2
        }
    ));
    // The secret's password cannot write a photo by itself, and a password that opens nothing
    // behind the decoy is no second password.
    assert_eq!(
        add(90, &secret_key, None).unwrap_err(),
        StegoError::Set(SetError::DecoyPassword)
    );
    let stranger = password("another public password");
    assert_eq!(
        add(91, &decoy_key, Some(&stranger)).unwrap_err(),
        StegoError::Set(SetError::NothingBehind)
    );
    assert_eq!(
        add(92, &decoy_key, Some(&decoy_key)).unwrap_err(),
        StegoError::Set(SetError::NothingBehind)
    );
}
