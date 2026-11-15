# stego-core

> [!WARNING]
> **Draft, not ready for production.** stego-core is an early draft: the code, the API, the defaults and the record format will still change, files written now may not open in later versions, and no independent cryptographer has reviewed it. Do not rely on it for anything you cannot afford to lose, and keep the originals.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

stego-core hides a text or a file in ordinary JPEG photos, protected by a password. Only someone with the password finds the message; to everyone else the photo looks and opens as before. It is the core library of the StegoCode program and works offline: it opens no file, network connection or clock of its own.

The [documentation index](docs/README.md) lists the guides; [How it works](docs/TECHNICAL.md) explains every algorithm.

## Contents

- [What it does](#what-it-does)
- [Several photos](#several-photos)
- [Passwords](#passwords)
- [Protection while it runs](#protection-while-it-runs)
- [Limits](#limits)
- [Use from Rust](#use-from-rust)
- [License](#license)

## What it does

- **Standard mode.** One message per photo, written with ±1 changes of the photo's own JPEG coefficients. A syndrome-trellis code (STC) chooses the fewest and least visible changes.
- **Decoy mode.** A decoy message with its own password, and the real secret hidden in the directions of the decoy's changes (a wet-paper code). Whoever has only the decoy password sees the decoy and cannot tell whether a secret exists: a decoy written alone looks the same.
- **Cost models**, which decide where a change is least visible: J-UNIWARD (image texture), J-MiPOD (a statistical model of the noise), J-CRFW (J-MiPOD plus neighbouring blocks), UERD (block energy; fast and older).
- **Read-back check.** Before any file is returned, every new photo is read back with each password, and each message's SHA-256 must match.
- **Self-test.** `startup_self_test` checks every part against published known answers (SHA-256, HKDF, XChaCha20-Poly1305, Argon2id, Reed–Solomon) and round trips in milliseconds; a host runs it at every start and keeps its controls closed if a check fails. `full_self_test` adds the default password stretch and a whole hiding job.
- **Reports** with every technical detail of a job: mode, model, changes, rate, key derivation, cipher.

## Several photos

A message can be spread over up to 256 photos in two ways:

- **All photos needed.** A large message is cut into parts in proportion to each photo's room. Reading needs every photo, in any order: each part knows its place. No secret sharing is involved.
- **Any k of n photos.** The message is encrypted once with a random key. Its ciphertext is cut into n Reed–Solomon pieces, any k of which rebuild it (Rabin's information dispersal), so each photo carries about 1/k of it. The key is split with Shamir's secret sharing, so fewer than k photos say nothing about it. Together these form Krawczyk's "secret sharing made short". Up to 16 photos.

Both ways work in the decoy mode too, for the decoy and the secret alike.

A set of which any k photos are enough can be given another photo later, in place of a lost one or as one more, from any k of its photos; the others are not touched. A set that needs every photo cannot grow.

## Passwords

Each password is stretched with Argon2id. The person may raise two numbers: the **PIM**, from 0 to 1,023, multiplies the passes (3 × (PIM + 1)), and the **memory level**, from 0 to 29, chooses the memory: 128, 192, 256, 384, 512, 768 MiB, 1 GiB and so on, up to 3 TiB at level 29. Neither number is stored in the photo: whoever reads must enter the same ones. Level 0 with PIM 0 is the default, and phones and browsers can open it; a browser cannot go above about 2 GiB (level 8).

## Protection while it runs

Passwords, messages, their parts on the way to the photos and keys live in pages of their own, locked against swap or in Linux's secret memory, between guard pages, kept out of core dumps and wiped when dropped. Locking stops at the system's limit, 8 MiB by default on Linux; beyond it the pages are used unlocked, and the report of each job says whether everything stayed locked. The protection comes from the workspace's shared crate `secret-protection-core`, re-exported as `stego_core::protect`: a host program runs the secret work in an isolated worker process, or isolates its own process, and refuses to read a secret when a protection it requires is missing. See [How it works](docs/TECHNICAL.md#protection).

## Limits

- Baseline JPEG only for now. Progressive files and files with data after the image (extra images, depth maps) are refused.
- Large photos work at any size. A job needs about 0.5 GB of memory for a 12-megapixel photo and 1.8 GB for 48 megapixels; the program shows the figure for each photo and warns when the device has less free memory.
- Keep the written files byte for byte. Recompression, resizing, editing and most messengers destroy the records.
- Statistical undetectability is not established yet. The recommended room uses 0.05 bits per non-zero coefficient until the measurements set it.

## Use from Rust

```rust
use stego_core::{hide, reveal, Content, Cover, Password, Random, Reading, Secret, Settings, StegoError};

fn example(photo: Vec<u8>, random: &mut dyn Random) -> Result<(), StegoError> {
    let cover = Cover::new(photo)?;
    let secret = Content::text("abandon ability able")?;
    let key = Password::new("correct horse battery")?;
    let job = Secret { content: &secret, password: &key };
    let result = hide(&[&cover], &Settings::default(), job, None, random)?;
    let written = Cover::new(result.files()[0].clone())?;
    if let Reading::Complete(found) = reveal(&[&written], &key)? {
        assert_eq!(found.content().bytes(), secret.bytes());
    }
    Ok(())
}
```

The host supplies the photo bytes and a cryptographic random source, and saves the results.

## License

Either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option. The [third-party notices](THIRD_PARTY_NOTICES.md) list the dependencies.
