# stego-core

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

stego-core hides a text or a file in ordinary JPEG photos, protected by a password. Only someone with the password finds the message; to everyone else the photo looks and opens as before. It is the core library of the StegoCode program and works offline: it opens no file, network connection or clock of its own.

> [!WARNING]
> stego-core is experimental. The record format may change until the detectability measurements are done, and no independent cryptographer has reviewed it. Keep the original of anything you hide.

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
- **Reports** with every technical detail of a job: mode, model, changes, rate, key derivation, cipher.

## Several photos

A message can be spread over up to 256 photos in two ways:

- **All photos needed.** A large message is cut into parts in proportion to each photo's room. Reading needs every photo, in any order: each part knows its place. No secret sharing is involved.
- **Any k of n photos.** The message is encrypted once with a random key. Its ciphertext is cut into n Reed–Solomon pieces, any k of which rebuild it (Rabin's information dispersal), so each photo carries about 1/k of it. The key is split with Shamir's secret sharing (SSKR), so fewer than k photos say nothing about it. Together these form Krawczyk's "secret sharing made short". Up to 16 photos.

Both ways work in the decoy mode too, for the decoy and the secret alike.

## Passwords

Each password is stretched with Argon2id. As in MHFE, the person may raise two numbers: the **PIM** multiplies the passes (3 × (PIM + 1)), and the **memory level** chooses the memory from 128 MiB upward (128, 192, 256, 384, 512, 768 MiB, 1 GiB, and so on). Neither number is stored in the photo: whoever reads must enter the same ones. Level 0 with PIM 0 is the default, and phones and browsers can open it; a browser cannot go above about 2 GiB (level 8).

## Protection while it runs

The protection code is MHFE's. Passwords, messages and keys live in pages of their own, locked against swap or in Linux's secret memory, kept out of core dumps and wiped when dropped. A host program can isolate its process: no core dumps, no memory reading by other programs, no new network connections and no file writes. See [How it works](docs/TECHNICAL.md#protection).

## Limits

- Baseline JPEG only for now. Progressive files and files with data after the image (extra images, depth maps) are refused, and so are photos above about 65 megapixels.
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
