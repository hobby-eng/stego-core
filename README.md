# stego-core

The core library of StegoCode: messages hidden in ordinary JPEG photos, protected by passwords.

Status: experimental. The record format may still change while the detectability measurements run; do not rely on it for anything you cannot afford to lose.

## What it does

- Hides a text or a file in one or several baseline JPEG photos and reads it back.
- Changes only quantized luminance AC coefficients by ±1 and rewrites the scan with the photo's own Huffman tables. Every other byte of the file stays as it was, and a photo whose unchanged coefficients do not re-encode to the same bytes is refused.
- Two modes (the decoy mode also takes a lone message, whose file looks the same as one with a secret behind it):
  - standard: one record, ternary syndrome-trellis code (STC);
  - with decoy: a decoy with its own password, and the secret carried by the directions of the decoy's changes (a keyed wet-paper code). With only the decoy password, nothing shows that a second record exists.
- Several photos: a message is split so that every photo is needed, or spread so that any `k` of `n` photos open it: each photo carries a Reed–Solomon shard of 1/k of the encrypted message and an SSKR (Shamir) share of its key. Both work in the decoy mode too, for the decoy and the secret alike.
- Every new set of files is read back with each password, and each message's SHA-256 is compared, before the files are returned.
- Cost models: J-UNIWARD, J-MiPOD, J-CRFW and UERD. Site rules: `frozen1`, `grow1`, `keep2`. The reader tries all of them, so changing the default never makes older files unreadable.
- Reports every technical detail of a job (mode, model, rule, sites, changes, rate in bits per non-zero AC coefficient, key derivation, cipher) for an advanced view.

## Security notes

- Passwords are stretched with Argon2id (128 MiB, 3 passes) salted with a hash of the photo's unchanged parts, then split into per-layer keys with HKDF-SHA-256. Records are encrypted with XChaCha20-Poly1305.
- Record sizes are padded to quarter-octave classes, so the number of changes shows only the size class.
- The coins that choose free change directions in the decoy mode come from the host's random source, never from a password.
- Statistical undetectability is not established yet. The detectability measurements will set the recommended rate; until then the recommended capacity uses 0.05 bits per non-zero AC coefficient.
- Keep the written files byte for byte: recompression, resizing, editing and most messengers destroy the records.

## Not supported yet

Progressive JPEG, files with data after the end of the image (MPF extra images, trailers), MP3 carriers.

## Use

```rust
use stego_core::{hide, reveal, Content, Cover, Password, Reading, Secret, Settings};

fn example(photo: Vec<u8>, random: &mut dyn stego_core::Random) -> Result<(), stego_core::StegoError> {
    let cover = Cover::new(photo)?;
    let secret = Content::text("abandon ability able")?;
    let key = Password::new("correct horse battery")?;
    let result = hide(&[&cover], &Settings::default(), Secret { content: &secret, password: &key }, None, random)?;
    let written = Cover::new(result.files()[0].clone())?;
    if let Reading::Complete(found) = reveal(&[&written], &key)? {
        assert_eq!(found.content().bytes(), secret.bytes());
    }
    Ok(())
}
```

The library opens no file, network connection, clock or thread; the host passes bytes and a cryptographic random source.

## License

MIT OR Apache-2.0, at your option.
