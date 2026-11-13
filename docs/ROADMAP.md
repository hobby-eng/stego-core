# Roadmap

What is planned, in rough order. Done items move to the [changelog](../CHANGELOG.md).

## Before any release

- **Startup self-test.** Known answers of every part (Argon2id, XChaCha20-Poly1305, HKDF, SHA-256, Reed–Solomon, Shamir, the JPEG codec, the coders, each cost model) run before a host opens its controls; a failure keeps them closed. A slower full self-test runs on request.
- **Large photos.** No megapixel limit: a host warns when a job needs more memory than the device has. Cut the memory per site (the trellis keeps its whole path today: about 128 bytes per site) and the reading time (every rule and size is tried with a full pass).
- **Our own Reed–Solomon codec (ShardCode).** Safe scalar Rust, no dependencies, GF(2^8) and GF(2^16), parity compatible with the current format, and:
  - an optional checksum per piece, so a damaged piece is dropped and a working set is found among the rest;
  - recreating one lost piece from any k others;
  - adding pieces later (3 of 5 becomes 3 of 7) without touching the existing ones;
  - an optional self-describing header (version, field, k, n, number, length, set);
  - checking that a whole set is consistent;
  - error correction (Berlekamp–Massey) for data where the damaged bytes are unknown: printed, scanned or recognized text.
  - Tests: every combination of pieces for small n, comparison with independent implementations (reed-solomon-erasure, reed-solomon-engine, sia_reed_solomon), fuzzing, property tests, fixed known answers.
- **Sets of photos, checked strictly before and after.** 2 ≤ k < n ≤ 16; the same k, nonce and length in every piece; a file added twice (same SHA-256) counts once; two different pieces claiming one number are reported as a conflict; unreadable photos are skipped and a working set is found among the rest; the room shows which photo limits it and how many may be lost.
- **Shamir through vsss-rs** instead of sskr: constant-time, wiped, without the second copy of RustCrypto that sskr brings.
- **Protection.** A strict mode that checks the protections before a password is accepted; the password normalized straight into protected memory; secrets wiped as soon as they are used; a warning when swap is unencrypted; the decrypted parts of records in protected memory.
- **Supply chain.** `cargo vet` with the Google, Mozilla, Bytecode Alliance, ISRG and Zcash audit sets; own audits for the versions they do not cover.
- **Compatibility tests.** A public set written by an older version keeps opening, its parity used, after every change.

## Formats

- Progressive JPEG.
- Photos with data after the image: MPF extra images, depth maps, vendor trailers (most phone photos).
- MP3, as in the earlier MnemoCode module.

## Proofs

- Lean: Cauchy and Vandermonde-derived matrices are MDS (every k rows are invertible), so any k pieces rebuild a set.
- Lean: the wet-paper solution is uniform among all solutions, so the change directions look like coins.
- EasyCrypt: the decoy password learns nothing about a secret behind the decoy (the game in the specification draft).

## The program (StegoCode)

- Tauri 2 with Svelte and TypeScript, once the look is chosen.
- The secret work in a separate isolated process; the window process chooses and saves files.
- Passwords and secret text typed in a native dialog, never in the web view.
- Screen capture blocked where the system allows it; no recent-files entries; no crash dumps.
- The same screens in the browser through the WebAssembly build of the core.
