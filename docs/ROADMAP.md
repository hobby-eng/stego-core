# Roadmap

What is planned, in rough order. Done items move to the [changelog](../CHANGELOG.md).

## Before any release

- **Startup self-test.** Done for SHA-256, HKDF, XChaCha20-Poly1305, Argon2id, Reed–Solomon, Shamir, the trellis and the JPEG codec, with a full self-test that adds the default stretch and a whole job; pinned against libjpeg, hand-built Shamir shares, the key path's own Argon2id memory and a frozen trellis reading. Left: known answers of the cost models from an independent implementation (conseal).
- **Large photos, faster.** Done: no size limit, a memory estimate per photo, reading in one pass per rule, the trellis path in checkpoints, per-site buffers freed early, the change rate solved in parallel (12 MP: 41 s, 0.46 GB; 48 MP: 125 s, 1.77 GB). Left: every site still passes the trellis's 1,024 states twice; a vectorized step and 32-bit positions would cut time and memory again.
- **Our own Reed–Solomon codec (ShardCode).** Done in `src/shard`: GF(2^8), parity equal to reed-solomon-erasure's, any piece made again, sets that grow, consistency checks, tests against that crate and every choice of pieces. Left, for a separate ShardCode crate: GF(2^16), an optional checksum and self-describing header per piece, error correction (Berlekamp–Massey) for data with unknown damaged bytes, fuzzing.
- **Sets of photos, checked strictly.** Done: duplicates count once and are refused for writing and for the room; conflicts are reported; k-of-n payloads are checked before any piece is used, each key share under its photo's number; several sets under one password are judged apart; a record in a form this version does not read is reported as such. The room names the photo that limits it and how many photos may be lost. Left: property tests over random shapes and damage, and fuzzing of the parsers.
- **Shamir through vsss-rs.** Done: sskr, bc-rand, bc-crypto and the second copy of RustCrypto they brought are gone (133 crates in the lock file became 93).
- **Adding photos to a k-of-n set.** Done (`extend`): a photo in place of a lost one or under a new number, from any k photos, with the key share worked out at the new point and checked against shares computed by hand; only the messages whose passwords are given are extended. Left: the host's screens for it, which must show the same piece twice as one photo; a report of which numbers a person has issued when a set is extended in two places.
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
- The secret work in a separate isolated process (`secret_protection_core::Worker`) with every option of `secret_protection_core::Options` turned on (file locks, `sendmsg`, dynamic code, DLLs not signed by Microsoft), which reports its isolation before it gets any secret; the window process chooses and saves files, and gets back only what it shows or saves, never a password or a key.
- Passwords and secret text never held by the web view: the field sends each typed character at once, through the Rust side, to the worker, which collects them in protected memory; the web view keeps only their count, to draw dots, and sends a deletion as a command. Pasting goes the same way: the Rust side reads the clipboard and hands it to the worker, so that the web view never sees it. A small native dialog that alone asks for the password, as GnuPG's pinentry does, is a stricter mode for later. The terminal version reads the password in the worker itself.
- Screen capture blocked where the system allows it; no recent-files entries; no crash dumps.
- The same screens in the browser through the WebAssembly build of the core.
