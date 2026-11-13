# Roadmap

What is planned, in rough order. Done items move to the [changelog](../CHANGELOG.md).

## Before any release

- **Startup self-test.** Done for SHA-256, HKDF, XChaCha20-Poly1305, Argon2id, Reed–Solomon, Shamir, the trellis and the JPEG codec, with a full self-test that adds the default stretch and a whole job; pinned against libjpeg, hand-built Shamir shares, the key path's own Argon2id memory and a frozen trellis reading. Left: known answers of the cost models from an independent implementation (conseal).
- **Large photos, faster.** Done: no size limit, a memory estimate per photo, reading in one pass per rule, the trellis path in checkpoints, per-site buffers freed early, the change rate solved in parallel (12 MP: 41 s, 0.46 GB; 48 MP: 125 s, 1.77 GB). Left: every site still passes the trellis's 1,024 states twice; a vectorized step and 32-bit positions would cut time and memory again.
- **Our own Reed–Solomon codec (ShardCode).** Done in `src/shard`: GF(2^8), parity equal to reed-solomon-erasure's, any piece made again, sets that grow, consistency checks, tests against that crate and every choice of pieces. Left, for a separate ShardCode crate: GF(2^16), an optional checksum and self-describing header per piece, error correction (Berlekamp–Massey) for data with unknown damaged bytes, fuzzing.
- **Sets of photos, checked strictly.** Done: duplicates count once and are refused for writing, conflicts are reported, k-of-n pieces must agree. The room names the photo that limits it and how many photos may be lost.
- **Shamir through vsss-rs.** Done: sskr, bc-rand, bc-crypto and the second copy of RustCrypto they brought are gone (133 crates in the lock file became 93).
- **Adding photos to a k-of-n set.** A set is already known without how many photos were issued, and any k photos make new Reed–Solomon pieces. Left: a new photo's Shamir share is the same polynomial at a new number, which any k shares fix (Lagrange at that number instead of zero); vsss-rs combines only at zero, so this needs its field arithmetic and a test against shares built by hand.
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
