# Changelog

## Unreleased

First draft of the core; the record format is not frozen.

- Baseline JPEG at the coefficient level: decoded and re-encoded with the photo's own tables; a photo is admitted only when it re-encodes to its exact bytes. No size limit; a memory estimate per photo.
- Standard mode (ternary syndrome-trellis code) and decoy mode (binary code for the decoy, the secret in the directions of its changes through a wet-paper code); a decoy written alone looks the same as one with a secret behind it.
- Cost models J-UNIWARD, J-MiPOD, J-CRFW and UERD; site rules frozen1, grow1 and keep2; a reader tries every rule and record size.
- Sets of photos: split over every photo, or any k of n photos (Krawczyk: XChaCha20-Poly1305, Reed–Solomon shards from the `reed-solomon-core` crate, Shamir shares through vsss-rs, their coefficients from a ChaCha20 generator that wipes itself). A k-of-n set is known by its set number, not by how many photos were issued, and `extend` gives it a further photo, in place of a lost one or under a new number, from any k photos and without touching the others. The same file twice counts once and is refused for writing and for the room. A set's payloads are checked before any piece is used (each key share under its photo's number, one nonce and length across the set); conflicts are reported; several sets under one password are judged apart, and a record in a form this version does not read is reported as such, never as nothing.
- Passwords: Argon2id with a PIM and a memory level from 128 MiB to 3 TiB; keys per layer and rule with HKDF-SHA-256; records in XChaCha20-Poly1305 with padded sizes.
- Protection from the workspace's shared crate `secret-protection-core`, re-exported as `protect`: secrets, keys and plaintext on its way in locked or secret memory between guard pages, the Argon2id work area in pages of its own, all wiped; ciphertext and Reed–Solomon shards in the allocator's memory, which leaves the lock limit to the secrets; each job's report says whether its memory stayed locked (`Locking`); an isolated worker process or the isolation of the host's process, with a strict mode.
- Every new set is read back with each password and each message's SHA-256 compared before it is returned.
- Room per message (recommended and maximum, the limiting photo, how many photos may be lost) and an inspection of any file for a details window.
- Startup and full self-tests against published known answers and independent implementations: libjpeg's reading of the sample photo, Shamir shares computed by hand, Argon2id through the key path's own memory; the trellis reading is frozen at this format.
