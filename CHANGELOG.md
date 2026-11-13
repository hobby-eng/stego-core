# Changelog

## Unreleased

First draft of the core; the record format is not frozen.

- Baseline JPEG at the coefficient level: decoded and re-encoded with the photo's own tables; a photo is admitted only when it re-encodes to its exact bytes. No size limit; a memory estimate per photo.
- Standard mode (ternary syndrome-trellis code) and decoy mode (binary code for the decoy, the secret in the directions of its changes through a wet-paper code); a decoy written alone looks the same as one with a secret behind it.
- Cost models J-UNIWARD, J-MiPOD, J-CRFW and UERD; site rules frozen1, grow1 and keep2; a reader tries every rule and record size.
- Sets of photos: split over every photo, or any k of n photos (Krawczyk: XChaCha20-Poly1305, our own Reed–Solomon codec, Shamir shares through vsss-rs, their coefficients from a ChaCha20 generator that wipes itself). The same file twice counts once and is refused for writing; conflicts are reported.
- Passwords: Argon2id with a PIM and a memory level from 128 MiB to 3 TiB; keys per layer and rule with HKDF-SHA-256; records in XChaCha20-Poly1305 with padded sizes.
- Protection: secrets, keys and the Argon2id work area in locked or secret memory, wiped; process isolation for the host program.
- Every new set is read back with each password and each message's SHA-256 compared before it is returned.
- Room per message (recommended and maximum, the limiting photo, how many photos may be lost) and an inspection of any file for a details window.
- Startup and full self-tests against published known answers.
