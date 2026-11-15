# Third-party notices

Runtime dependencies, pinned exactly in `Cargo.toml`:

| Crate                  | Why                                                                                                                        | License           |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| argon2                 | Password stretching (Argon2id, RFC 9106)                                                                                   | MIT OR Apache-2.0 |
| chacha20               | Keyed order of the sites; the share generator, wiped when dropped                                                          | MIT OR Apache-2.0 |
| chacha20poly1305       | Record and threshold-set encryption                                                                                        | MIT OR Apache-2.0 |
| hkdf, sha2             | Key separation and hashes                                                                                                  | MIT OR Apache-2.0 |
| vsss-rs                | Shamir's sharing of the key of a k-of-n set over GF(256), constant time, wiped                                             | Apache-2.0 OR MIT |
| unicode-normalization  | NFKD of passwords                                                                                                          | MIT OR Apache-2.0 |
| zeroize                | Wiping secrets                                                                                                             | MIT OR Apache-2.0 |
| secret-protection-core | Pages for secrets and the isolation of the process; the workspace's own crate, which brings libc, windows-sys and landlock | MIT OR Apache-2.0 |

Development dependencies: jpeg-encoder (synthetic test photos), (MIT OR Apache-2.0) AND IJG; reed-solomon-erasure (an independent Reed–Solomon implementation whose parity the shard tests expect), MIT. The Reed–Solomon codec itself is this crate's own.

Published algorithms implemented from their papers: J-UNIWARD (Holub, Fridrich, Denemark 2014), J-MiPOD (Cogranne, Giboulot, Bas 2021), J-CRFW (Pan et al. 2024), UERD (Guo et al. 2015), syndrome-trellis codes (Filler, Judas, Fridrich 2011), wet-paper codes (Fridrich, Goljan, Soukal 2004).
