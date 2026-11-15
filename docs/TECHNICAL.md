# How stego-core works

This document explains each step from a photo and a password to a written file, and back. The [README](../README.md) is the short version.

## Contents

- [JPEG at the level of coefficients](#jpeg-at-the-level-of-coefficients)
- [Sites: which coefficients may change](#sites-which-coefficients-may-change)
- [Cost models](#cost-models)
- [The coders](#the-coders)
- [Implementation notes](#implementation-notes)
- [Records and keys](#records-and-keys)
- [The decoy mode](#the-decoy-mode)
- [Several photos](#several-photos)
- [Room](#room)
- [Protection](#protection)
- [References](#references)

## JPEG at the level of coefficients

A JPEG photo stores, for every 8×8 block of pixels, 64 quantized DCT coefficients, compressed with Huffman codes. stego-core decodes every scan into these integers, changes some luminance AC coefficients by ±1, and encodes the scan again with the photo's own Huffman tables. Every byte outside the scan stays as it was: metadata, tables, comments.

A photo is admitted only when encoding its unchanged coefficients gives back its exact bytes. Otherwise a rewritten file would differ in ways that show, such as padding bits. Baseline and extended sequential JPEG with 8-bit samples are supported, with any chroma subsampling, restart markers and several sequential scans. Progressive JPEG and files with bytes after the end of the image are refused for now.

## Sites: which coefficients may change

A site is a coefficient that carries the record. Only luminance AC coefficients of blocks wholly inside the image are sites; DC and chroma never change. Three rules exist, and each keeps zeros at zero and non-zeros away from zero, so that the reader finds the same sites in the written photo:

| Rule      | Sites                         | Allowed changes                                        |
| --------- | ----------------------------- | ------------------------------------------------------ |
| `frozen1` | non-zero coefficients         | magnitude 2 or more moves both ways; ones never change |
| `grow1`   | non-zero coefficients         | a 1 may only grow to 2; larger ones move both ways     |
| `keep2`   | coefficients of magnitude ≥ 2 | a 2 may only grow; larger ones move both ways          |

A change keeps the coefficient's place in the run of zeros, but may change its size category. When the photo's Huffman table has no code for the new symbol, that direction is forbidden, so the file keeps its tables.

The reader does not know the rule and tries each one.

## Cost models

A cost model gives every site the price of changing it: low where a change hides in texture or noise, high in flat areas. The coder then finds the changes of least total price.

- **J-UNIWARD** (Holub, Fridrich, Denemark 2014): the change of three directional wavelet residuals of the decoded image, relative to their size.
- **J-MiPOD** (Cogranne, Giboulot, Bas 2021): each coefficient as Gaussian noise with its own variance; prices minimize the statistical detectability (Fisher information) of the changes.
- **J-CRFW** (Pan et al. 2024): J-MiPOD with the correlation between the same frequency in neighbouring blocks.
- **UERD** (Guo et al. 2015): the quantization step over the block's energy and its neighbours'.

The model matters only to the writer; the reader never needs it, so the default can change without making older files unreadable.

## The coders

**Syndrome-trellis codes** (STC; Filler, Judas, Fridrich 2011) embed m message bits into n ≫ m sites so that a fixed sparse matrix H gives `H · x = m` for the sites' values x, and the Viterbi algorithm finds the cheapest changes that make it hold. Here H has height 10 and the message is cut into 128-bit segments. The reader only multiplies H by what it reads; it needs no cost.

- **Ternary STC** (standard mode): ±1 changes carry log2 3 bits of choice per site. Half of the record goes into the second bit of each value, half into the parity.
- **Binary STC** (decoy mode): the parity of each site carries the decoy. A change of parity may go up or down; that free choice is used next.

**Wet-paper code** (Fridrich, Goljan, Soukal 2004): the secret behind a decoy is the keyed syndrome of the second bit of |q| over every site. Only the decoy's two-way changes may set it ("dry" sites); all others are "wet". The writer solves the linear system over GF(2) for the dry sites, choosing every free variable from the host's random source, so the directions look like coins. It is the double-layered ±1 scheme of Zhang, Zhang and Wang (2007) under a separate key.

## Implementation notes

What the code comments leave out, for whoever maintains the cost models and coders.

- **J-MiPOD.** The printed TIFS formulas have typos; the code uses: eq. 24 `P⊥ = I − H(HᵀH)⁻¹Hᵀ`; the covariance of a forward DCT matrix `D` is `D Σ Dᵀ`; eqs. 50–53 with the orthonormal JPEG DCT-II; eq. 29 `f(β) = β / log₂(1/β − 2)` (printed as `x·log₂(x − 2)`). The multiplier is found by Newton's method on `ln λ` (with a bisection fallback) over a Hermite table of the ternary entropy, then exact passes hold the payload to `1e-9` relative. A first global pass estimates the Wiener noise even when only some coefficients are selected.
- **J-CRF statistics.** Window `p = 5`, so 19 degrees of freedom; the six fitted basis functions are the 5-point DCT-II vectors with `a + b ≤ 2`. Pixel variance is the residual energy over 19, a pixel's noise is the residual at the window centre, and the block correlation is Pearson's over the 64 noises of two blocks (eq. 32). Coefficient variance is `Σ D[u,x]² ζ²ₓ / Δᵤ²` (eq. 31), floored at `1e-10`, with no smoothing across blocks.
- **J-CRFW.** Energy per coefficient `β²/σ⁴` and per edge `[βᵢ²/σᵢ⁴ + βⱼ²/σⱼ⁴ + 2ϱ²βᵢβⱼ/(σᵢ²σⱼ²)] / (1 − ϱ²)²`; the optimality condition `βᵢ·FIᵢ = λ·log₂(1/βᵢ − 2)` couples neighbours through `βⱼ/βᵢ`. The solver starts with ratio 1 (0 for a neighbour that cannot change) and updates until the `β` map moves by less than `1e-6` of its total, usually about a dozen times and at most 60 (the paper suggests three); only the last update is exact. Costs are `ρ = ln(1/β − 2)` (eq. 30). Choices the paper leaves open: pixels decoded without rounding or +128, edges only between blocks inside the image, `β = 0` for a neighbour that is not selected or is wet. An exact coordinate solver changed photos' maps by at most `5e-6` at 2–30 times the time, so it is not used.
- **J-CRFW weights.** Block weight is the sum of S-UNIWARD costs (`σ = 1`) of its 64 pixels, with convolution residuals and half-sample symmetric reflection, as the reference code and conseal (checked to `1e-9`). Mode weight is 5 for the last `n` zigzag modes: `n = 16` at quality 75 and 3 at quality 95, interpolated linearly in the IJG quality estimated from the table and clamped to `0..=16`.
- **J-UNIWARD.** `σ = 2⁻⁶`; residuals per 512-pixel tile with a 16-pixel mirrored halo; pixels decompressed without rounding or clipping.
- **UERD.** The DC step is replaced by `(q₀₁ + q₁₀)/2`; outside the image the edge blocks are repeated. Equal to conseal 2026.11 (`compute_cost_adjusted`) on four public photos, edge blocks and DC included.
- **Syndrome-trellis codes.** `m` message bits share `n` columns as evenly as possible (bit `k` owns columns `⌊kn/m⌋` to `⌊(k+1)n/m⌋ − 1`); the trellis restarts every `segment` bits, and `usize::MAX` gives one trellis over the whole cover.
- **Wet-paper layer.** Column `j` of `H` comes from the hidden key and the site's position alone; free variables come from a keyed stream. The layer on the decoy's directions is the double-layered ±1 scheme of Zhang, Zhang and Wang (IEEE SPL 14(11), 2007) under a separate key.
- **Reed–Solomon shards.** Parity row `i` is row `i` of the Vandermonde matrix `V[r][c] = rᶜ` times the inverse of its top `k` rows, in GF(2⁸) with polynomial 0x11D.

## Records and keys

**Password stretch.** Argon2id (RFC 9106) with one lane turns the password into a 32-byte root key. The salt is a hash of the parts of the photo no rule changes (frame header, quantization tables, luminance DC, chroma), so a guess made for one photo is worthless for another. Memory and passes come from the password's work factor:

- passes `t = 3 × (PIM + 1)`, PIM from 0 to 1,023;
- memory `m = (2 + MEM mod 2) × 2^(16 + ⌊MEM / 2⌋)` KiB, MEM from 0 to 29: 128, 192, 256, 384, 512, 768 MiB, 1 GiB, … 3 TiB.

Every memory level:

| Level | Memory  | Level | Memory  |
| ----- | ------- | ----- | ------- |
| 0     | 128 MiB | 15    | 24 GiB  |
| 1     | 192 MiB | 16    | 32 GiB  |
| 2     | 256 MiB | 17    | 48 GiB  |
| 3     | 384 MiB | 18    | 64 GiB  |
| 4     | 512 MiB | 19    | 96 GiB  |
| 5     | 768 MiB | 20    | 128 GiB |
| 6     | 1 GiB   | 21    | 192 GiB |
| 7     | 1.5 GiB | 22    | 256 GiB |
| 8     | 2 GiB   | 23    | 384 GiB |
| 9     | 3 GiB   | 24    | 512 GiB |
| 10    | 4 GiB   | 25    | 768 GiB |
| 11    | 6 GiB   | 26    | 1 TiB   |
| 12    | 8 GiB   | 27    | 1.5 TiB |
| 13    | 12 GiB  | 28    | 2 TiB   |
| 14    | 16 GiB  | 29    | 3 TiB   |

Some PIMs (any whole number from 0 to 1,023 is allowed):

| PIM   | Passes |
| ----- | ------ |
| 0     | 3      |
| 1     | 6      |
| 9     | 30     |
| 99    | 300    |
| 1,023 | 3,072  |

Time grows with both: twice the memory or twice the passes takes about twice as long.

Neither number is stored; the reader enters them. Level 0 opens on phones and in browsers; a browser cannot go past about 2 GiB (level 8).

**Key separation.** HKDF-SHA-256 derives, for each layer and site rule, the key of the site order, the seed of the coder's matrix and the record cipher's key.

**Site order.** The sites are visited in a keyed Fisher–Yates order from ChaCha20, so that changes spread over the whole photo.

**Record.** XChaCha20-Poly1305 encrypts the body: a length, the message part and random padding up to one of the sizes 64, 80, 96, 112, 128, 160 bytes and so on, four steps per doubling. The number of changes then tells only the size class. The associated data binds the record to its photo, layer, rule and size. The record is a random nonce, the encrypted body and the tag.

**Reading.** Nothing in a photo names the layer, rule or size. The reader tries each combination; only the right one passes the tag. A photo without a record gives the same answer as a wrong password.

**Format generations.** Every key label and every associated data begins with `stego-core 1`; the number is the generation of the format. A change that readers of this generation could not follow takes the next number, so its records never open under these keys and nothing has to be guessed from a byte of the body; a reader tries each generation it supports. Inside a generation, a record that opens but holds a part or a message this version does not know is reported as a form this version does not read. Drafts before the first release change without a new number and are not kept readable.

## The decoy mode

Whoever is forced to reveal a password gives the decoy's. The decoy is padded to the photo's recommended room, whatever the secret behind it, and the decoy mode also writes a lone message whose change directions are plain coins. The decoy password therefore sees the same record either way: its size and layer say nothing about a secret.

The secret behind a decoy is small: about 5 % of the decoy's bits, at most 8,192 bits per photo, because the wet-paper solve grows with the cube of its size.

## Several photos

### All photos needed

A large message is cut into slices in proportion to each photo's room, so every photo carries the same rate. Each slice is stored with the set's random identifier, its number and the count. Reading puts them in order by number, whatever the files are called or the order they are given in. Every photo is needed.

### Any k of n photos

Four ideas are combined:

- **Shamir's secret sharing** (1979). A secret is the constant term of a random polynomial of degree k − 1; each share is one point on it. Any k points determine the polynomial and the secret; k − 1 points leave every secret equally likely. Each share is as long as the secret. stego-core shares only a 32-byte key, over GF(256) with the constant-time vsss-rs.
- **Reed–Solomon codes** (1960). Data of k pieces is extended to n pieces, the values of a polynomial at n points over GF(2^8), so that any k pieces rebuild all of it. They are what CDs, QR codes and RAID 6 use against losses.
- **Rabin's information dispersal** (1989). Using such a code, a file is split into n pieces of size 1/k each, any k of which rebuild it. It saves space but does not hide anything: k − 1 pieces still show parts of the data.
- **Krawczyk's "secret sharing made short"** (1993) joins them. The message is encrypted once with a random key; the ciphertext is dispersed with Reed–Solomon into n pieces of about 1/k each; the key is split with Shamir. Any k photos give k pieces and k key shares, enough to rebuild and open the ciphertext. Fewer than k photos give no key, so their pieces are ciphertext only. The space is close to Rabin's; the secrecy rests on the cipher.

The Reed–Solomon codec is stego-core's own: GF(2^8) with the polynomial x^8 + x^4 + x^3 + x^2 + 1, and the systematic matrix made from the Vandermonde matrix V[r][c] = r^c times the inverse of its top k rows. That is the construction of Backblaze's and klauspost's codes and of the `reed-solomon-erasure` crate, and the tests check that the pieces agree with that crate byte for byte for every shape up to 16 photos (four one-byte pieces 01 02 03 04 give the parity 45 5E). Row i depends only on i and k, so one lost piece can be made again from any k others, and a set can grow later without touching its pieces.

Reading checks a set strictly. The same file given twice counts once. In a k-of-n set every photo's payload is held to what this version writes before any piece is used: a threshold from 2 to 16, a key share that carries the photo's own number, one nonce and one ciphertext length across the set, and a piece of exactly the length that ciphertext gives. Two different pieces under one number, payloads that disagree, more than k pieces that do not belong to one code word, and enough pieces that do not open together are reported as a conflict instead of being chosen between; too few pieces are reported with how many were found and how many are needed. A message is taken as genuine only because its tag opens under the key the shares give: with exactly k pieces nothing else can check them. A record that opens under the password but is not in a form this version writes is reported as a form it does not read, never as nothing; the tag says the record is whole, not who wrote it.

The photos may hold several sets under one password. Each set is judged on its own, so a set in conflict never hides a whole one. One set is answered for: a whole message if any set gives one, taking the set with the most photos and, among equals, the one whose first photo was given first; otherwise the state of the set with the most photos. The report names the photos of the set that was read and counts what else the password opened.

Writing refuses the same photo twice, since two records in copies of one photo would show their changes when the copies are compared; the room refuses it the same way.

**A further photo.** A set of which any k photos are enough can be given another photo later: one that takes the number of a lost photo, or one more under a new number (`extend`). The photos at hand must open, as one set and no other, to a whole message. The new photo's piece of the ciphertext is made from any k pieces, and its key share is the same polynomials at the new photo's point, worked out from any k shares by Lagrange's formula with the sharing library's field arithmetic; every further share at hand is checked against those k. The ciphertext, its nonce and its key do not change and the photos already written are not touched. The part of a number therefore depends on the set alone: a photo made twice for one number, at different times and from different photos, holds the same part, and the two count as one photo, not as two that may be lost. A new number comes after the largest count any photo at hand declares, every copy of a part counted and in whatever order the photos are given; photos added elsewhere from an older copy are not known to them, so a person who extends a set in two places should name the numbers. No record of the numbers issued exists outside the photos: the report says whether a photo with the new number was at hand and the highest count declared, and claims nothing about a number that was not at hand. With a decoy, the decoy's password writes the new photo and the secret's password, given as well, puts the secret's part behind it; without it the new photo carries the decoy alone and the secret stays in the photos that had it. The second password is tried on the photos of the decoy's own set and on no other, every copy of a part included, so a secret that sits in other photos is never tied to this decoy. Before the new photo is returned it is read back together with k − 1 of the old ones, which cannot open without it. A set that needs every photo cannot grow.

Every photo carries one piece, one key share and the set's identifier, inside its own password-encrypted record. Sets have up to 16 photos; the pieces are of equal size, so the smallest photo bounds the room.

## Room

The recommended room is the largest message at 0.05 bits per non-zero AC coefficient, a provisional rate until the detectability measurements set it; the maximum is the coder's limit of 0.5 bits per site. `fit` answers, for the photos and messages chosen, how many bytes are left or missing at both limits, by the same rules writing uses.

## Protection

- **Where it comes from.** The pages and the isolation are the workspace's shared crate `secret-protection-core`, re-exported as `stego_core::protect`; its own documentation says what each system applies and what it does not cover.
- **Memory.** Every password, message and key lives in a `Secret`: whole pages of its own, between guard pages. On Linux they are secret memory (`memfd_secret`), which no process reads through `/proc` or `ptrace`, never swapped or dumped, and which blocks hibernation. Elsewhere they are locked pages advised out of core dumps. All are wiped when dropped. Argon2id's work area is pages of its own as well, wiped after each stretch.
- **Isolation**, for the host program: the secret work in a `Worker`, a process of its own that isolates itself before it gets anything and reports what holds, with every option of `Options` turned on; or `Isolation::enter` in a process that does only that work. It refuses core dumps, memory reading by other programs, new sockets, file writes, the kernel's objects that other programs could read and signals to them, and limits the processor's speculation, by what each system offers. Each protection is read back and reported, never assumed, and `Isolation::enter_requiring` or `Worker::start` stops before a secret when a required one is missing.
- **What the memory protection does not reach.** The parts of a message between the cipher and the coder, and the key of a k-of-n set with its shares, are ordinary heap buffers, wiped after use but not on locked pages. The libraries keep working values of their own that this crate cannot wipe; the sharing library leaves the polynomial of the last byte it shared in freed memory, so a public zero byte is shared after the key and that leftover says nothing.

## References

- J. Fridrich, M. Goljan, D. Soukal, "Perturbed quantization steganography with wet paper codes", ACM MM&Sec 2004.
- T. Filler, J. Judas, J. Fridrich, "Minimizing additive distortion in steganography using syndrome-trellis codes", IEEE TIFS 6(3), 2011.
- V. Holub, J. Fridrich, T. Denemark, "Universal distortion function for steganography in an arbitrary domain", EURASIP JIS 2014.
- L. Guo et al., "Using statistical image model for JPEG steganography: uniform embedding revisited", IEEE TIFS 10(12), 2015.
- R. Cogranne, Q. Giboulot, P. Bas, "Efficient steganography in JPEG images by minimizing performance of optimal detector", IEEE TIFS 2021.
- W. Pan et al., "Efficient JPEG image steganography using pairwise conditional random field model", Signal Processing 221, 2024.
- W. Zhang, X. Zhang, S. Wang, "A double layered 'plus-minus one' data embedding scheme", IEEE SPL 14(11), 2007.
- A. Shamir, "How to share a secret", CACM 22(11), 1979.
- I. S. Reed, G. Solomon, "Polynomial codes over certain finite fields", J. SIAM 8(2), 1960.
- M. O. Rabin, "Efficient dispersal of information for security, load balancing, and fault tolerance", J. ACM 36(2), 1989.
- H. Krawczyk, "Secret sharing made short", CRYPTO 1993.
- RFC 9106, Argon2; RFC 5869, HKDF.
