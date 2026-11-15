//! Plaintext and key material on their way between a caller's content and the encrypted records.
//! Every such run of bytes lies in protected pages, as the content and the keys themselves do.

use crate::protect::Secret;
use crate::report::Locking;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Buffers of secrets, and password stretches, that this process got unlocked pages for: beyond
/// the lock limit pages are given all the same, and can reach swap.
static UNLOCKED: AtomicUsize = AtomicUsize::new(0);
static STRETCHES_UNLOCKED: AtomicUsize = AtomicUsize::new(0);

/// Counts a buffer of secrets whose pages were not locked.
pub(crate) fn note(locked: bool) {
    if !locked {
        UNLOCKED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Counts a password stretch whose work area was not locked.
pub(crate) fn note_stretch(locked: bool) {
    if !locked {
        STRETCHES_UNLOCKED.fetch_add(1, Ordering::Relaxed);
    }
}

/// The counts when a job starts, to tell afterwards whether its memory stayed locked.
pub(crate) struct Watch(usize, usize);

impl Watch {
    pub(crate) fn start() -> Self {
        Self(
            UNLOCKED.load(Ordering::Relaxed),
            STRETCHES_UNLOCKED.load(Ordering::Relaxed),
        )
    }

    /// What stayed locked since the start; `owners` says whether the caller's own buffers are.
    pub(crate) fn locking(&self, owners: bool) -> Locking {
        Locking {
            secrets: owners && UNLOCKED.load(Ordering::Relaxed) == self.0,
            stretch: STRETCHES_UNLOCKED.load(Ordering::Relaxed) == self.1,
        }
    }
}

/// Whether `a` and `b` hold the same bytes, looking at every byte whichever differs.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    let differ = a.iter().zip(b).fold(0, |differ, (x, y)| differ | (x ^ y));
    a.len() == b.len() && std::hint::black_box(differ) == 0
}

/// Bytes of plaintext or of a key in pages of their own: locked where the system allows, out of
/// core dumps and child processes, wiped when dropped. Its `Debug` text hides them, and two are
/// compared without stopping at the first difference.
pub(crate) struct Plain(Secret);

impl Plain {
    /// `length` zero bytes, to be written in place.
    pub(crate) fn zeros(length: usize) -> Self {
        let secret = Secret::zeroed(length);
        note(secret.is_locked());
        Self(secret)
    }

    /// The bytes of `pieces`, one after another.
    pub(crate) fn gathered(pieces: &[&[u8]]) -> Self {
        let mut plain = Self::zeros(pieces.iter().map(|piece| piece.len()).sum());
        let mut rest = &mut *plain;
        for piece in pieces {
            let (front, after) = rest.split_at_mut(piece.len());
            front.copy_from_slice(piece);
            rest = after;
        }
        plain
    }

    /// The bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self
    }

    /// The bytes, to change in place.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }
}

impl Deref for Plain {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl DerefMut for Plain {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_bytes()
    }
}

impl fmt::Debug for Plain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plain({} bytes, hidden)", self.len())
    }
}

impl PartialEq for Plain {
    /// Every byte is looked at, whichever differs.
    fn eq(&self, other: &Self) -> bool {
        same(self, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pieces_are_gathered_in_their_order_and_hidden_in_debug_text() {
        let plain = Plain::gathered(&[b"ab", b"", b"cde"]);
        assert_eq!(&*plain, b"abcde");
        assert_eq!(format!("{plain:?}"), "Plain(5 bytes, hidden)");
        assert!(Plain::gathered(&[]).is_empty());
    }

    #[test]
    fn two_are_equal_only_with_the_same_bytes_and_length() {
        let plain = Plain::gathered(&[b"abc"]);
        assert!(plain == Plain::gathered(&[b"a", b"bc"]));
        assert!(plain != Plain::gathered(&[b"abd"]) && plain != Plain::gathered(&[b"ab"]));
    }

    #[test]
    fn a_job_sees_a_buffer_left_unlocked_while_it_ran() {
        let watch = Watch::start();
        assert!(!watch.locking(false).secrets);
        note(true);
        note_stretch(true);
        assert!(
            watch.locking(true)
                == Locking {
                    secrets: true,
                    stretch: true
                }
        );
        note(false);
        note_stretch(false);
        let locking = watch.locking(true);
        assert!(!locking.secrets && !locking.stretch);
    }

    #[test]
    fn its_bytes_lie_in_pages_kept_out_of_core_dumps() {
        let mut plain = Plain::zeros(64);
        plain[63] = 7;
        assert!(plain.0.is_out_of_dumps() || !cfg!(target_os = "linux"));
    }
}
