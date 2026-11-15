//! Record passwords: NFKD-normalized UTF-8 in a wiped owner (CORE-24).

use crate::StegoError;
use crate::keys::WorkFactor;
use crate::protect::Secret;
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Fewest normalized bytes a password may have. Every guess costs one Argon2id run, but a short
/// password is still found by trying common ones.
pub const PASSWORD_MIN: usize = 12;
/// Most normalized bytes a password may have.
pub const PASSWORD_MAX: usize = 1024;

/// A password after Unicode NFKD. Spaces and case stay significant; nothing is trimmed.
pub struct Password {
    bytes: Secret,
    work: WorkFactor,
}

impl Password {
    /// Normalizes `text` (NFKD). Fails for a control character, or for a length outside
    /// [`PASSWORD_MIN`]..=[`PASSWORD_MAX`] bytes.
    pub fn new(text: &str) -> Result<Self, StegoError> {
        if text.len() > PASSWORD_MAX * 4 {
            return Err(StegoError::PasswordLong);
        }
        if text
            .chars()
            .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
        {
            return Err(StegoError::PasswordCharacter);
        }
        // Counted first, then written straight into its pages. The normalizer's own buffer of
        // characters it is still composing is not covered (docs/TECHNICAL.md, Protection).
        let length: usize = text.nfkd().map(char::len_utf8).sum();
        if length < PASSWORD_MIN {
            return Err(StegoError::PasswordShort);
        }
        if length > PASSWORD_MAX {
            return Err(StegoError::PasswordLong);
        }
        let mut locked = Secret::with_capacity(length);
        crate::plain::note(locked.is_locked());
        let mut buffer = Zeroizing::new([0; 4]);
        for c in text.nfkd() {
            locked.push(c.encode_utf8(&mut *buffer).as_bytes())?;
        }
        Ok(Self {
            bytes: locked,
            work: WorkFactor::default(),
        })
    }

    /// Whether both passwords have the same normalized bytes.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        crate::plain::same(self.bytes(), other.bytes())
    }

    /// Whether its pages are locked.
    pub(crate) fn is_locked(&self) -> bool {
        self.bytes.is_locked()
    }

    /// The same password with another PIM and memory level; reading needs the same ones.
    #[must_use]
    pub const fn with_work(mut self, work: WorkFactor) -> Self {
        self.work = work;
        self
    }

    /// The PIM and memory level.
    #[must_use]
    pub const fn work(&self) -> WorkFactor {
        self.work
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composed_and_decomposed_spellings_are_the_same_password() {
        let composed = Password::new("caf\u{e9} password 1").unwrap();
        let decomposed = Password::new("cafe\u{301} password 1").unwrap();
        assert!(composed.same_as(&decomposed));
    }

    /// The bytes of the Unicode standard's own decompositions: U+00E9 is e and U+0301, the
    /// ligature U+FB01 is f and i, and U+2460, the circled one, is 1.
    #[test]
    fn a_password_is_the_bytes_of_its_compatibility_decomposition() {
        let password = Password::new("caf\u{e9} \u{fb01}nance \u{2460}").unwrap();
        assert_eq!(password.bytes(), b"cafe\xCC\x81 finance 1");
        // Twelve bytes are counted after the decomposition, not before it.
        assert_eq!(
            Password::new("\u{fb01}\u{fb01}\u{fb01}\u{fb01}\u{fb01}").unwrap_err(),
            StegoError::PasswordShort
        );
        assert!(Password::new("\u{fb01}\u{fb01}\u{fb01}\u{fb01}\u{fb01}\u{fb01}").is_ok());
    }

    #[test]
    fn short_and_control_passwords_are_refused() {
        assert_eq!(
            Password::new("short").unwrap_err(),
            StegoError::PasswordShort
        );
        assert_eq!(
            Password::new("twelve bytes\n!").unwrap_err(),
            StegoError::PasswordCharacter
        );
    }

    #[test]
    fn debug_never_shows_the_password() {
        let password = Password::new("a secret password").unwrap();
        assert_eq!(format!("{password:?}"), "Password(redacted)");
    }
}
