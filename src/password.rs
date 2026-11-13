//! Record passwords: NFKD-normalized UTF-8 in a wiped owner (CORE-24).

use crate::StegoError;
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
    bytes: Zeroizing<Vec<u8>>,
}

impl Password {
    /// Normalizes `text`.
    ///
    /// # Errors
    ///
    /// [`StegoError::PasswordCharacter`] for a control character, [`StegoError::PasswordShort`]
    /// and [`StegoError::PasswordLong`] outside [`PASSWORD_MIN`]..=[`PASSWORD_MAX`] bytes.
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
        let mut bytes = Zeroizing::new(Vec::with_capacity(text.len() * 2));
        let mut buffer = [0; 4];
        for c in text.nfkd() {
            bytes.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
        }
        if bytes.len() < PASSWORD_MIN {
            return Err(StegoError::PasswordShort);
        }
        if bytes.len() > PASSWORD_MAX {
            return Err(StegoError::PasswordLong);
        }
        Ok(Self { bytes })
    }

    /// Whether both passwords have the same normalized bytes.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.bytes.len() == other.bytes.len()
            && self
                .bytes
                .iter()
                .zip(other.bytes.iter())
                .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
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
