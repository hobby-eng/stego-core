//! What a record holds: a text or a file with its name, as exact bytes.

use crate::StegoError;
use crate::plain::{Plain, same};
use crate::protect::Secret;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

/// Longest file name, in UTF-8 bytes.
pub const FILE_NAME_MAX: usize = 255;
/// Bytes of the encoded form before the data: the kind and the name length.
pub(crate) const CONTENT_HEADER: usize = 2;

const KIND_TEXT: u8 = 1;
const KIND_FILE: u8 = 2;

/// Whether a record holds a text or a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// UTF-8 text typed or pasted by the person.
    Text,
    /// A file's bytes and its name without any folder.
    File,
}

/// A message to hide or a message read back. The bytes are exact: nothing is normalized.
pub struct Content {
    kind: Kind,
    /// A file's name can say as much as its contents: it lies in protected pages too.
    name: Secret,
    data: Secret,
}

impl Content {
    /// A text message.
    ///
    /// # Errors
    ///
    /// [`StegoError::MessageEmpty`] for an empty text.
    pub fn text(text: &str) -> Result<Self, StegoError> {
        Self::new(Kind::Text, "", text.as_bytes())
    }

    /// A file's bytes with its name. `name` is the bare file name, without any folder.
    ///
    /// # Errors
    ///
    /// [`StegoError::FileName`] for an unusable name, [`StegoError::MessageEmpty`] for no bytes.
    pub fn file(name: &str, mut bytes: Vec<u8>) -> Result<Self, StegoError> {
        let made = if usable_name(name) {
            Self::new(Kind::File, name, &bytes)
        } else {
            Err(StegoError::FileName)
        };
        // The caller's buffer is wiped once its bytes sit in the locked owner.
        bytes.zeroize();
        made
    }

    fn new(kind: Kind, name: &str, bytes: &[u8]) -> Result<Self, StegoError> {
        if bytes.is_empty() {
            return Err(StegoError::MessageEmpty);
        }
        let mut data = Secret::with_capacity(bytes.len());
        data.push(bytes)?;
        let mut held = Secret::with_capacity(name.len());
        held.push(name.as_bytes())?;
        crate::plain::note(data.is_locked() && held.is_locked());
        Ok(Self {
            kind,
            name: held,
            data,
        })
    }

    /// Text or file.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The file name; empty for a text.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str().unwrap_or_default()
    }

    /// The exact bytes: the UTF-8 text or the file's contents.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }

    /// The text of a text message; `None` for a file.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self.kind {
            Kind::Text => std::str::from_utf8(self.data.as_bytes()).ok(),
            Kind::File => None,
        }
    }

    /// SHA-256 of [`Content::bytes`], the value a person compares with `sha256sum` of the file.
    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.data.as_bytes()).into()
    }

    /// Length of the encoded form.
    pub(crate) fn encoded_len(&self) -> usize {
        CONTENT_HEADER + self.name.as_bytes().len() + self.data.as_bytes().len()
    }

    /// The encoded form: kind, name length, name, data.
    pub(crate) fn encode_into(&self, out: &mut [u8]) {
        out[0] = match self.kind {
            Kind::Text => KIND_TEXT,
            Kind::File => KIND_FILE,
        };
        // `usable_name` keeps names within one byte of length.
        out[1] = self.name.as_bytes().len() as u8;
        let name_end = CONTENT_HEADER + self.name.as_bytes().len();
        out[CONTENT_HEADER..name_end].copy_from_slice(self.name.as_bytes());
        out[name_end..name_end + self.data.as_bytes().len()].copy_from_slice(self.data.as_bytes());
    }

    /// The encoded form in a wiped buffer.
    pub(crate) fn encoded(&self) -> Plain {
        let mut out = Plain::zeros(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// Reads the encoded form back; `None` when it is not one this crate writes.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        let (&name_len, rest) = rest.split_first()?;
        let name_len = usize::from(name_len);
        let name = std::str::from_utf8(rest.get(..name_len)?).ok()?;
        let data = rest.get(name_len..)?;
        match kind {
            KIND_TEXT if name.is_empty() && std::str::from_utf8(data).is_ok() => {
                Self::new(Kind::Text, "", data).ok()
            }
            KIND_FILE if usable_name(name) => Self::new(Kind::File, name, data).ok(),
            _ => None,
        }
    }

    /// Whether both contents are the same kind, name and bytes.
    pub(crate) fn same_as(&self, other: &Self) -> bool {
        let name = same(self.name.as_bytes(), other.name.as_bytes());
        let data = same(self.data.as_bytes(), other.data.as_bytes());
        self.kind == other.kind && name && data
    }

    /// Whether its pages are locked.
    pub(crate) fn is_locked(&self) -> bool {
        self.data.is_locked() && self.name.is_locked()
    }
}

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Content({:?}, {} bytes, redacted)",
            self.kind,
            self.data.as_bytes().len()
        )
    }
}

fn usable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= FILE_NAME_MAX
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_survives_encoding_with_its_name() {
        let file = Content::file("seed.txt", b"abandon ability".to_vec()).unwrap();
        let mut out = vec![0; file.encoded_len()];
        file.encode_into(&mut out);
        assert_eq!(&out[..10], b"\x02\x08seed.txt");
        let back = Content::decode(&out).unwrap();
        assert!(back.same_as(&file));
        assert_eq!(back.name(), "seed.txt");
    }

    #[test]
    fn names_with_folders_and_empty_messages_are_refused() {
        assert_eq!(
            Content::file("a/b", vec![1]).unwrap_err(),
            StegoError::FileName
        );
        assert_eq!(
            Content::file("..", vec![1]).unwrap_err(),
            StegoError::FileName
        );
        assert_eq!(Content::text("").unwrap_err(), StegoError::MessageEmpty);
    }

    #[test]
    fn the_hash_is_the_plain_sha256_of_the_bytes() {
        // sha256("abc"), FIPS 180-2 appendix B.1.
        let text = Content::text("abc").unwrap();
        assert_eq!(text.sha256()[..4], [0xba, 0x78, 0x16, 0xbf]);
    }
}
