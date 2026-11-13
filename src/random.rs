//! The host's cryptographic random source (CORE-09, CORE-46).

use crate::StegoError;

/// Fills buffers with cryptographic randomness. A host passes the operating system's or the
/// browser's source; tests pass a deterministic one through the same trait.
pub trait Random {
    /// Fills `bytes` completely.
    ///
    /// # Errors
    ///
    /// [`StegoError::Random`] when the source fails.
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), StegoError>;
}

/// Draws one `u64` from `random`.
pub(crate) fn next_u64(random: &mut dyn Random) -> Result<u64, StegoError> {
    let mut bytes = [0; 8];
    random.fill(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
