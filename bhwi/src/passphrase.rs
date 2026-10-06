//! Normalized BIP-39 passphrases for host-side entry.
//!
//! Trezor defaults to on-device passphrase entry; KeepKey defaults to host entry.

/// A BIP-39 passphrase normalized for host-side entry.
///
/// The stored string uses NFKD normalization, is redacted in `Debug` output, and is
/// zeroized on drop. Trezor and KeepKey host entry accept at most 50 normalized UTF-8
/// bytes, not 50 characters; this type does not enforce that limit.
#[derive(Clone, Default, zeroize::Zeroize, zeroize_derive::ZeroizeOnDrop)]
pub struct HostPassphrase(String);

impl HostPassphrase {
    /// Creates a passphrase using the NFKD form required by BIP-39.
    pub fn new(passphrase: String) -> Self {
        use unicode_normalization::UnicodeNormalization;
        Self(passphrase.nfkd().collect())
    }

    /// Returns the normalized passphrase.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the length of the normalized UTF-8 encoding in bytes.
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl core::fmt::Debug for HostPassphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostPassphrase(<redacted>)")
    }
}
