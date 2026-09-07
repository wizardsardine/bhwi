#[derive(Clone, Default, zeroize::Zeroize, zeroize_derive::ZeroizeOnDrop)]
pub struct HostPassphrase(String);

impl HostPassphrase {
    /// BIP-39 requires the passphrase in NFKD form.
    pub fn new(passphrase: String) -> Self {
        use unicode_normalization::UnicodeNormalization;
        Self(passphrase.nfkd().collect())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl core::fmt::Debug for HostPassphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostPassphrase(<redacted>)")
    }
}
