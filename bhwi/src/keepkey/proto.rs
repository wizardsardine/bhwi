//! Handwritten KeepKey-specific protobuf messages.
//!
//! Optional fields are absent when not supplied or reported; `None` is not
//! equivalent to an explicit false or zero value.
//!
// KeepKey-specific protobuf messages.
// Source: keepkey/device-protocol @ 323802f17dd44165a5100357df771348c8b49672.
// Encoded with prost 0.13.5. Unknown fields are intentionally omitted.
#![allow(dead_code)]

/// Device identity and wallet features reported by KeepKey.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Features {
    /// Vendor identifier string.
    #[prost(string, optional, tag = "1")]
    pub vendor: Option<String>,
    /// Major firmware version.
    #[prost(uint32, optional, tag = "2")]
    pub major_version: Option<u32>,
    /// Minor firmware version.
    #[prost(uint32, optional, tag = "3")]
    pub minor_version: Option<u32>,
    /// Firmware patch version.
    #[prost(uint32, optional, tag = "4")]
    pub patch_version: Option<u32>,
    /// Whether PIN protection is enabled.
    #[prost(bool, optional, tag = "7")]
    pub pin_protection: Option<bool>,
    /// Whether passphrase protection is enabled.
    #[prost(bool, optional, tag = "8")]
    pub passphrase_protection: Option<bool>,
    /// User-visible device label.
    #[prost(string, optional, tag = "10")]
    pub label: Option<String>,
    /// Whether a wallet has been initialized.
    #[prost(bool, optional, tag = "12")]
    pub initialized: Option<bool>,
    /// Whether the PIN is cached for the current session.
    #[prost(bool, optional, tag = "16")]
    pub pin_cached: Option<bool>,
    /// Device model string.
    #[prost(string, optional, tag = "21")]
    pub model: Option<String>,
    /// Firmware variant string.
    #[prost(string, optional, tag = "22")]
    pub firmware_variant: Option<String>,
}

/// Parameters for initializing a new KeepKey wallet.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ResetDevice {
    /// Whether to display device-generated randomness.
    #[prost(bool, optional, tag = "1")]
    pub display_random: Option<bool>,
    /// Entropy strength in bits.
    #[prost(uint32, optional, tag = "2")]
    pub strength: Option<u32>,
    /// Whether to enable passphrase protection.
    #[prost(bool, optional, tag = "3")]
    pub passphrase_protection: Option<bool>,
    /// Whether to enable PIN protection.
    #[prost(bool, optional, tag = "4")]
    pub pin_protection: Option<bool>,
    /// Mnemonic language.
    #[prost(string, optional, tag = "5")]
    pub language: Option<String>,
    /// User-visible device label.
    #[prost(string, optional, tag = "6")]
    pub label: Option<String>,
    /// Whether to omit the backup flow.
    #[prost(bool, optional, tag = "7")]
    pub no_backup: Option<bool>,
    /// Auto-lock delay in milliseconds.
    #[prost(uint32, optional, tag = "8")]
    pub auto_lock_delay_ms: Option<u32>,
    /// Initial U2F counter.
    #[prost(uint32, optional, tag = "9")]
    pub u2f_counter: Option<u32>,
}

/// Parameters for KeepKey mnemonic recovery.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RecoveryDevice {
    /// Number of mnemonic words.
    #[prost(uint32, optional, tag = "1")]
    pub word_count: Option<u32>,
    /// Whether to enable passphrase protection.
    #[prost(bool, optional, tag = "2")]
    pub passphrase_protection: Option<bool>,
    /// Whether to enable PIN protection.
    #[prost(bool, optional, tag = "3")]
    pub pin_protection: Option<bool>,
    /// Mnemonic language.
    #[prost(string, optional, tag = "4")]
    pub language: Option<String>,
    /// User-visible device label.
    #[prost(string, optional, tag = "5")]
    pub label: Option<String>,
    /// Whether to enforce membership in the mnemonic word list.
    #[prost(bool, optional, tag = "6")]
    pub enforce_wordlist: Option<bool>,
    /// Whether to use character-cipher recovery.
    #[prost(bool, optional, tag = "7")]
    pub use_character_cipher: Option<bool>,
    /// Auto-lock delay in milliseconds.
    #[prost(uint32, optional, tag = "8")]
    pub auto_lock_delay_ms: Option<u32>,
    /// Initial U2F counter.
    #[prost(uint32, optional, tag = "9")]
    pub u2f_counter: Option<u32>,
    /// Whether to verify a mnemonic without replacing the wallet.
    #[prost(bool, optional, tag = "10")]
    pub dry_run: Option<bool>,
}

/// Recovery cursor positions in a KeepKey character request.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct CharacterRequest {
    /// Zero-based mnemonic word position.
    #[prost(uint32, required, tag = "1")]
    pub word_pos: u32,
    /// Zero-based character position within the current word.
    #[prost(uint32, required, tag = "2")]
    pub character_pos: u32,
}

/// A recovery character or editing action sent to KeepKey.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CharacterAck {
    /// Recovery character, including a space to advance to the next word.
    #[prost(string, optional, tag = "1")]
    pub character: Option<String>,
    /// Whether to delete the previous character.
    #[prost(bool, optional, tag = "2")]
    pub delete: Option<bool>,
    /// Whether to complete mnemonic entry.
    #[prost(bool, optional, tag = "3")]
    pub done: Option<bool>,
}

/// A request for the state exposed by KeepKey's debug-link interface.
#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct DebugLinkGetState {}

/// Debug-link state, which can contain sensitive wallet material.
#[derive(Clone, PartialEq, prost::Message)]
pub struct DebugLinkState {
    /// Display layout bytes.
    #[prost(bytes = "vec", optional, tag = "1")]
    pub layout: Option<Vec<u8>>,
    /// Device PIN exposed by debug firmware.
    #[prost(string, optional, tag = "2")]
    pub pin: Option<String>,
    /// Scrambled PIN matrix mapping.
    #[prost(string, optional, tag = "3")]
    pub matrix: Option<String>,
    /// Wallet mnemonic exposed by debug firmware.
    #[prost(string, optional, tag = "4")]
    pub mnemonic: Option<String>,
    /// Wallet HD node exposed by debug firmware.
    #[prost(message, optional, tag = "5")]
    pub node: Option<crate::trezor::proto::common::HdNodeType>,
    /// Whether passphrase protection is enabled.
    #[prost(bool, optional, tag = "6")]
    pub passphrase_protection: Option<bool>,
    /// Word currently displayed during wallet initialization.
    #[prost(string, optional, tag = "7")]
    pub reset_word: Option<String>,
    /// Device-generated initialization entropy.
    #[prost(bytes = "vec", optional, tag = "8")]
    pub reset_entropy: Option<Vec<u8>>,
    /// Decoy word used during recovery.
    #[prost(string, optional, tag = "9")]
    pub recovery_fake_word: Option<String>,
    /// Recovery word position reported by the debug interface.
    #[prost(uint32, optional, tag = "10")]
    pub recovery_word_pos: Option<u32>,
    /// Recovery character-cipher mapping.
    #[prost(string, optional, tag = "11")]
    pub recovery_cipher: Option<String>,
    /// Word auto-completed by recovery.
    #[prost(string, optional, tag = "12")]
    pub recovery_auto_completed_word: Option<String>,
    /// Firmware hash bytes.
    #[prost(bytes = "vec", optional, tag = "13")]
    pub firmware_hash: Option<Vec<u8>>,
    /// Storage hash bytes.
    #[prost(bytes = "vec", optional, tag = "14")]
    pub storage_hash: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn features_skips_conflicting_keepkey_fields() {
        let mut payload = Features {
            vendor: Some("keepkey.com".into()),
            major_version: Some(7),
            minor_version: Some(10),
            patch_version: Some(0),
            pin_protection: Some(true),
            passphrase_protection: Some(true),
            label: Some("test".into()),
            initialized: Some(true),
            pin_cached: Some(false),
            model: Some("K1-14AM".into()),
            firmware_variant: Some("keepkey".into()),
        }
        .encode_to_vec();
        // Policy tag 18, firmware hash tag 23, and no-backup tag 24 conflict
        // with the Trezor Features schema and must remain harmless unknowns.
        payload.extend_from_slice(&[
            0x92, 0x01, 0x02, 0x08, 0x01, 0xba, 0x01, 0x02, 0xaa, 0xbb, 0xc0, 0x01, 0x01,
        ]);

        let decoded = Features::decode(payload.as_slice()).unwrap();
        assert_eq!(decoded.vendor.as_deref(), Some("keepkey.com"));
        assert_eq!(decoded.major_version, Some(7));
        assert_eq!(decoded.pin_cached, Some(false));
        assert_eq!(decoded.model.as_deref(), Some("K1-14AM"));
        assert_eq!(decoded.firmware_variant.as_deref(), Some("keepkey"));
    }

    #[test]
    fn debug_state_uses_the_pinned_string_mnemonic_field() {
        let decoded = DebugLinkState::decode([0x22, 0x03, b'o', b'n', b'e'].as_slice()).unwrap();
        assert_eq!(decoded.mnemonic.as_deref(), Some("one"));
    }
}
