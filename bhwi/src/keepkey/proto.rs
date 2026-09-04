// KeepKey-specific protobuf messages.
// Source: keepkey/device-protocol @ 323802f17dd44165a5100357df771348c8b49672.
// Encoded with prost 0.13.5. Unknown fields are intentionally omitted.
#![allow(dead_code)]

#[derive(Clone, PartialEq, prost::Message)]
pub struct Features {
    #[prost(string, optional, tag = "1")]
    pub vendor: Option<String>,
    #[prost(uint32, optional, tag = "2")]
    pub major_version: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub minor_version: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub patch_version: Option<u32>,
    #[prost(bool, optional, tag = "7")]
    pub pin_protection: Option<bool>,
    #[prost(bool, optional, tag = "8")]
    pub passphrase_protection: Option<bool>,
    #[prost(string, optional, tag = "10")]
    pub label: Option<String>,
    #[prost(bool, optional, tag = "12")]
    pub initialized: Option<bool>,
    #[prost(bool, optional, tag = "16")]
    pub pin_cached: Option<bool>,
    #[prost(string, optional, tag = "21")]
    pub model: Option<String>,
    #[prost(string, optional, tag = "22")]
    pub firmware_variant: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ResetDevice {
    #[prost(bool, optional, tag = "1")]
    pub display_random: Option<bool>,
    #[prost(uint32, optional, tag = "2")]
    pub strength: Option<u32>,
    #[prost(bool, optional, tag = "3")]
    pub passphrase_protection: Option<bool>,
    #[prost(bool, optional, tag = "4")]
    pub pin_protection: Option<bool>,
    #[prost(string, optional, tag = "5")]
    pub language: Option<String>,
    #[prost(string, optional, tag = "6")]
    pub label: Option<String>,
    #[prost(bool, optional, tag = "7")]
    pub no_backup: Option<bool>,
    #[prost(uint32, optional, tag = "8")]
    pub auto_lock_delay_ms: Option<u32>,
    #[prost(uint32, optional, tag = "9")]
    pub u2f_counter: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RecoveryDevice {
    #[prost(uint32, optional, tag = "1")]
    pub word_count: Option<u32>,
    #[prost(bool, optional, tag = "2")]
    pub passphrase_protection: Option<bool>,
    #[prost(bool, optional, tag = "3")]
    pub pin_protection: Option<bool>,
    #[prost(string, optional, tag = "4")]
    pub language: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub label: Option<String>,
    #[prost(bool, optional, tag = "6")]
    pub enforce_wordlist: Option<bool>,
    #[prost(bool, optional, tag = "7")]
    pub use_character_cipher: Option<bool>,
    #[prost(uint32, optional, tag = "8")]
    pub auto_lock_delay_ms: Option<u32>,
    #[prost(uint32, optional, tag = "9")]
    pub u2f_counter: Option<u32>,
    #[prost(bool, optional, tag = "10")]
    pub dry_run: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct CharacterRequest {
    #[prost(uint32, required, tag = "1")]
    pub word_pos: u32,
    #[prost(uint32, required, tag = "2")]
    pub character_pos: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CharacterAck {
    #[prost(string, optional, tag = "1")]
    pub character: Option<String>,
    #[prost(bool, optional, tag = "2")]
    pub delete: Option<bool>,
    #[prost(bool, optional, tag = "3")]
    pub done: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, prost::Message)]
pub struct DebugLinkGetState {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DebugLinkState {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub layout: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    pub pin: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub matrix: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub mnemonic: Option<String>,
    #[prost(message, optional, tag = "5")]
    pub node: Option<crate::trezor::proto::common::HdNodeType>,
    #[prost(bool, optional, tag = "6")]
    pub passphrase_protection: Option<bool>,
    #[prost(string, optional, tag = "7")]
    pub reset_word: Option<String>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub reset_entropy: Option<Vec<u8>>,
    #[prost(string, optional, tag = "9")]
    pub recovery_fake_word: Option<String>,
    #[prost(uint32, optional, tag = "10")]
    pub recovery_word_pos: Option<u32>,
    #[prost(string, optional, tag = "11")]
    pub recovery_cipher: Option<String>,
    #[prost(string, optional, tag = "12")]
    pub recovery_auto_completed_word: Option<String>,
    #[prost(bytes = "vec", optional, tag = "13")]
    pub firmware_hash: Option<Vec<u8>>,
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
