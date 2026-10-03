//! KeepKey-specific protobuf request builders and wire message identifiers.

use prost::Message;

use crate::keepkey::proto;
use crate::trezor::proto::bitcoin as btc;

pub use crate::trezor::api::{frame, parse_frame};

/// Wire identifiers used by the KeepKey protocol profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    /// Session initialization request.
    Initialize = 0,
    /// Successful operation response.
    Success = 2,
    /// Device failure response.
    Failure = 3,
    /// Wallet erasure request.
    WipeDevice = 5,
    /// Extended-public-key request.
    GetPublicKey = 11,
    /// Extended-public-key response.
    PublicKey = 12,
    /// New-wallet initialization request.
    ResetDevice = 14,
    /// Transaction-signing request.
    SignTx = 15,
    /// Device-features response.
    Features = 17,
    /// Device request for scrambled PIN positions.
    PinMatrixRequest = 18,
    /// Host response containing scrambled PIN positions.
    PinMatrixAck = 19,
    /// Cancellation request.
    Cancel = 20,
    /// Device request for transaction data.
    TxRequest = 21,
    /// Host response containing transaction data.
    TxAck = 22,
    /// Device-settings update request.
    ApplySettings = 25,
    /// Device request to acknowledge a confirmation prompt.
    ButtonRequest = 26,
    /// Host acknowledgement of a confirmation prompt.
    ButtonAck = 27,
    /// Address request.
    GetAddress = 29,
    /// Address response.
    Address = 30,
    /// Device request for host entropy.
    EntropyRequest = 35,
    /// Host entropy response.
    EntropyAck = 36,
    /// Message-signing request.
    SignMessage = 38,
    /// Message-signature response.
    MessageSignature = 40,
    /// Device request for host passphrase entry.
    PassphraseRequest = 41,
    /// Host passphrase response.
    PassphraseAck = 42,
    /// Character-cipher mnemonic recovery request.
    RecoveryDevice = 45,
    /// Device-features request.
    GetFeatures = 55,
    /// Device request for a recovery character.
    CharacterRequest = 80,
    /// Host recovery character or editing action.
    CharacterAck = 81,
    /// Debug-link state request.
    DebugLinkGetState = 101,
    /// Debug-link state response.
    DebugLinkState = 102,
}

fn encode<M: Message>(message_type: MessageType, message: &M) -> Vec<u8> {
    frame(message_type as u16, &message.encode_to_vec())
}

/// Decodes a protobuf payload without its frame header.
pub fn decode<M: Message + Default>(payload: &[u8]) -> Result<M, crate::trezor::TrezorError> {
    M::decode(payload).map_err(crate::trezor::TrezorError::Decode)
}

/// Encodes a session-initialization request.
pub fn initialize() -> Vec<u8> {
    crate::trezor::api::initialize()
}

/// Encodes a device-features request.
pub fn get_features() -> Vec<u8> {
    crate::trezor::api::get_features()
}

/// Encodes a wallet-erasure request.
pub fn wipe_device() -> Vec<u8> {
    crate::trezor::api::wipe_device()
}

/// Encodes 128-bit wallet initialization with PIN protection and an optional label.
pub fn reset_device(passphrase_protection: bool, label: Option<String>) -> Vec<u8> {
    encode(
        MessageType::ResetDevice,
        &proto::ResetDevice {
            display_random: Some(false),
            strength: Some(128),
            passphrase_protection: Some(passphrase_protection),
            pin_protection: Some(true),
            language: Some("english".into()),
            label,
            no_backup: Some(false),
            auto_lock_delay_ms: None,
            u2f_counter: Some(0),
        },
    )
}

/// Encodes character-cipher recovery with PIN protection and initial U2F counter.
pub fn recovery_device(
    word_count: u32,
    passphrase_protection: bool,
    label: Option<String>,
    u2f_counter: u32,
) -> Vec<u8> {
    encode(
        MessageType::RecoveryDevice,
        &proto::RecoveryDevice {
            word_count: Some(word_count),
            passphrase_protection: Some(passphrase_protection),
            pin_protection: Some(true),
            language: Some("english".into()),
            label,
            enforce_wordlist: Some(true),
            use_character_cipher: Some(true),
            auto_lock_delay_ms: None,
            u2f_counter: Some(u2f_counter),
            dry_run: None,
        },
    )
}

/// Encodes caller-supplied entropy for a pending device entropy request.
pub fn entropy_ack(entropy: &[u8]) -> Vec<u8> {
    crate::trezor::api::entropy_ack(entropy)
}

/// Encodes a passphrase-protection settings update.
pub fn apply_settings(use_passphrase: bool) -> Vec<u8> {
    crate::trezor::api::apply_settings(use_passphrase)
}

/// Encodes cancellation of the pending device operation.
pub fn cancel() -> Vec<u8> {
    crate::trezor::api::cancel()
}

/// Encodes acknowledgement of a device confirmation prompt.
pub fn button_ack() -> Vec<u8> {
    crate::trezor::api::button_ack()
}

/// Encodes host passphrase text without normalization or length validation.
pub fn passphrase_ack_from_host(passphrase: &str) -> Vec<u8> {
    #[derive(Clone, PartialEq, prost::Message)]
    struct PassphraseAck {
        #[prost(string, required, tag = "1")]
        passphrase: String,
    }

    encode(
        MessageType::PassphraseAck,
        &PassphraseAck {
            passphrase: passphrase.to_owned(),
        },
    )
}

/// Encodes scrambled keypad positions without validating them.
pub fn pin_matrix_ack(positions: &str) -> Vec<u8> {
    crate::trezor::api::pin_matrix_ack(positions)
}

/// Encodes an extended-key request using BIP-32 child numbers and the selected coin.
pub fn get_public_key(address_n: Vec<u32>, show_display: bool, coin_name: String) -> Vec<u8> {
    encode(
        MessageType::GetPublicKey,
        &btc::GetPublicKey {
            address_n,
            show_display: Some(show_display),
            coin_name: Some(coin_name),
            script_type: Some(btc::InputScriptType::Spendaddress as i32),
            ignore_xpub_magic: None,
            ..Default::default()
        },
    )
}

/// Encodes transaction-signing metadata with consensus version and lock time.
pub fn sign_tx(
    inputs_count: u32,
    outputs_count: u32,
    version: u32,
    lock_time: u32,
    coin_name: &str,
) -> Vec<u8> {
    crate::trezor::api::sign_tx(inputs_count, outputs_count, version, lock_time, coin_name)
}

/// Encodes transaction data requested during signing.
pub fn tx_ack(tx: btc::tx_ack::TransactionType) -> Vec<u8> {
    crate::trezor::api::tx_ack(tx)
}

/// Encodes legacy single-key message signing with a BIP-32 path and message bytes.
pub fn sign_message(address_n: Vec<u32>, message: Vec<u8>, coin_name: String) -> Vec<u8> {
    #[derive(Clone, PartialEq, prost::Message)]
    struct SignMessage {
        #[prost(uint32, repeated, packed = "false", tag = "1")]
        address_n: Vec<u32>,
        #[prost(bytes = "vec", required, tag = "2")]
        message: Vec<u8>,
        #[prost(string, optional, tag = "3")]
        coin_name: Option<String>,
        #[prost(enumeration = "btc::InputScriptType", optional, tag = "4")]
        script_type: Option<i32>,
    }

    encode(
        MessageType::SignMessage,
        &SignMessage {
            address_n,
            message,
            coin_name: Some(coin_name),
            script_type: Some(btc::InputScriptType::Spendaddress as i32),
        },
    )
}

/// Encodes address retrieval or display, optionally supplying a multisig script.
pub fn get_address(
    address_n: Vec<u32>,
    show_display: bool,
    script_type: btc::InputScriptType,
    coin_name: String,
    multisig: Option<btc::MultisigRedeemScriptType>,
) -> Vec<u8> {
    crate::trezor::api::get_address(address_n, show_display, script_type, coin_name, multisig)
}

/// Encodes a recovery character, mapping backspace to deletion and newline to completion.
///
/// Other bytes become a one-character string; this builder does not validate
/// lowercase ASCII or the recovery cursor position.
pub fn character_ack(value: u8) -> Vec<u8> {
    let message = match value {
        0x08 => proto::CharacterAck {
            delete: Some(true),
            ..Default::default()
        },
        b'\n' => proto::CharacterAck {
            done: Some(true),
            ..Default::default()
        },
        character => proto::CharacterAck {
            character: Some(char::from(character).to_string()),
            ..Default::default()
        },
    };
    encode(MessageType::CharacterAck, &message)
}

/// Encodes a debug-link state request for firmware exposing that interface.
pub fn debug_link_get_state() -> Vec<u8> {
    encode(MessageType::DebugLinkGetState, &proto::DebugLinkGetState {})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(frame: Vec<u8>, message_type: MessageType) -> Vec<u8> {
        let (actual, payload) = parse_frame(&frame).unwrap();
        assert_eq!(actual, message_type as u16);
        payload
    }

    #[test]
    fn public_key_request_is_the_exact_keepkey_profile() {
        assert_eq!(
            payload(
                get_public_key(vec![1], false, "Bitcoin".into()),
                MessageType::GetPublicKey,
            ),
            [
                0x08, 0x01, 0x18, 0x00, 0x22, 0x07, b'B', b'i', b't', b'c', b'o', b'i', b'n', 0x28,
                0x00,
            ]
        );
    }

    #[test]
    fn sign_message_omits_the_trezor_only_field_five() {
        assert_eq!(
            payload(
                sign_message(vec![1], vec![b'x'], "Bitcoin".into()),
                MessageType::SignMessage,
            ),
            [
                0x08, 0x01, 0x12, 0x01, b'x', 0x1a, 0x07, b'B', b'i', b't', b'c', b'o', b'i', b'n',
                0x20, 0x00,
            ]
        );
    }

    #[test]
    fn host_passphrase_ack_has_only_the_required_field() {
        assert_eq!(
            payload(passphrase_ack_from_host("x"), MessageType::PassphraseAck),
            [0x0a, 0x01, b'x']
        );
        assert_eq!(
            payload(passphrase_ack_from_host(""), MessageType::PassphraseAck),
            [0x0a, 0x00]
        );
    }

    #[test]
    fn reset_request_has_keepkey_tags_and_omits_auto_lock() {
        assert_eq!(
            payload(
                reset_device(true, Some("k".into())),
                MessageType::ResetDevice,
            ),
            [
                0x08, 0x00, 0x10, 0x80, 0x01, 0x18, 0x01, 0x20, 0x01, 0x2a, 0x07, b'e', b'n', b'g',
                b'l', b'i', b's', b'h', 0x32, 0x01, b'k', 0x38, 0x00, 0x48, 0x00,
            ]
        );
    }

    #[test]
    fn recovery_request_enables_character_cipher_and_omits_auto_lock() {
        assert_eq!(
            payload(
                recovery_device(12, true, Some("k".into()), 1),
                MessageType::RecoveryDevice,
            ),
            [
                0x08, 0x0c, 0x10, 0x01, 0x18, 0x01, 0x22, 0x07, b'e', b'n', b'g', b'l', b'i', b's',
                b'h', 0x2a, 0x01, b'k', 0x30, 0x01, 0x38, 0x01, 0x48, 0x01,
            ]
        );
    }

    #[test]
    fn recovery_actions_use_character_delete_space_and_done_fields() {
        assert_eq!(
            payload(character_ack(b'a'), MessageType::CharacterAck),
            [0x0a, 0x01, b'a']
        );
        assert_eq!(
            payload(character_ack(0x08), MessageType::CharacterAck),
            [0x10, 0x01]
        );
        assert_eq!(
            payload(character_ack(b' '), MessageType::CharacterAck),
            [0x0a, 0x01, b' ']
        );
        assert_eq!(
            payload(character_ack(b'\n'), MessageType::CharacterAck),
            [0x18, 0x01]
        );
    }
}
