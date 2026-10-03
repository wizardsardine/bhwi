//! Trezor protobuf request builders and message framing.

use crate::trezor::error::TrezorError;
use crate::trezor::proto::{bitcoin as btc, common as pb, management as mgmt};
use prost::Message;

const HEADER: [u8; 2] = *b"##";

/// Wire identifiers for messages used by the Trezor interpreter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    /// Session initialization request.
    Initialize = 0,
    /// Successful operation response.
    Success = 2,
    /// Wallet erasure request.
    WipeDevice = 5,
    /// New-wallet initialization request.
    ResetDevice = 14,
    /// Mnemonic recovery request.
    RecoveryDevice = 45,
    /// Device-settings update request.
    ApplySettings = 25,
    /// Device request for host entropy.
    EntropyRequest = 35,
    /// Host entropy response.
    EntropyAck = 36,
    /// Device failure response.
    Failure = 3,
    /// Extended-public-key request.
    GetPublicKey = 11,
    /// Extended-public-key response.
    PublicKey = 12,
    /// Device-features response.
    Features = 17,
    /// Device request for scrambled PIN positions.
    PinMatrixRequest = 18,
    /// Host response containing scrambled PIN positions.
    PinMatrixAck = 19,
    /// Device request to acknowledge a confirmation prompt.
    ButtonRequest = 26,
    /// Host acknowledgement of a confirmation prompt.
    ButtonAck = 27,
    /// Transaction-signing request.
    SignTx = 15,
    /// Cancellation request.
    Cancel = 20,
    /// Device request for transaction data.
    TxRequest = 21,
    /// Host response containing transaction data.
    TxAck = 22,
    /// Address request.
    GetAddress = 29,
    /// Address response.
    Address = 30,
    /// Message-signing request.
    SignMessage = 38,
    /// Message-signature response.
    MessageSignature = 40,
    /// Device request for passphrase entry.
    PassphraseRequest = 41,
    /// Host passphrase response or on-device entry selection.
    PassphraseAck = 42,
    /// Device-features request.
    GetFeatures = 55,
}

/// Frames protobuf bytes with a message identifier and big-endian byte length.
///
/// Payload length is cast to `u32` without range validation.
pub fn frame(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parses a framed message identifier and payload, ignoring trailing bytes.
pub fn parse_frame(data: &[u8]) -> Result<(u16, Vec<u8>), TrezorError> {
    if data.len() < 8 || data[0..2] != HEADER {
        return Err(TrezorError::MalformedFrame);
    }
    let msg_type = u16::from_be_bytes([data[2], data[3]]);
    let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let payload = data
        .get(8..8 + len)
        .ok_or(TrezorError::MalformedFrame)?
        .to_vec();
    Ok((msg_type, payload))
}

/// Decodes a protobuf payload without its frame header.
pub fn decode<M: Message + Default>(payload: &[u8]) -> Result<M, TrezorError> {
    M::decode(payload).map_err(TrezorError::Decode)
}

fn encode<M: Message>(msg_type: MessageType, msg: &M) -> Vec<u8> {
    frame(msg_type as u16, &msg.encode_to_vec())
}

/// Encodes a session-initialization request.
pub fn initialize() -> Vec<u8> {
    encode(MessageType::Initialize, &mgmt::Initialize::default())
}

/// Encodes a device-features request.
pub fn get_features() -> Vec<u8> {
    encode(MessageType::GetFeatures, &mgmt::GetFeatures::default())
}

/// Encodes a wallet-erasure request.
pub fn wipe_device() -> Vec<u8> {
    encode(MessageType::WipeDevice, &mgmt::WipeDevice::default())
}

/// Encodes BIP-39 wallet initialization with entropy strength in bits and PIN protection.
///
/// An absent label leaves naming to firmware.
pub fn reset_device(strength: u32, passphrase_protection: bool, label: Option<String>) -> Vec<u8> {
    encode(
        MessageType::ResetDevice,
        &mgmt::ResetDevice {
            strength: Some(strength),
            passphrase_protection: Some(passphrase_protection),
            pin_protection: Some(true),
            label,
            u2f_counter: Some(0),
            skip_backup: Some(false),
            no_backup: Some(false),
            backup_type: Some(mgmt::BackupType::Bip39 as i32),
            ..Default::default()
        },
    )
}

/// Encodes mnemonic recovery with PIN protection, word count, and initial U2F counter.
pub fn recovery_device(
    word_count: u32,
    passphrase_protection: bool,
    label: Option<String>,
    u2f_counter: u32,
) -> Vec<u8> {
    encode(
        MessageType::RecoveryDevice,
        &mgmt::RecoveryDevice {
            word_count: Some(word_count),
            passphrase_protection: Some(passphrase_protection),
            pin_protection: Some(true),
            label,
            enforce_wordlist: Some(true),
            u2f_counter: Some(u2f_counter),
            ..Default::default()
        },
    )
}

/// Encodes caller-supplied entropy for a pending device entropy request.
pub fn entropy_ack(entropy: &[u8]) -> Vec<u8> {
    encode(
        MessageType::EntropyAck,
        &mgmt::EntropyAck {
            entropy: entropy.to_vec(),
        },
    )
}

/// Encodes a passphrase-protection settings update.
pub fn apply_settings(use_passphrase: bool) -> Vec<u8> {
    encode(
        MessageType::ApplySettings,
        &mgmt::ApplySettings {
            use_passphrase: Some(use_passphrase),
            ..Default::default()
        },
    )
}

/// Encodes cancellation of the pending device operation.
pub fn cancel() -> Vec<u8> {
    encode(MessageType::Cancel, &mgmt::Cancel::default())
}

/// Encodes acknowledgement of a device confirmation prompt.
pub fn button_ack() -> Vec<u8> {
    encode(MessageType::ButtonAck, &pb::ButtonAck::default())
}

/// Encodes selection of on-device passphrase entry.
pub fn passphrase_ack_on_device() -> Vec<u8> {
    let msg = pb::PassphraseAck {
        on_device: Some(true),
        passphrase: None,
        ..Default::default()
    };
    encode(MessageType::PassphraseAck, &msg)
}

/// Encodes host passphrase text without normalization or length validation.
pub fn passphrase_ack_from_host(passphrase: &str) -> Vec<u8> {
    let msg = pb::PassphraseAck {
        on_device: Some(false),
        passphrase: Some(passphrase.to_owned()),
        ..Default::default()
    };
    encode(MessageType::PassphraseAck, &msg)
}

/// Encodes scrambled keypad positions without validating them.
pub fn pin_matrix_ack(positions: &str) -> Vec<u8> {
    let msg = pb::PinMatrixAck {
        pin: positions.to_owned(),
    };
    encode(MessageType::PinMatrixAck, &msg)
}

/// Encodes an extended-key request using BIP-32 child numbers and the selected coin.
pub fn get_public_key(
    address_n: Vec<u32>,
    show_display: bool,
    script_type: btc::InputScriptType,
    coin_name: String,
) -> Vec<u8> {
    let msg = btc::GetPublicKey {
        address_n,
        show_display: Some(show_display),
        coin_name: Some(coin_name),
        script_type: Some(script_type as i32),
        ignore_xpub_magic: Some(true),
        ..Default::default()
    };
    encode(MessageType::GetPublicKey, &msg)
}

/// Encodes transaction-signing metadata with consensus version and lock time.
pub fn sign_tx(
    inputs_count: u32,
    outputs_count: u32,
    version: u32,
    lock_time: u32,
    coin_name: &str,
) -> Vec<u8> {
    let msg = btc::SignTx {
        inputs_count,
        outputs_count,
        coin_name: Some(coin_name.to_string()),
        version: Some(version),
        lock_time: Some(lock_time),
        serialize: Some(false),
        ..Default::default()
    };
    encode(MessageType::SignTx, &msg)
}

/// Encodes transaction data requested during signing.
pub fn tx_ack(tx: btc::tx_ack::TransactionType) -> Vec<u8> {
    let msg = btc::TxAck { tx: Some(tx) };
    encode(MessageType::TxAck, &msg)
}

/// Encodes legacy single-key message signing with a BIP-32 path and message bytes.
pub fn sign_message(address_n: Vec<u32>, message: Vec<u8>, coin_name: String) -> Vec<u8> {
    let msg = btc::SignMessage {
        address_n,
        message,
        coin_name: Some(coin_name),
        script_type: Some(btc::InputScriptType::Spendaddress as i32),
        no_script_type: Some(false),
        ..Default::default()
    };
    encode(MessageType::SignMessage, &msg)
}

/// Encodes address retrieval or display, optionally supplying a multisig script.
pub fn get_address(
    address_n: Vec<u32>,
    show_display: bool,
    script_type: btc::InputScriptType,
    coin_name: String,
    multisig: Option<btc::MultisigRedeemScriptType>,
) -> Vec<u8> {
    let msg = btc::GetAddress {
        address_n,
        show_display: Some(show_display),
        coin_name: Some(coin_name),
        script_type: Some(script_type as i32),
        multisig,
        ..Default::default()
    };
    encode(MessageType::GetAddress, &msg)
}
