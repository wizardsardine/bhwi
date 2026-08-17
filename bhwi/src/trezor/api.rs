use crate::trezor::error::TrezorError;
use crate::trezor::proto::{bitcoin as btc, common as pb, management as mgmt};
use prost::Message;

const HEADER: [u8; 2] = *b"##";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Initialize = 0,
    Success = 2,
    WipeDevice = 5,
    ResetDevice = 14,
    RecoveryDevice = 45,
    ApplySettings = 25,
    EntropyRequest = 35,
    EntropyAck = 36,
    Failure = 3,
    GetPublicKey = 11,
    PublicKey = 12,
    Features = 17,
    PinMatrixRequest = 18,
    PinMatrixAck = 19,
    ButtonRequest = 26,
    ButtonAck = 27,
    SignTx = 15,
    Cancel = 20,
    TxRequest = 21,
    TxAck = 22,
    GetAddress = 29,
    Address = 30,
    SignMessage = 38,
    MessageSignature = 40,
    PassphraseRequest = 41,
    PassphraseAck = 42,
    GetFeatures = 55,
}

pub fn frame(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

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

pub fn decode<M: Message + Default>(payload: &[u8]) -> Result<M, TrezorError> {
    M::decode(payload).map_err(TrezorError::Decode)
}

fn encode<M: Message>(msg_type: MessageType, msg: &M) -> Vec<u8> {
    frame(msg_type as u16, &msg.encode_to_vec())
}

pub fn initialize() -> Vec<u8> {
    encode(MessageType::Initialize, &mgmt::Initialize::default())
}

pub fn get_features() -> Vec<u8> {
    encode(MessageType::GetFeatures, &mgmt::GetFeatures::default())
}

pub fn wipe_device() -> Vec<u8> {
    encode(MessageType::WipeDevice, &mgmt::WipeDevice::default())
}

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

pub fn entropy_ack(entropy: &[u8]) -> Vec<u8> {
    encode(
        MessageType::EntropyAck,
        &mgmt::EntropyAck {
            entropy: entropy.to_vec(),
        },
    )
}

pub fn apply_settings(use_passphrase: bool) -> Vec<u8> {
    encode(
        MessageType::ApplySettings,
        &mgmt::ApplySettings {
            use_passphrase: Some(use_passphrase),
            ..Default::default()
        },
    )
}

pub fn cancel() -> Vec<u8> {
    encode(MessageType::Cancel, &mgmt::Cancel::default())
}

pub fn button_ack() -> Vec<u8> {
    encode(MessageType::ButtonAck, &pb::ButtonAck::default())
}

pub fn passphrase_ack_on_device() -> Vec<u8> {
    let msg = pb::PassphraseAck {
        on_device: Some(true),
        passphrase: None,
        ..Default::default()
    };
    encode(MessageType::PassphraseAck, &msg)
}

pub fn passphrase_ack_from_host(passphrase: &str) -> Vec<u8> {
    let msg = pb::PassphraseAck {
        on_device: Some(false),
        passphrase: Some(passphrase.to_owned()),
        ..Default::default()
    };
    encode(MessageType::PassphraseAck, &msg)
}

pub fn pin_matrix_ack(positions: &str) -> Vec<u8> {
    let msg = pb::PinMatrixAck {
        pin: positions.to_owned(),
    };
    encode(MessageType::PinMatrixAck, &msg)
}

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
        ..Default::default()
    };
    encode(MessageType::SignTx, &msg)
}

pub fn tx_ack(tx: btc::tx_ack::TransactionType) -> Vec<u8> {
    let msg = btc::TxAck { tx: Some(tx) };
    encode(MessageType::TxAck, &msg)
}

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
