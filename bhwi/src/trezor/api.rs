use crate::trezor::error::TrezorError;
use crate::trezor::proto::{bitcoin as btc, common as pb, management as mgmt};
use prost::Message;

const HEADER: [u8; 2] = [b'#', b'#'];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Initialize = 0,
    Success = 2,
    Failure = 3,
    GetPublicKey = 11,
    PublicKey = 12,
    Features = 17,
    PinMatrixRequest = 18,
    ButtonRequest = 26,
    ButtonAck = 27,
    GetAddress = 29,
    Address = 30,
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

pub fn get_address(
    address_n: Vec<u32>,
    show_display: bool,
    script_type: btc::InputScriptType,
    coin_name: String,
) -> Vec<u8> {
    let msg = btc::GetAddress {
        address_n,
        show_display: Some(show_display),
        coin_name: Some(coin_name),
        script_type: Some(script_type as i32),
        ..Default::default()
    };
    encode(MessageType::GetAddress, &msg)
}
