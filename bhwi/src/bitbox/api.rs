//! Bitcoin-specific request and response builders for BitBox02.
//!
//! Ported minimally from bitbox-api-rs (`src/btc.rs`) — Bitcoin operations only,
//! Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
//! Version 2.0 — see BITBOX_LICENSE at the repository root.

use bitcoin::bip32::Xpub;

use super::error::BitBoxError;
use super::keypath::Keypath;
use super::proto as pb;

/// Convert a `bitcoin::bip32::Xpub` to the protobuf `pb::XPub` representation.
pub fn convert_xpub(xpub: &Xpub) -> pb::XPub {
    pb::XPub {
        depth: vec![xpub.depth],
        parent_fingerprint: xpub.parent_fingerprint[..].to_vec(),
        child_num: xpub.child_number.into(),
        chain_code: xpub.chain_code[..].to_vec(),
        public_key: xpub.public_key.serialize().to_vec(),
    }
}

/// Origin info for a single key in a wallet policy or multisig registration.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyOriginInfo {
    pub root_fingerprint: Option<bitcoin::bip32::Fingerprint>,
    pub keypath: Option<Keypath>,
    pub xpub: Xpub,
}

impl From<KeyOriginInfo> for pb::KeyOriginInfo {
    fn from(value: KeyOriginInfo) -> Self {
        pb::KeyOriginInfo {
            root_fingerprint: value
                .root_fingerprint
                .map_or(vec![], |fp| fp.as_bytes().to_vec()),
            keypath: value.keypath.map_or(vec![], |kp| kp.to_vec()),
            xpub: Some(convert_xpub(&value.xpub)),
        }
    }
}

/// Create a single-sig script config.
pub fn make_script_config_simple(
    simple_type: pb::btc_script_config::SimpleType,
) -> pb::BtcScriptConfig {
    pb::BtcScriptConfig {
        config: Some(pb::btc_script_config::Config::SimpleType(
            simple_type.into(),
        )),
    }
}

/// Create a wallet policy script config (BIP-388).
pub fn make_script_config_policy(policy: &str, keys: &[KeyOriginInfo]) -> pb::BtcScriptConfig {
    pb::BtcScriptConfig {
        config: Some(pb::btc_script_config::Config::Policy(
            pb::btc_script_config::Policy {
                policy: policy.into(),
                keys: keys.iter().cloned().map(pb::KeyOriginInfo::from).collect(),
            },
        )),
    }
}

/// Map a `bitcoin::Network` to the BitBox02 `BtcCoin` enum. Only mainnet and testnet variants
/// are supported; every non-mainnet network is treated as testnet (matches async-hwi behaviour).
pub fn coin_from_network(network: bitcoin::Network) -> pb::BtcCoin {
    if network == bitcoin::Network::Bitcoin {
        pb::BtcCoin::Btc
    } else {
        pb::BtcCoin::Tbtc
    }
}

/// Choose the appropriate `XPubType` for the given network (mainnet vs. testnet).
pub fn xpub_type_from_network(network: bitcoin::Network) -> pb::btc_pub_request::XPubType {
    if network == bitcoin::Network::Bitcoin {
        pb::btc_pub_request::XPubType::Xpub
    } else {
        pb::btc_pub_request::XPubType::Tpub
    }
}

/// Build a `BtcPub` request for a raw xpub.
pub fn xpub_request(
    coin: pb::BtcCoin,
    keypath: &Keypath,
    xpub_type: pb::btc_pub_request::XPubType,
    display: bool,
) -> pb::request::Request {
    pb::request::Request::BtcPub(pb::BtcPubRequest {
        coin: coin as _,
        keypath: keypath.to_vec(),
        display,
        output: Some(pb::btc_pub_request::Output::XpubType(xpub_type as _)),
    })
}

/// Build a `BtcPub` request for an address display.
pub fn address_request(
    coin: pb::BtcCoin,
    keypath: &Keypath,
    script_config: pb::BtcScriptConfig,
    display: bool,
) -> pb::request::Request {
    pb::request::Request::BtcPub(pb::BtcPubRequest {
        coin: coin as _,
        keypath: keypath.to_vec(),
        display,
        output: Some(pb::btc_pub_request::Output::ScriptConfig(script_config)),
    })
}

/// Build a `RootFingerprint` request.
pub fn root_fingerprint_request() -> pb::request::Request {
    pb::request::Request::Fingerprint(pb::RootFingerprintRequest {})
}

/// Build a `DeviceInfo` request.
pub fn device_info_request() -> pb::request::Request {
    pb::request::Request::DeviceInfo(pb::DeviceInfoRequest {})
}

/// Build a nested `BtcRequest::IsScriptConfigRegistered`.
pub fn is_script_config_registered_request(
    coin: pb::BtcCoin,
    script_config: pb::BtcScriptConfig,
    keypath_account: Option<&Keypath>,
) -> pb::request::Request {
    pb::request::Request::Btc(pb::BtcRequest {
        request: Some(pb::btc_request::Request::IsScriptConfigRegistered(
            pb::BtcIsScriptConfigRegisteredRequest {
                registration: Some(pb::BtcScriptConfigRegistration {
                    coin: coin as _,
                    script_config: Some(script_config),
                    keypath: keypath_account.map_or(vec![], |kp| kp.to_vec()),
                }),
            },
        )),
    })
}

/// Build a nested `BtcRequest::RegisterScriptConfig`.
pub fn register_script_config_request(
    coin: pb::BtcCoin,
    script_config: pb::BtcScriptConfig,
    keypath_account: Option<&Keypath>,
    xpub_type: pb::btc_register_script_config_request::XPubType,
    name: Option<&str>,
) -> pb::request::Request {
    pb::request::Request::Btc(pb::BtcRequest {
        request: Some(pb::btc_request::Request::RegisterScriptConfig(
            pb::BtcRegisterScriptConfigRequest {
                registration: Some(pb::BtcScriptConfigRegistration {
                    coin: coin as _,
                    script_config: Some(script_config),
                    keypath: keypath_account.map_or(vec![], |kp| kp.to_vec()),
                }),
                name: name.unwrap_or("").into(),
                xpub_type: xpub_type as _,
            },
        )),
    })
}

/// Decode a top-level device response, mapping known error codes.
pub fn decode_response(bytes: &[u8]) -> Result<pb::response::Response, BitBoxError> {
    use prost::Message;
    let response = pb::Response::decode(bytes)?;
    match response.response {
        Some(pb::response::Response::Error(pb::Error { code, .. })) => Err(BitBoxError::Device(
            super::error::BitBoxDeviceError::from_code(code),
        )),
        Some(r) => Ok(r),
        None => Err(BitBoxError::UnexpectedResponse),
    }
}
