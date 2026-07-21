//! Bitcoin-specific request and response builders for BitBox02.
//!
//! Ported minimally from bitbox-api-rs (`src/btc.rs`) — Bitcoin operations only,
//! Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
//! Version 2.0 — see BITBOX_LICENSE at the repository root.

use bitcoin::bip32::DerivationPath;

use super::error::BitBoxError;
use super::proto as pb;

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
    keypath: &DerivationPath,
    xpub_type: pb::btc_pub_request::XPubType,
    display: bool,
) -> pb::request::Request {
    pb::request::Request::BtcPub(pb::BtcPubRequest {
        coin: coin as _,
        keypath: keypath.to_u32_vec(),
        display,
        output: Some(pb::btc_pub_request::Output::XpubType(xpub_type as _)),
    })
}

/// Build a `BtcPub` request for an address display.
pub fn address_request(
    coin: pb::BtcCoin,
    keypath: &DerivationPath,
    script_config: pb::BtcScriptConfig,
    display: bool,
) -> pb::request::Request {
    pb::request::Request::BtcPub(pb::BtcPubRequest {
        coin: coin as _,
        keypath: keypath.to_u32_vec(),
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

/// Build a request that asks the BitBox02 to display/export its mnemonic backup flow.
pub fn show_mnemonic_request() -> pb::request::Request {
    pb::request::Request::ShowMnemonic(pb::ShowMnemonicRequest {})
}

/// Set the user-visible device name.
pub fn set_device_name_request(name: impl Into<String>) -> pb::request::Request {
    pb::request::Request::DeviceName(pb::SetDeviceNameRequest { name: name.into() })
}

/// Initialize a new wallet using host-provided entropy.
pub fn set_password_request(entropy: &[u8; 32]) -> pb::request::Request {
    pb::request::Request::SetPassword(pb::SetPasswordRequest {
        entropy: entropy.to_vec(),
    })
}

/// Create the initial SD-card backup after a new wallet has been initialized.
pub fn create_backup_request(timestamp: u32, timezone_offset: i32) -> pb::request::Request {
    pb::request::Request::CreateBackup(pb::CreateBackupRequest {
        timestamp,
        timezone_offset,
    })
}

/// Start the on-device mnemonic restore flow.
pub fn restore_from_mnemonic_request(timestamp: u32, timezone_offset: i32) -> pb::request::Request {
    pb::request::Request::RestoreFromMnemonic(pb::RestoreFromMnemonicRequest {
        timestamp,
        timezone_offset,
    })
}

/// Erase wallet material and return the device to its uninitialized state.
pub fn reset_request() -> pb::request::Request {
    pb::request::Request::Reset(pb::ResetRequest {})
}

/// Enable or disable use of a mnemonic passphrase on the device.
pub fn set_mnemonic_passphrase_enabled_request(enabled: bool) -> pb::request::Request {
    pb::request::Request::SetMnemonicPassphraseEnabled(pb::SetMnemonicPassphraseEnabledRequest {
        enabled,
    })
}

/// Build a nested `BtcRequest::IsScriptConfigRegistered`.
pub fn is_script_config_registered_request(
    coin: pb::BtcCoin,
    script_config: pb::BtcScriptConfig,
    keypath_account: Option<&DerivationPath>,
) -> pb::request::Request {
    pb::request::Request::Btc(pb::BtcRequest {
        request: Some(pb::btc_request::Request::IsScriptConfigRegistered(
            pb::BtcIsScriptConfigRegisteredRequest {
                registration: Some(pb::BtcScriptConfigRegistration {
                    coin: coin as _,
                    script_config: Some(script_config),
                    keypath: keypath_account.map_or(vec![], |kp| kp.to_u32_vec()),
                }),
            },
        )),
    })
}

/// Build a nested `BtcRequest::RegisterScriptConfig`.
pub fn register_script_config_request(
    coin: pb::BtcCoin,
    script_config: pb::BtcScriptConfig,
    keypath_account: Option<&DerivationPath>,
    xpub_type: pb::btc_register_script_config_request::XPubType,
    name: Option<&str>,
) -> pb::request::Request {
    pb::request::Request::Btc(pb::BtcRequest {
        request: Some(pb::btc_request::Request::RegisterScriptConfig(
            pb::BtcRegisterScriptConfigRequest {
                registration: Some(pb::BtcScriptConfigRegistration {
                    coin: coin as _,
                    script_config: Some(script_config),
                    keypath: keypath_account.map_or(vec![], |kp| kp.to_u32_vec()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_mnemonic_request_uses_backup_flow() {
        assert!(matches!(
            show_mnemonic_request(),
            pb::request::Request::ShowMnemonic(pb::ShowMnemonicRequest {})
        ));
    }

    #[test]
    fn setup_requests_preserve_external_inputs() {
        assert!(matches!(
            set_device_name_request("HWI Test"),
            pb::request::Request::DeviceName(pb::SetDeviceNameRequest { name })
                if name == "HWI Test"
        ));

        let entropy = [42; 32];
        assert!(matches!(
            set_password_request(&entropy),
            pb::request::Request::SetPassword(pb::SetPasswordRequest { entropy: encoded })
                if encoded == entropy
        ));

        assert!(matches!(
            create_backup_request(1_601_450_521, 3_600),
            pb::request::Request::CreateBackup(pb::CreateBackupRequest {
                timestamp: 1_601_450_521,
                timezone_offset: 3_600,
            })
        ));

        assert!(matches!(
            restore_from_mnemonic_request(1_601_450_521, -3_600),
            pb::request::Request::RestoreFromMnemonic(pb::RestoreFromMnemonicRequest {
                timestamp: 1_601_450_521,
                timezone_offset: -3_600,
            })
        ));
    }

    #[test]
    fn wipe_request_uses_reset() {
        assert!(matches!(
            reset_request(),
            pb::request::Request::Reset(pb::ResetRequest {})
        ));
    }

    #[test]
    fn toggle_passphrase_request_preserves_enabled_state() {
        assert!(matches!(
            set_mnemonic_passphrase_enabled_request(true),
            pb::request::Request::SetMnemonicPassphraseEnabled(
                pb::SetMnemonicPassphraseEnabledRequest { enabled: true }
            )
        ));
    }
}
