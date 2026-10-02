//! Bitcoin-specific request and response builders for BitBox02.
//!
//! Ported minimally from bitbox-api-rs (`src/btc.rs`) — Bitcoin operations only,
//! Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
//! Version 2.0 — see BITBOX_LICENSE at the repository root.

use bitcoin::bip32::DerivationPath;

use super::error::BitBoxError;
use super::proto as pb;

/// Creates a single-key script configuration.
pub fn make_script_config_simple(
    simple_type: pb::btc_script_config::SimpleType,
) -> pb::BtcScriptConfig {
    pb::BtcScriptConfig {
        config: Some(pb::btc_script_config::Config::SimpleType(
            simple_type.into(),
        )),
    }
}

/// Maps mainnet to the Bitcoin coin and every other network to the testnet coin.
pub fn coin_from_network(network: bitcoin::Network) -> pb::BtcCoin {
    if network == bitcoin::Network::Bitcoin {
        pb::BtcCoin::Btc
    } else {
        pb::BtcCoin::Tbtc
    }
}

/// Returns the mainnet xpub encoding or testnet tpub encoding for any other network.
pub fn xpub_type_from_network(network: bitcoin::Network) -> pb::btc_pub_request::XPubType {
    if network == bitcoin::Network::Bitcoin {
        pb::btc_pub_request::XPubType::Xpub
    } else {
        pb::btc_pub_request::XPubType::Tpub
    }
}

/// Creates an extended-public-key request with optional device confirmation.
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

/// Creates an address request with optional device display.
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

/// Creates a master-fingerprint request.
pub fn root_fingerprint_request() -> pb::request::Request {
    pb::request::Request::Fingerprint(pb::RootFingerprintRequest {})
}

/// Creates a device-information request.
pub fn device_info_request() -> pb::request::Request {
    pb::request::Request::DeviceInfo(pb::DeviceInfoRequest {})
}

/// Creates a request to display the mnemonic backup on the device.
pub fn show_mnemonic_request() -> pb::request::Request {
    pb::request::Request::ShowMnemonic(pb::ShowMnemonicRequest {})
}

/// Creates a request to set the user-visible device name.
pub fn set_device_name_request(name: impl Into<String>) -> pb::request::Request {
    pb::request::Request::DeviceName(pb::SetDeviceNameRequest { name: name.into() })
}

/// Creates a new-wallet initialization request using host-provided entropy.
pub fn set_password_request(entropy: &[u8; 32]) -> pb::request::Request {
    pb::request::Request::SetPassword(pb::SetPasswordRequest {
        entropy: entropy.to_vec(),
    })
}

/// Creates an initial SD-card backup request after wallet initialization.
///
/// `timestamp` is Unix time in seconds and `timezone_offset` is the UTC offset
/// in seconds.
pub fn create_backup_request(timestamp: u32, timezone_offset: i32) -> pb::request::Request {
    pb::request::Request::CreateBackup(pb::CreateBackupRequest {
        timestamp,
        timezone_offset,
    })
}

/// Creates an on-device mnemonic restore request.
///
/// `timestamp` is Unix time in seconds and `timezone_offset` is the UTC offset
/// in seconds.
pub fn restore_from_mnemonic_request(timestamp: u32, timezone_offset: i32) -> pb::request::Request {
    pb::request::Request::RestoreFromMnemonic(pb::RestoreFromMnemonicRequest {
        timestamp,
        timezone_offset,
    })
}

/// Creates a request to erase wallet material and reset the device.
pub fn reset_request() -> pb::request::Request {
    pb::request::Request::Reset(pb::ResetRequest {})
}

/// Creates a request to enable or disable mnemonic passphrase use.
pub fn set_mnemonic_passphrase_enabled_request(enabled: bool) -> pb::request::Request {
    pb::request::Request::SetMnemonicPassphraseEnabled(pb::SetMnemonicPassphraseEnabledRequest {
        enabled,
    })
}

/// Creates a script-configuration registration query.
///
/// An absent account path is encoded as an empty key path.
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

/// Creates a script-configuration registration request.
///
/// An absent account path is encoded as an empty key path and an absent name
/// as an empty string.
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

/// Decodes a device response, mapping error codes and rejecting an absent response.
pub fn decode_response(bytes: &[u8]) -> Result<pb::response::Response, BitBoxError> {
    use prost::Message;
    let response = pb::Response::decode(bytes)?;
    match response.response {
        Some(pb::response::Response::Error(pb::Error { code, message })) => {
            Err(BitBoxError::from_reply(code, message))
        }
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
