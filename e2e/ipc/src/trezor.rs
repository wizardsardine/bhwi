use anyhow::Result;
use bhwi_ipc::bhwi_capnp::{DeviceType, ErrorCode, Network};

use crate::approve::Approver;
use crate::support::{
    account_xpub, assert_address_matches_xpub_on, assert_descriptor_set,
    assert_info_matches_discovery, assert_keypool_on, assert_listed_emulator,
    assert_shows_address_on, assert_signs_message_on, assert_signs_psbt_on, error_code, ok, open,
    with_server,
};

const TREZOR_FINGERPRINT: &str = "5c9e228d";
const TREZOR_XPUB_44: &str = "tpubDDKn3FtHc74CaRrRbi1WFdJNaaenZkDWqq9NsEhcafnDZ4VuKeuLG2aKHm5SuwuLgAhRkkfHqcCxpnVNSrs5kJYZXwa6Ud431VnevzzzK3U";
const TREZOR_XPUB_84: &str = "tpubDCZB6sR48s4T5Cr8qHUYSZEFCQMMHRg8AoVKVmvcAP5bRw7ArDKeoNwKAJujV3xCPkBvXH5ejSgbgyN6kREmF7sMd41NdbuHa8n1DZNxSMg";

#[test]
fn trezor_is_listed_as_an_emulator() -> Result<()> {
    assert_listed_emulator(DeviceType::Trezor, TREZOR_FINGERPRINT, "trezor")
}

#[test]
fn trezor_reports_its_fingerprint_over_the_session() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Trezor, TREZOR_FINGERPRINT).await?;
        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            TREZOR_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn trezor_returns_a_legacy_account_xpub() -> Result<()> {
    account_xpub(
        DeviceType::Trezor,
        TREZOR_FINGERPRINT,
        "m/44'/1'/0'",
        TREZOR_XPUB_44,
    )
}

#[test]
fn trezor_returns_a_native_segwit_account_xpub() -> Result<()> {
    account_xpub(
        DeviceType::Trezor,
        TREZOR_FINGERPRINT,
        "m/84'/1'/0'",
        TREZOR_XPUB_84,
    )
}

#[test]
fn trezor_derives_the_standard_descriptor_set() -> Result<()> {
    assert_descriptor_set(DeviceType::Trezor, TREZOR_FINGERPRINT)
}

#[test]
fn trezor_reports_the_same_info_over_the_session_as_discovery() -> Result<()> {
    assert_info_matches_discovery(Network::Testnet, DeviceType::Trezor, TREZOR_FINGERPRINT)
}

#[test]
fn trezor_returns_a_keypool_descriptor() -> Result<()> {
    assert_keypool_on(
        Network::Testnet,
        DeviceType::Trezor,
        TREZOR_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn trezor_returns_the_address_its_xpub_derives() -> Result<()> {
    assert_address_matches_xpub_on(
        Network::Testnet,
        DeviceType::Trezor,
        TREZOR_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn trezor_shows_the_address_its_xpub_derives() -> Result<()> {
    assert_shows_address_on(
        Network::Testnet,
        DeviceType::Trezor,
        TREZOR_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Trezor),
    )
}

#[test]
fn trezor_signs_a_message_with_its_own_key() -> Result<()> {
    assert_signs_message_on(
        Network::Testnet,
        DeviceType::Trezor,
        TREZOR_FINGERPRINT,
        "m/44'/1'/0'",
        Some(Approver::Trezor),
    )
}

#[test]
fn trezor_signs_a_psbt() -> Result<()> {
    assert_signs_psbt_on(
        Network::Testnet,
        DeviceType::Trezor,
        TREZOR_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Trezor),
    )
}

/// A Trezor verifies the descriptor at display and signing time instead.
#[test]
fn trezor_refuses_to_register_a_wallet() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Trezor, TREZOR_FINGERPRINT).await?;
        let mut request = device.register_wallet_request();
        request.get().set_name("testwallet");
        request.get().set_policy("wpkh(@0/**)");
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::Unsupported
        );
        Ok(())
    })
}
