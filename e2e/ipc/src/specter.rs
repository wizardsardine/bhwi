use anyhow::Result;
use bhwi_ipc::bhwi_capnp::{DeviceType, Network};

use crate::approve::Approver;
use crate::support::{
    assert_descriptor_set_on, assert_info_matches_discovery, assert_keypool_on,
    assert_listed_emulator, assert_registered_wallet_on, assert_shows_address_on,
    assert_signs_message_on, assert_signs_psbt_on, ok, open_on, with_server,
};

// specter-init loads the synthetic "abandon ... about" mnemonic.
const SPECTER_FINGERPRINT: &str = "73c5da0a";

// The simulator derives mainnet xpubs, which a testnet selector rejects.
const SPECTER_NETWORK: Network = Network::Bitcoin;

#[test]
fn specter_is_listed_as_an_emulator() -> Result<()> {
    assert_listed_emulator(DeviceType::Specter, SPECTER_FINGERPRINT, "specter")
}

#[test]
fn specter_reports_its_fingerprint_over_the_session() -> Result<()> {
    with_server(|client| async move {
        let device = open_on(
            &client,
            SPECTER_NETWORK,
            DeviceType::Specter,
            SPECTER_FINGERPRINT,
        )
        .await?;
        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            SPECTER_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn specter_derives_the_standard_descriptor_set() -> Result<()> {
    assert_descriptor_set_on(SPECTER_NETWORK, DeviceType::Specter, SPECTER_FINGERPRINT)
}

#[test]
fn specter_reports_the_same_info_over_the_session_as_discovery() -> Result<()> {
    assert_info_matches_discovery(SPECTER_NETWORK, DeviceType::Specter, SPECTER_FINGERPRINT)
}

#[test]
fn specter_returns_a_keypool_descriptor() -> Result<()> {
    assert_keypool_on(
        SPECTER_NETWORK,
        DeviceType::Specter,
        SPECTER_FINGERPRINT,
        "m/84'/0'/0'",
    )
}

#[test]
fn specter_shows_the_address_its_xpub_derives() -> Result<()> {
    assert_shows_address_on(
        SPECTER_NETWORK,
        DeviceType::Specter,
        SPECTER_FINGERPRINT,
        "m/84'/0'/0'",
        Some(Approver::Specter),
    )
}

#[test]
fn specter_signs_a_message_with_its_own_key() -> Result<()> {
    assert_signs_message_on(
        SPECTER_NETWORK,
        DeviceType::Specter,
        SPECTER_FINGERPRINT,
        "m/44'/0'/0'",
        Some(Approver::Specter),
    )
}

/// One test, as registering the same name twice may be refused.
#[test]
fn specter_registers_a_wallet_then_shows_and_signs_with_it() -> Result<()> {
    assert_registered_wallet_on(
        SPECTER_NETWORK,
        DeviceType::Specter,
        SPECTER_FINGERPRINT,
        Some(Approver::Specter),
        true,
        true,
    )
}

#[test]
fn specter_signs_a_psbt() -> Result<()> {
    assert_signs_psbt_on(
        SPECTER_NETWORK,
        DeviceType::Specter,
        SPECTER_FINGERPRINT,
        "m/84'/0'/0'",
        Some(Approver::Specter),
    )
}
