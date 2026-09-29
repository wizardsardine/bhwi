use anyhow::Result;
use bhwi_ipc::bhwi_capnp::{DeviceType, Network};

use crate::approve::Approver;
use crate::support::{
    Registered, account_xpub, assert_address_matches_xpub_on, assert_descriptor_set,
    assert_info_matches_discovery, assert_keypool_on, assert_listed_emulator,
    assert_registered_wallet_on, assert_registers_wallet_on, assert_shows_address_on,
    assert_signs_message_on, assert_signs_psbt_on, ok, open, set_selector_on, with_server,
};

const LEDGER_FINGERPRINT: &str = "f5acc2fd";
const LEDGER_XPUB_44: &str = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";

#[test]
fn ledger_is_listed_as_an_emulator() -> Result<()> {
    assert_listed_emulator(DeviceType::Ledger, LEDGER_FINGERPRINT, "ledger")
}

#[test]
fn ledger_reports_its_fingerprint_over_the_session() -> Result<()> {
    crate::support::with_server(|client| async move {
        let device = open(&client, DeviceType::Ledger, LEDGER_FINGERPRINT).await?;
        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            LEDGER_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn ledger_returns_an_account_xpub() -> Result<()> {
    account_xpub(
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        "m/44'/1'/0'",
        LEDGER_XPUB_44,
    )
}

#[test]
fn ledger_derives_the_standard_descriptor_set() -> Result<()> {
    assert_descriptor_set(DeviceType::Ledger, LEDGER_FINGERPRINT)
}

/// The reported network comes from the app name, and Speculos runs the testnet app.
#[test]
fn a_network_the_app_is_not_for_is_reported_as_a_mismatch() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.open_device_request();
        set_selector_on(
            request.get().init_selector(),
            Network::Bitcoin,
            DeviceType::Ledger,
            LEDGER_FINGERPRINT,
        );
        let response = request.send().promise.await?;
        let opened = ok(response.get()?.get_result()?)?;
        let mismatch = opened.get_network_mismatch()?;
        assert_eq!(mismatch.get_expected()?, Network::Bitcoin);
        let reported = mismatch.get_reported()?;
        assert_eq!(reported.len(), 1);
        assert_eq!(reported.get(0)?, Network::Testnet);
        Ok(())
    })
}

#[test]
fn ledger_reports_the_same_info_over_the_session_as_discovery() -> Result<()> {
    assert_info_matches_discovery(Network::Testnet, DeviceType::Ledger, LEDGER_FINGERPRINT)
}

#[test]
fn ledger_returns_a_keypool_descriptor() -> Result<()> {
    assert_keypool_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn ledger_returns_the_address_its_xpub_derives() -> Result<()> {
    assert_address_matches_xpub_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn ledger_shows_the_address_its_xpub_derives() -> Result<()> {
    assert_shows_address_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Speculos),
    )
}

#[test]
fn ledger_signs_a_message_with_its_own_key() -> Result<()> {
    assert_signs_message_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        "m/44'/1'/0'",
        Some(Approver::Speculos),
    )
}

#[test]
fn ledger_registers_a_wallet_with_an_hmac() -> Result<()> {
    assert_registers_wallet_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        Some(Approver::Speculos),
        Registered::Hmac,
    )
}

#[test]
fn ledger_shows_an_address_of_a_registered_wallet() -> Result<()> {
    assert_registered_wallet_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        Some(Approver::Speculos),
        true,
        false,
    )
}

/// Speculos dies while signing a PSBT, so the harness runs the `ledger_signs_a_psbt`
/// tests on their own after a restart.
#[test]
fn ledger_signs_a_psbt_with_a_registered_wallet() -> Result<()> {
    assert_registered_wallet_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        Some(Approver::Speculos),
        false,
        true,
    )
}

#[test]
fn ledger_signs_a_psbt() -> Result<()> {
    assert_signs_psbt_on(
        Network::Testnet,
        DeviceType::Ledger,
        LEDGER_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Speculos),
    )
}
