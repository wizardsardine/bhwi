use anyhow::Result;
use bhwi_ipc::bhwi_capnp::{DeviceType, ErrorCode, Network};

use crate::support::{
    RecordingPrompter, assert_address_matches_xpub_on, assert_descriptor_set,
    assert_info_matches_discovery, assert_keypool_on, assert_listed_emulator,
    assert_registered_wallet_on, assert_shows_address_on, assert_signs_message_on,
    assert_signs_psbt_on, error_code, ok, open, set_selector, with_server,
};

// The simulator restores a fixed mnemonic, so its fingerprint is deterministic.
const BITBOX_FINGERPRINT: &str = "4c00739d";

#[test]
fn bitbox_is_listed_as_an_emulator() -> Result<()> {
    assert_listed_emulator(DeviceType::Bitbox02, BITBOX_FINGERPRINT, "bitbox")
}

#[test]
fn bitbox_reports_its_fingerprint_over_the_session() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Bitbox02, BITBOX_FINGERPRINT).await?;
        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            BITBOX_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn bitbox_derives_the_standard_descriptor_set() -> Result<()> {
    assert_descriptor_set(DeviceType::Bitbox02, BITBOX_FINGERPRINT)
}

#[test]
fn bitbox_reports_the_same_info_over_the_session_as_discovery() -> Result<()> {
    assert_info_matches_discovery(Network::Testnet, DeviceType::Bitbox02, BITBOX_FINGERPRINT)
}

#[test]
fn bitbox_returns_a_keypool_descriptor() -> Result<()> {
    assert_keypool_on(
        Network::Testnet,
        DeviceType::Bitbox02,
        BITBOX_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn bitbox_returns_the_address_its_xpub_derives() -> Result<()> {
    assert_address_matches_xpub_on(
        Network::Testnet,
        DeviceType::Bitbox02,
        BITBOX_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn bitbox_shows_the_address_its_xpub_derives() -> Result<()> {
    assert_shows_address_on(
        Network::Testnet,
        DeviceType::Bitbox02,
        BITBOX_FINGERPRINT,
        "m/84'/1'/0'",
        None,
    )
}

#[test]
fn bitbox_signs_a_message_with_its_own_key() -> Result<()> {
    assert_signs_message_on(
        Network::Testnet,
        DeviceType::Bitbox02,
        BITBOX_FINGERPRINT,
        "m/84'/1'/0'",
        None,
    )
}

#[test]
fn bitbox_signs_a_psbt() -> Result<()> {
    assert_signs_psbt_on(
        Network::Testnet,
        DeviceType::Bitbox02,
        BITBOX_FINGERPRINT,
        "m/84'/1'/0'",
        None,
    )
}

#[test]
fn bitbox_registers_a_wallet_and_shows_its_address() -> Result<()> {
    assert_registered_wallet_on(
        Network::Testnet,
        DeviceType::Bitbox02,
        BITBOX_FINGERPRINT,
        None,
        true,
        false,
    )
}

#[test]
fn a_host_supplied_passphrase_is_refused() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.open_device_request();
        {
            let mut selector = request.get().init_selector();
            set_selector(
                selector.reborrow(),
                DeviceType::Bitbox02,
                BITBOX_FINGERPRINT,
            );
            selector.init_passphrase().set_value("host secret");
        }
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::BadArgument
        );
        Ok(())
    })
}

#[test]
#[ignore = "requires a fresh, uninitialized BitBox02 simulator and wipes it"]
fn bitbox_pairs_then_sets_up_toggles_and_wipes() -> Result<()> {
    with_server(|client| async move {
        let prompter = RecordingPrompter::default();
        let pairing_codes = prompter.pairing_codes.clone();
        let mut request = client.open_device_request();
        set_selector(request.get().init_selector(), DeviceType::Bitbox02, "");
        request.get().set_prompter(capnp_rpc::new_client(prompter));
        let response = request.send().promise.await?;
        let device = ok(response.get()?.get_result()?)?.get_device()?;

        let mut request = device.setup_device_request();
        request.get().init_options().set_label("BHWI IPC");
        let response = request.send().promise.await?;
        ok(response.get()?.get_result()?)?;
        // The simulator confirms pairing itself, so it never shows a code.
        assert!(pairing_codes.borrow().is_empty());

        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(ok(response.get()?.get_result()?)?.len(), 8);

        for _ in 0..2 {
            let response = device.toggle_passphrase_request().send().promise.await?;
            ok(response.get()?.get_result()?)?;
        }
        let response = device.wipe_device_request().send().promise.await?;
        ok(response.get()?.get_result()?)?;
        Ok(())
    })
}
