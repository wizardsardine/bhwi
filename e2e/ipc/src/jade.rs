use anyhow::Result;
use bhwi_ipc::bhwi_capnp::{AddressFormat, DeviceType, ErrorCode, Network::Testnet};
use bitcoin::{
    bip32::{Fingerprint, Xpub},
    psbt::Psbt,
};
use std::str::FromStr;

use crate::support::{
    Registered, assert_info_matches_discovery, assert_keypool_on, assert_registers_wallet_on,
    error_code, ok, open, set_selector, single_input_psbt, with_server,
};

const JADE_FINGERPRINT: &str = "e3ebcc79";
const JADE_XPUB_44: &str = "tpubDCKD5cdxMEFd2i4cNa3PJUbUHMsGDxsnfqjxVpMoG1ymWYUQUaZzTcHQo3JwYgaKe2FyKGA2FzGPSVczBoAiHGyERuA1mZ2UkGKufEnUxKk";
const JADE_ADDRESS_84_0: &str = "tb1q9t9pgtdsyf6r8ks7gnxvj99sea4d3nmjl0tnzu";
const JADE_MESSAGE_SIGNATURE: &str =
    "H+SvKg15TSz+2C5ra6Q8/e8BaImOZVEeS0rOL6GCEt4vO+4xRRt+YYKavSqgAJBYZaGEiTqr7f9imyyElMNhYXU=";

#[test]
fn jade_returns_an_account_xpub() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Jade, JADE_FINGERPRINT).await?;
        let mut request = device.get_extended_pubkey_request();
        request.get().set_path("m/44'/1'/0'");
        request.get().set_display(false);
        let response = request.send().promise.await?;
        assert_eq!(ok(response.get()?.get_result()?)?.to_str()?, JADE_XPUB_44);
        Ok(())
    })
}

#[test]
fn jade_shows_an_address_for_a_path() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Jade, JADE_FINGERPRINT).await?;
        let mut request = device.display_address_request();
        {
            let mut path = request.get().init_target().init_path();
            path.set_path("m/84'/1'/0'/0/0");
            path.set_display(false);
            path.set_address_format(AddressFormat::P2wpkh);
        }
        let response = request.send().promise.await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            JADE_ADDRESS_84_0
        );
        Ok(())
    })
}

#[test]
fn jade_reports_the_same_info_over_the_session_as_discovery() -> Result<()> {
    assert_info_matches_discovery(Testnet, DeviceType::Jade, JADE_FINGERPRINT)
}

#[test]
fn jade_returns_a_keypool_descriptor() -> Result<()> {
    assert_keypool_on(Testnet, DeviceType::Jade, JADE_FINGERPRINT, "m/84'/1'/0'")
}

#[test]
fn jade_registers_a_wallet() -> Result<()> {
    assert_registers_wallet_on(
        Testnet,
        DeviceType::Jade,
        JADE_FINGERPRINT,
        None,
        Registered::NoHmac,
    )
}

#[test]
fn jade_signs_a_message() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Jade, JADE_FINGERPRINT).await?;
        let mut request = device.sign_message_request();
        request.get().set_message(b"hello");
        request.get().set_path("m/44'/1'/0'");
        let response = request.send().promise.await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            JADE_MESSAGE_SIGNATURE
        );
        Ok(())
    })
}

#[test]
fn jade_signs_a_psbt_through_the_signing_capability() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Jade, JADE_FINGERPRINT).await?;

        let mut request = device.get_extended_pubkey_request();
        request.get().set_path("m/84'/1'/0'");
        request.get().set_display(false);
        let response = request.send().promise.await?;
        let xpub = Xpub::from_str(ok(response.get()?.get_result()?)?.to_str()?)?;
        let fingerprint = Fingerprint::from_str(JADE_FINGERPRINT)?;
        let (psbt, input_pubkey) =
            single_input_psbt(&xpub, fingerprint, "m/84'/1'/0'", bitcoin::Network::Testnet)?;

        let mut request = device.sign_psbt_request();
        request.get().set_psbt(psbt.to_string());
        request.get().init_policy().set_auto(());
        let response = request.send().promise.await?;
        let signing = ok(response.get()?.get_result()?)?;

        let response = signing.result_request().send().promise.await?;
        let response = ok(response.get()?.get_result()?)?;
        assert!(response.get_signed());
        let signed = Psbt::from_str(response.get_psbt()?.to_str()?)?;
        assert_eq!(signed.inputs.len(), 1);
        assert!(signed.inputs[0].partial_sigs.contains_key(&input_pubkey));
        Ok(())
    })
}

#[test]
fn a_signing_run_can_only_be_collected_once() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Jade, JADE_FINGERPRINT).await?;
        let signing = start_signing(&device).await?;

        let first = signing.result_request().send().promise.await?;
        ok(first.get()?.get_result()?)?;
        let second = signing.result_request().send().promise.await?;
        assert_eq!(
            error_code(second.get()?.get_result()?)?,
            ErrorCode::BadArgument
        );
        Ok(())
    })
}

/// Cutting a command short drops the connection, which reboots the emulator and
/// clears its seed.
#[test]
#[ignore = "requires a fresh Jade emulator afterwards"]
fn an_aborted_signing_run_reports_the_cancellation() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Jade, JADE_FINGERPRINT).await?;
        let signing = start_signing(&device).await?;

        signing.abort_request().send().promise.await?;
        let response = signing.result_request().send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::UserCancelled
        );

        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::NotReady
        );
        Ok(())
    })
}

async fn start_signing(
    device: &bhwi_ipc::bhwi_capnp::device::Client,
) -> Result<bhwi_ipc::bhwi_capnp::signing::Client> {
    let mut request = device.get_extended_pubkey_request();
    request.get().set_path("m/84'/1'/0'");
    request.get().set_display(false);
    let response = request.send().promise.await?;
    let xpub = Xpub::from_str(ok(response.get()?.get_result()?)?.to_str()?)?;
    let (psbt, _) = single_input_psbt(
        &xpub,
        Fingerprint::from_str(JADE_FINGERPRINT)?,
        "m/84'/1'/0'",
        bitcoin::Network::Testnet,
    )?;

    let mut request = device.sign_psbt_request();
    request.get().set_psbt(psbt.to_string());
    request.get().init_policy().set_auto(());
    let response = request.send().promise.await?;
    ok(response.get()?.get_result()?)
}

#[test]
fn jade_is_listed_with_taproot_support_reported() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.list_devices_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Jade,
            JADE_FINGERPRINT,
        );
        let response = request.send().promise.await?;
        let devices = ok(response.get()?.get_result()?)?.get_devices()?;
        assert_eq!(devices.len(), 1);
        // The Jade firmware bhwi supports has no taproot signing.
        assert!(!devices.get(0).get_can_sign_taproot());
        Ok(())
    })
}
