use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bhwi_ipc::bhwi_capnp::{AddressFormat, DeviceType, ErrorCode, Network};

use crate::approve::Approver;
use crate::support::{
    Connection, RecordingPrompter, RefusingPrompter, Registered, assert_registers_wallet_on,
    assert_shows_address_on, assert_signs_message_on, assert_signs_psbt_on, error_code, ok, open,
    open_on, set_selector, with_server, with_server_socket,
};

const COLDCARD_FINGERPRINT: &str = "0f056943";
const COLDCARD_SOCKET: &str = "/tmp/ckcc-simulator.sock";

#[test]
fn coldcard_is_listed_as_an_emulator() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.list_devices_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            COLDCARD_FINGERPRINT,
        );
        let response = request.send().promise.await?;
        let devices = ok(response.get()?.get_result()?)?.get_devices()?;
        assert_eq!(devices.len(), 1);
        let device = devices.get(0);
        assert_eq!(device.get_fingerprint()?.to_str()?, COLDCARD_FINGERPRINT);
        assert!(device.get_is_emulated());
        assert!(device.get_model()?.to_str()?.contains("coldcard"));
        assert!(!device.get_info()?.get_version()?.to_str()?.is_empty());
        assert_eq!(device.get_network_mismatch()?.get_reported()?.len(), 0);
        Ok(())
    })
}

#[test]
fn an_unmatched_fingerprint_reports_no_device() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.open_device_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            "deadbeef",
        );
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::NoDevice
        );
        Ok(())
    })
}

#[test]
fn a_malformed_psbt_is_rejected_before_the_device_sees_it() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let mut request = device.sign_psbt_request();
        request.get().set_psbt("not-a-psbt");
        request.get().init_policy().set_auto(());
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::InvalidInput
        );
        Ok(())
    })
}

#[test]
fn a_device_can_be_selected_by_path_alone() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.open_device_request();
        {
            let mut selector = request.get().init_selector();
            selector.set_network(bhwi_ipc::bhwi_capnp::Network::Testnet);
            selector.set_device_path(COLDCARD_SOCKET);
            selector.set_include_emulators(true);
            selector.init_passphrase().set_none(());
        }
        let response = request.send().promise.await?;
        let device = ok(response.get()?.get_result()?)?.get_device()?;

        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            COLDCARD_FINGERPRINT
        );

        let mut request = client.open_device_request();
        {
            let mut selector = request.get().init_selector();
            selector.set_network(bhwi_ipc::bhwi_capnp::Network::Testnet);
            selector.set_device_path("/tmp/not-a-device.sock");
            selector.set_include_emulators(true);
            selector.init_passphrase().set_none(());
        }
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::NoDevice
        );
        Ok(())
    })
}

#[test]
fn coldcard_reports_its_fingerprint_over_the_session() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            COLDCARD_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn coldcard_derives_the_standard_descriptor_set() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let mut request = device.get_descriptors_request();
        request.get().set_account(0);
        let response = request.send().promise.await?;
        let descriptors = ok(response.get()?.get_result()?)?;
        let receive = descriptors.get_receive()?;
        let internal = descriptors.get_internal()?;
        assert_eq!(receive.len(), 4);
        assert_eq!(internal.len(), 4);
        for index in 0..receive.len() {
            let descriptor = receive.get(index)?.to_str()?;
            assert!(
                descriptor.contains(COLDCARD_FINGERPRINT),
                "{descriptor} has no key origin"
            );
            assert!(
                descriptor.contains("/0/*"),
                "{descriptor} is not a receive branch"
            );
        }
        for index in 0..internal.len() {
            let descriptor = internal.get(index)?.to_str()?;
            assert!(
                descriptor.contains("/1/*"),
                "{descriptor} is not a change branch"
            );
        }
        Ok(())
    })
}

#[test]
fn a_held_device_is_listed_as_skipped_rather_than_probed() -> Result<()> {
    with_server(|client| async move {
        let _held = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;

        let mut request = client.list_devices_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            COLDCARD_FINGERPRINT,
        );
        let response = request.send().promise.await?;
        let listed = ok(response.get()?.get_result()?)?;
        assert_eq!(listed.get_devices()?.len(), 0);
        let skipped = listed.get_skipped()?;
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped.get(0).get_path()?.to_str()?, COLDCARD_SOCKET);
        assert_eq!(skipped.get(0).get_code()?, ErrorCode::Busy);
        Ok(())
    })
}

#[test]
fn coldcard_reports_the_same_info_over_the_session_as_discovery() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.list_devices_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            COLDCARD_FINGERPRINT,
        );
        let response = request.send().promise.await?;
        let listed = ok(response.get()?.get_result()?)?.get_devices()?.get(0);
        let listed_version = listed.get_info()?.get_version()?.to_string()?;

        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let response = device.get_info_request().send().promise.await?;
        let version = ok(response.get()?.get_result()?)?
            .get_version()?
            .to_string()?;

        assert!(!version.is_empty());
        assert_eq!(version, listed_version);
        Ok(())
    })
}

#[test]
fn coldcard_returns_a_keypool_descriptor() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let mut request = device.get_keypool_request();
        {
            let mut options = request.get().init_options();
            options.set_path("m/84'/1'/0'");
            options.set_start(0);
            options.set_end(4);
            options.set_internal(false);
            options.set_address_format(AddressFormat::P2wpkh);
        }
        let response = request.send().promise.await?;
        let descriptor = ok(response.get()?.get_result()?)?.to_str()?;
        assert!(
            descriptor.contains(COLDCARD_FINGERPRINT),
            "{descriptor} has no key origin"
        );
        assert!(
            descriptor.starts_with("wpkh("),
            "{descriptor} is not native segwit"
        );
        Ok(())
    })
}

#[test]
fn coldcard_shows_the_address_its_xpub_derives() -> Result<()> {
    assert_shows_address_on(
        Network::Testnet,
        DeviceType::Coldcard,
        COLDCARD_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Coldcard),
    )
}

#[test]
fn coldcard_signs_a_message_with_its_own_key() -> Result<()> {
    assert_signs_message_on(
        Network::Testnet,
        DeviceType::Coldcard,
        COLDCARD_FINGERPRINT,
        "m/44'/1'/0'",
        Some(Approver::Coldcard),
    )
}

#[test]
fn coldcard_signs_a_psbt() -> Result<()> {
    assert_signs_psbt_on(
        Network::Testnet,
        DeviceType::Coldcard,
        COLDCARD_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Coldcard),
    )
}

/// A Coldcard answers before the user does and asks on its own screen afterwards.
#[test]
fn coldcard_registration_waits_for_the_user() -> Result<()> {
    assert_registers_wallet_on(
        Network::Testnet,
        DeviceType::Coldcard,
        COLDCARD_FINGERPRINT,
        None,
        Registered::Pending,
    )
}

#[test]
fn a_second_client_cannot_open_a_held_device() -> Result<()> {
    with_server(|client| async move {
        let _held = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let mut request = client.open_device_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            COLDCARD_FINGERPRINT,
        );
        let response = request.send().promise.await?;
        assert_eq!(error_code(response.get()?.get_result()?)?, ErrorCode::Busy);
        Ok(())
    })
}

#[test]
fn the_server_asks_the_client_for_a_passphrase() -> Result<()> {
    with_server(|client| async move {
        let passphrases = Rc::new(Cell::new(0));
        let prompter = capnp_rpc::new_client(RecordingPrompter {
            passphrases: passphrases.clone(),
            ..Default::default()
        });

        let mut request = client.open_device_request();
        {
            let mut params = request.get();
            params.set_prompter(prompter);
            let mut selector = params.init_selector();
            selector.set_network(bhwi_ipc::bhwi_capnp::Network::Testnet);
            selector.set_fingerprint(COLDCARD_FINGERPRINT);
            selector.set_include_emulators(true);
            selector
                .reborrow()
                .init_device_type()
                .set_only(DeviceType::Coldcard);
            selector.init_passphrase().set_ask_prompter(());
        }
        let response = request.send().promise.await?;
        ok(response.get()?.get_result()?)?;

        assert_eq!(passphrases.get(), 1);
        Ok(())
    })
}

#[test]
fn asking_for_a_passphrase_without_a_prompter_is_not_ready() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.open_device_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            COLDCARD_FINGERPRINT,
        );
        request
            .get()
            .get_selector()?
            .init_passphrase()
            .set_ask_prompter(());
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::NotReady
        );
        Ok(())
    })
}

#[test]
fn a_refused_prompt_keeps_the_code_the_client_raised() -> Result<()> {
    with_server(|client| async move {
        let mut request = client.open_device_request();
        request
            .get()
            .set_prompter(capnp_rpc::new_client(RefusingPrompter(
                "userCancelled: the user closed the dialog",
            )));
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            COLDCARD_FINGERPRINT,
        );
        request
            .get()
            .get_selector()?
            .init_passphrase()
            .set_ask_prompter(());
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::UserCancelled
        );
        Ok(())
    })
}

#[test]
fn management_commands_are_refused_before_the_device_is_reached() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;

        let mut setup = device.setup_device_request();
        setup.get().init_options().set_label("ipc");
        let response = setup.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::Unsupported
        );

        let mut restore = device.restore_device_request();
        restore.get().init_options().set_word_count(12);
        let response = restore.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::Unsupported
        );

        let response = device.wipe_device_request().send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::Unsupported
        );

        let response = device.toggle_passphrase_request().send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::Unsupported
        );

        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            COLDCARD_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn an_unreadable_derivation_path_is_a_bad_argument() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;

        let mut request = device.get_extended_pubkey_request();
        request.get().set_path("m/84'/not-an-index");
        request.get().set_display(false);
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::BadArgument
        );

        let mut request = device.sign_message_request();
        request.get().set_message(b"never signed");
        request.get().set_path("not a path");
        let response = request.send().promise.await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::BadArgument
        );
        Ok(())
    })
}

#[test]
fn a_released_device_can_be_opened_again() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        drop(device);

        let device = open(&client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            COLDCARD_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn a_client_that_disconnects_frees_its_device() -> Result<()> {
    with_server_socket(|socket| async move {
        let holder = Connection::open(&socket).await?;
        let _held = open(&holder.client, DeviceType::Coldcard, COLDCARD_FINGERPRINT).await?;
        let other = Connection::open(&socket).await?;

        let mut request = other.client.open_device_request();
        set_selector(
            request.get().init_selector(),
            DeviceType::Coldcard,
            COLDCARD_FINGERPRINT,
        );
        let response = request.send().promise.await?;
        assert_eq!(error_code(response.get()?.get_result()?)?, ErrorCode::Busy);

        drop(holder);
        // The server learns of the closed socket on its own schedule.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match open_on(
                &other.client,
                Network::Testnet,
                DeviceType::Coldcard,
                COLDCARD_FINGERPRINT,
            )
            .await
            {
                Ok(_) => return Ok(()),
                Err(err) if Instant::now() < deadline && err.to_string().contains("Busy") => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => return Err(err),
            }
        }
    })
}
