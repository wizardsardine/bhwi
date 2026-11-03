use std::cell::{Cell, RefCell};
use std::rc::Rc;

use anyhow::Result;
use bhwi_ipc::bhwi_capnp::{DeviceType, ErrorCode, Network, PinKind, prompter};

use crate::approve::{Approver, approving, keepkey_state, lock_keepkey};
use crate::support::{
    account_xpub, assert_address_matches_xpub_on, assert_descriptor_set,
    assert_info_matches_discovery, assert_keypool_on, assert_listed_emulator,
    assert_shows_address_on, assert_signs_message_on, assert_signs_psbt_on, error_code, ok, open,
    set_selector, with_server,
};

const KEEPKEY_FINGERPRINT: &str = "95d8f670";
const KEEPKEY_XPUB_44: &str = "tpubDCknDegFqAdP4V2AhHhs635DPe8N1aTjfKE9m2UFbdej8zmeNbtqDzK59SxnsYSRSx5uS3AujbwgANUiAk4oHmDNUKoGGkWWUY6c48WgjEx";
const KEEPKEY_XPUB_84: &str = "tpubDDPHCt8nzaf3HZXAMeUj3grAcDdXmyy6BkUZgMyhCjUDLwpdE4gdzCFH6rG9Ex9PukLURFmGYhbrZAXzP4D464g8wHa2FRz3cbB6Q6QGqno";

#[test]
fn keepkey_is_listed_as_an_emulator() -> Result<()> {
    assert_listed_emulator(DeviceType::Keepkey, KEEPKEY_FINGERPRINT, "keepkey")
}

#[test]
fn keepkey_reports_its_fingerprint_over_the_session() -> Result<()> {
    with_server(|client| async move {
        let device = open(&client, DeviceType::Keepkey, KEEPKEY_FINGERPRINT).await?;
        let response = device
            .get_master_fingerprint_request()
            .send()
            .promise
            .await?;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            KEEPKEY_FINGERPRINT
        );
        Ok(())
    })
}

#[test]
fn keepkey_returns_a_legacy_account_xpub() -> Result<()> {
    account_xpub(
        DeviceType::Keepkey,
        KEEPKEY_FINGERPRINT,
        "m/44'/1'/0'",
        KEEPKEY_XPUB_44,
    )
}

#[test]
fn keepkey_returns_a_native_segwit_account_xpub() -> Result<()> {
    account_xpub(
        DeviceType::Keepkey,
        KEEPKEY_FINGERPRINT,
        "m/84'/1'/0'",
        KEEPKEY_XPUB_84,
    )
}

#[test]
fn keepkey_derives_the_standard_descriptor_set() -> Result<()> {
    assert_descriptor_set(DeviceType::Keepkey, KEEPKEY_FINGERPRINT)
}

#[test]
fn keepkey_reports_the_same_info_over_the_session_as_discovery() -> Result<()> {
    assert_info_matches_discovery(Network::Testnet, DeviceType::Keepkey, KEEPKEY_FINGERPRINT)
}

#[test]
fn keepkey_returns_a_keypool_descriptor() -> Result<()> {
    assert_keypool_on(
        Network::Testnet,
        DeviceType::Keepkey,
        KEEPKEY_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn keepkey_returns_the_address_its_xpub_derives() -> Result<()> {
    assert_address_matches_xpub_on(
        Network::Testnet,
        DeviceType::Keepkey,
        KEEPKEY_FINGERPRINT,
        "m/84'/1'/0'",
    )
}

#[test]
fn keepkey_shows_the_address_its_xpub_derives() -> Result<()> {
    assert_shows_address_on(
        Network::Testnet,
        DeviceType::Keepkey,
        KEEPKEY_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Keepkey),
    )
}

#[test]
fn keepkey_signs_a_message_with_its_own_key() -> Result<()> {
    assert_signs_message_on(
        Network::Testnet,
        DeviceType::Keepkey,
        KEEPKEY_FINGERPRINT,
        "m/44'/1'/0'",
        Some(Approver::Keepkey),
    )
}

#[test]
fn keepkey_signs_a_psbt() -> Result<()> {
    assert_signs_psbt_on(
        Network::Testnet,
        DeviceType::Keepkey,
        KEEPKEY_FINGERPRINT,
        "m/84'/1'/0'",
        Some(Approver::Keepkey),
    )
}

const PIN: &str = "1357";
// keepkey-init's fixture, so a restore lands on KEEPKEY_FINGERPRINT again.
const MNEMONIC: &str =
    "alcohol woman abuse must during monitor noble actual mixed trade anger aisle";

#[test]
#[ignore = "requires a fresh KeepKey emulator and leaves it with a PIN"]
fn keepkey_setup_restore_and_pin_lifecycle() -> Result<()> {
    with_server(|client| async move {
        let user = KeepKeyUser::new(PIN);
        let pin_kinds = user.pin_kinds.clone();
        let recovery_requests = user.recovery_requests.clone();
        let device = {
            let response = open_request(&client, "", user).await?;
            ok(response.get()?.get_result()?)?.get_device()?
        };

        let mut request = device.setup_device_request();
        request.get().init_options().set_label("BHWI IPC");
        let response = approving(Some(Approver::Keepkey), || request.send().promise).await??;
        ok(response.get()?.get_result()?)?;
        assert_eq!(pin_kinds.take(), [PinKind::ChooseNew, PinKind::ConfirmNew]);

        let request = device.wipe_device_request();
        let response = approving(Some(Approver::Keepkey), || request.send().promise).await??;
        ok(response.get()?.get_result()?)?;

        let mut request = device.restore_device_request();
        {
            let mut options = request.get().init_options();
            options.set_label("BHWI IPC restored");
            options.set_word_count(12);
        }
        let response = approving(Some(Approver::Keepkey), || request.send().promise).await??;
        ok(response.get()?.get_result()?)?;
        assert_eq!(pin_kinds.take(), [PinKind::ChooseNew, PinKind::ConfirmNew]);
        assert!(recovery_requests.get() >= 12);
        assert_eq!(fingerprint_of(&device).await?, KEEPKEY_FINGERPRINT);
        drop(device);

        lock_keepkey().await?;
        let response = open_request(&client, KEEPKEY_FINGERPRINT, KeepKeyUser::new("2468")).await?;
        assert_eq!(
            error_code(response.get()?.get_result()?)?,
            ErrorCode::WrongPin
        );

        let user = KeepKeyUser::new(PIN);
        let pin_kinds = user.pin_kinds.clone();
        let response = open_request(&client, KEEPKEY_FINGERPRINT, user).await?;
        let device = ok(response.get()?.get_result()?)?.get_device()?;
        assert_eq!(pin_kinds.take(), [PinKind::Current]);
        assert_eq!(fingerprint_of(&device).await?, KEEPKEY_FINGERPRINT);
        Ok(())
    })
}

async fn open_request(
    client: &bhwi_ipc::bhwi_capnp::bhwi::Client,
    fingerprint: &str,
    user: KeepKeyUser,
) -> Result<capnp::capability::Response<bhwi_ipc::bhwi_capnp::bhwi::open_device_results::Owned>> {
    let mut request = client.open_device_request();
    set_selector(
        request.get().init_selector(),
        DeviceType::Keepkey,
        fingerprint,
    );
    request.get().set_prompter(capnp_rpc::new_client(user));
    Ok(request.send().promise.await?)
}

async fn fingerprint_of(device: &bhwi_ipc::bhwi_capnp::device::Client) -> Result<String> {
    let response = device
        .get_master_fingerprint_request()
        .send()
        .promise
        .await?;
    Ok(ok(response.get()?.get_result()?)?.to_string()?)
}

/// Answers PIN and recovery prompts as a user reading the KeepKey's screen
/// would, with the screen read over the debuglink.
struct KeepKeyUser {
    pin: &'static str,
    pin_kinds: Rc<RefCell<Vec<PinKind>>>,
    recovery_requests: Rc<Cell<usize>>,
}

impl KeepKeyUser {
    fn new(pin: &'static str) -> Self {
        Self {
            pin,
            pin_kinds: Rc::default(),
            recovery_requests: Rc::default(),
        }
    }
}

fn failed(err: impl std::fmt::Display) -> capnp::Error {
    capnp::Error::failed(err.to_string())
}

impl prompter::Server for KeepKeyUser {
    async fn request_pin(
        self: Rc<Self>,
        params: prompter::RequestPinParams,
        mut results: prompter::RequestPinResults,
    ) -> Result<(), capnp::Error> {
        self.pin_kinds.borrow_mut().push(params.get()?.get_kind()?);
        let matrix = keepkey_state()
            .await
            .map_err(failed)?
            .matrix
            .ok_or_else(|| failed("no PIN matrix on the screen"))?;
        // A position is where the digit sits in the scrambled keypad, 1 to 9.
        let positions = self
            .pin
            .chars()
            .map(|digit| {
                matrix
                    .find(digit)
                    .map(|index| char::from(b'1' + index as u8))
                    .ok_or_else(|| failed(format!("{digit} is not on the keypad")))
            })
            .collect::<Result<String, _>>()?;
        results.get().set_positions(&positions);
        Ok(())
    }

    async fn request_recovery_character(
        self: Rc<Self>,
        params: prompter::RequestRecoveryCharacterParams,
        mut results: prompter::RequestRecoveryCharacterResults,
    ) -> Result<(), capnp::Error> {
        self.recovery_requests.set(self.recovery_requests.get() + 1);
        let params = params.get()?;
        let word_position = params.get_word_position() as usize;
        let character_position = params.get_character_position() as usize;
        let words: Vec<&str> = MNEMONIC.split_whitespace().collect();
        let word = words
            .get(word_position)
            .ok_or_else(|| failed(format!("no word {word_position} in the fixture")))?;
        let state = keepkey_state().await.map_err(failed)?;
        let mut input = results.get().init_input();
        // The KeepKey completes a word once its prefix is unique.
        if state.recovery_auto_completed_word.as_deref() == Some(word)
            || character_position >= word.len()
        {
            if word_position + 1 == words.len() {
                input.set_done(());
            } else {
                input.set_next_word(());
            }
            return Ok(());
        }
        // The screen shows a scrambled alphabet; the user types the letter
        // standing where the word's letter sits in a to z.
        let cipher = state
            .recovery_cipher
            .ok_or_else(|| failed("no recovery cipher on the screen"))?;
        let letter = word.as_bytes()[character_position];
        let shown = cipher
            .as_bytes()
            .get(usize::from(letter - b'a'))
            .ok_or_else(|| failed("the recovery cipher is not 26 letters"))?;
        input.set_character(char::from(*shown).to_string());
        Ok(())
    }
}
