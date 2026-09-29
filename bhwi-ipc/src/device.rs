use std::rc::Rc;
use std::str::FromStr;

use bhwi_async::descriptors::{
    GetKeypoolOptions, PubkeyDescriptors, get_keypool_descriptor, get_pubkey_descriptors,
};
use bhwi_async::device::{DeviceType, networks_string, supports_device_management};
use bhwi_async::display_address::display_address_context;
use bhwi_async::display_address::display_address_from_descriptor;
#[cfg(feature = "bitbox")]
use bhwi_async::management::SetupEntropy;
#[cfg(feature = "keepkey")]
use bhwi_async::management::keepkey_pin_context_from_positions;
use bhwi_async::signing::message_signature;
use bhwi_async::{
    DeviceBackup, DeviceContext, DisplayAddress, RestoreOptions, SetupOptions, WalletRegistration,
};
use bitcoin::Network;
use bitcoin::base64::prelude::{BASE64_STANDARD, Engine as _};
use bitcoin::psbt::Psbt;
use miniscript::descriptor::WalletPolicy;

#[cfg(feature = "keepkey")]
use crate::bhwi_capnp::PinKind;
use crate::bhwi_capnp::{address_target, device, signing, signing_policy};
use crate::convert;
use crate::error::{self, ErrorCode, Failure};
#[cfg(feature = "keepkey")]
use crate::prompt::Prompter;
use crate::session::Session;
use crate::signing::SigningServer;

/// Serves the `Device` capability for one held device.
pub struct DeviceServer {
    session: Rc<Session>,
}

impl DeviceServer {
    /// Creates the capability for a held device's session.
    pub fn new(session: Rc<Session>) -> Self {
        Self { session }
    }
}

impl device::Server for DeviceServer {
    async fn get_info(
        self: Rc<Self>,
        _: device::GetInfoParams,
        mut results: device::GetInfoResults,
    ) -> Result<(), capnp::Error> {
        let outcome = async {
            self.session.ensure_open()?;
            let mut device = self.session.lock_open().await?;
            device.info().await.map_err(|err| error::device(&err))
        }
        .await;
        error::reply(results.get().init_result(), outcome, |builder, info| {
            convert::fill_info(&info, builder.init_ok())
        })
    }

    async fn get_master_fingerprint(
        self: Rc<Self>,
        _: device::GetMasterFingerprintParams,
        mut results: device::GetMasterFingerprintResults,
    ) -> Result<(), capnp::Error> {
        let outcome = async {
            self.session.ensure_open()?;
            let mut device = self.session.lock_open().await?;
            device
                .fingerprint()
                .await
                .map_err(|err| error::device(&err))
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |mut builder, fingerprint| builder.set_ok(fingerprint.to_string().as_str()),
        )
    }

    async fn get_extended_pubkey(
        self: Rc<Self>,
        params: device::GetExtendedPubkeyParams,
        mut results: device::GetExtendedPubkeyResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let path = convert::derivation_path(request.get_path()?.to_str()?)?;
            let display = request.get_display();
            let mut device = self.session.lock_open().await?;
            refuse_wrong_network(&mut device, self.session.network).await?;
            device
                .device()
                .get_extended_pubkey(path, display)
                .await
                .map_err(|err| error::device(&err))
        }
        .await;
        error::reply(results.get().init_result(), outcome, |mut builder, xpub| {
            builder.set_ok(xpub.to_string().as_str())
        })
    }

    async fn get_descriptors(
        self: Rc<Self>,
        params: device::GetDescriptorsParams,
        mut results: device::GetDescriptorsResults,
    ) -> Result<(), capnp::Error> {
        let account = params.get()?.get_account();
        let outcome = async {
            self.session.ensure_open()?;
            let network = self.session.network;
            let mut device = self.session.lock_open().await?;
            refuse_wrong_network(&mut device, network).await?;
            let fingerprint = device
                .fingerprint()
                .await
                .map_err(|err| error::device(&err))?;
            get_pubkey_descriptors(device.device().as_mut(), fingerprint, account, network)
                .await
                .map_err(|err| descriptor_error(err, ErrorCode::Other))
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |builder, PubkeyDescriptors { receive, internal }| {
                let mut descriptors = builder.init_ok();
                {
                    let mut list = descriptors.reborrow().init_receive(receive.len() as u32);
                    for (index, descriptor) in receive.iter().enumerate() {
                        list.set(index as u32, format!("{descriptor:#}").as_str());
                    }
                }
                let mut list = descriptors.init_internal(internal.len() as u32);
                for (index, descriptor) in internal.iter().enumerate() {
                    list.set(index as u32, format!("{descriptor:#}").as_str());
                }
                Ok(())
            },
        )
    }

    async fn get_keypool(
        self: Rc<Self>,
        params: device::GetKeypoolParams,
        mut results: device::GetKeypoolResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let request = request.get_options()?;
            let options = GetKeypoolOptions {
                path: convert::derivation_path(request.get_path()?.to_str()?)?,
                start: request.get_start(),
                end: request.get_end(),
                internal: request.get_internal(),
                descriptor_type: convert::descriptor_type(request.get_address_format()?)?,
                network: self.session.network,
            };
            let mut device = self.session.lock_open().await?;
            refuse_wrong_network(&mut device, self.session.network).await?;
            let fingerprint = device
                .fingerprint()
                .await
                .map_err(|err| error::device(&err))?;
            get_keypool_descriptor(device.device().as_mut(), fingerprint, &options)
                .await
                .map_err(|err| descriptor_error(err, ErrorCode::BadArgument))
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |mut builder, descriptor| builder.set_ok(format!("{descriptor:#}").as_str()),
        )
    }

    async fn sign_message(
        self: Rc<Self>,
        params: device::SignMessageParams,
        mut results: device::SignMessageResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let message = request.get_message()?.to_vec();
            let path = convert::derivation_path(request.get_path()?.to_str()?)?;
            let mut device = self.session.lock_open().await?;
            let (header, signature) = device
                .device()
                .sign_message(&message, path)
                .await
                .map_err(|err| error::device(&err))?;
            Ok(message_signature(
                self.session.device_type,
                header,
                &signature,
            ))
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |mut builder, payload| builder.set_ok(BASE64_STANDARD.encode(payload).as_str()),
        )
    }

    async fn display_address(
        self: Rc<Self>,
        params: device::DisplayAddressParams,
        mut results: device::DisplayAddressResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let target = request.get_target()?;
            let mut device = self.session.lock_open().await?;
            let (address, context) = match target.which()? {
                address_target::Which::Path(path) => (
                    DisplayAddress::ByPath {
                        path: convert::derivation_path(path.get_path()?.to_str()?)?,
                        display: path.get_display(),
                        address_format: convert::address_format(path.get_address_format()?),
                    },
                    None,
                ),
                address_target::Which::DescriptorName(named) => {
                    let name = named.get_name()?.to_string()?;
                    let context = descriptor_context(
                        self.session.device_type,
                        &name,
                        named.get_policy()?.to_str()?,
                        named.get_hmac()?,
                    )?;
                    (
                        DisplayAddress::ByDescriptor {
                            index: named.get_index(),
                            change: named.get_change(),
                            display: named.get_display(),
                            descriptor_name: name,
                        },
                        context,
                    )
                }
                address_target::Which::Descriptor(descriptor) => {
                    let address =
                        display_address_from_descriptor(&mut device, descriptor?.to_str()?)
                            .await
                            .map_err(display_address_error)?;
                    (address, None)
                }
            };
            let shown = match &address {
                DisplayAddress::ByPath { display, .. }
                | DisplayAddress::ByDescriptor { display, .. } => *display,
                DisplayAddress::ByMultisig(_) => true,
            };
            let warning = network_mismatch(&mut device, self.session.network).await?;
            if let (Some(message), false) = (&warning, shown) {
                return Err(Failure::new(ErrorCode::WrongNetwork, message));
            }
            let address = device
                .device()
                .display_address(address, context)
                .await
                .map_err(|err| error::device(&err))?;
            Ok((address, warning))
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |mut builder, (address, warning)| {
                if let Some(warning) = warning {
                    builder.reborrow().init_warnings(1).set(0, warning.as_str());
                }
                builder.set_ok(address.as_str())
            },
        )
    }

    async fn register_wallet(
        self: Rc<Self>,
        params: device::RegisterWalletParams,
        mut results: device::RegisterWalletResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let name = request.get_name()?.to_string()?;
            let policy = request.get_policy()?.to_string()?;
            let mut device = self.session.lock_open().await?;
            refuse_wrong_network(&mut device, self.session.network).await?;
            device
                .device()
                .register_wallet(&name, &policy)
                .await
                .map_err(|err| error::device(&err))
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |builder, registration| {
                let mut response = builder.init_ok();
                match registration {
                    WalletRegistration::Complete { hmac } => {
                        let mut complete = response.init_complete();
                        if let Some(hmac) = hmac {
                            complete.set_hmac(&hmac);
                        }
                    }
                    WalletRegistration::PendingUserConfirmation => {
                        response.set_pending_user_confirmation(());
                    }
                }
                Ok(())
            },
        )
    }

    async fn sign_psbt(
        self: Rc<Self>,
        params: device::SignPsbtParams,
        mut results: device::SignPsbtResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let psbt = Psbt::from_str(request.get_psbt()?.to_str()?.trim())
                .map_err(|err| Failure::new(ErrorCode::InvalidInput, err))?;
            let context = match request.get_policy()?.which()? {
                signing_policy::Which::Auto(()) => None,
                signing_policy::Which::Registered(registered) => Some(signing_context(
                    self.session.device_type,
                    registered.get_name()?.to_string()?,
                    registered.get_policy()?.to_str()?,
                    registered.get_hmac()?,
                )?),
            };
            refuse_wrong_network(&mut *self.session.lock_open().await?, self.session.network)
                .await?;
            Ok::<_, Failure>(SigningServer::spawn(self.session.clone(), psbt, context))
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |mut builder, signing| {
                let client: signing::Client = capnp_rpc::new_client(signing);
                builder.set_ok(client)
            },
        )
    }

    async fn setup_device(
        self: Rc<Self>,
        params: device::SetupDeviceParams,
        mut results: device::SetupDeviceResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let label = request.get_options()?.get_label()?.to_string()?;
            let context = setup_context(self.session.device_type, self.session.is_emulated)?;
            let mut device = self.session.lock_open().await?;
            device
                .setup_device(
                    SetupOptions {
                        label,
                        backup_passphrase: String::new(),
                    },
                    Some(context),
                )
                .await
                .map_err(|err| error::device(&err))
        }
        .await;
        error::reply(results.get().init_result(), outcome, success)
    }

    async fn restore_device(
        self: Rc<Self>,
        params: device::RestoreDeviceParams,
        mut results: device::RestoreDeviceResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            self.session.ensure_open()?;
            let request = request.get_options()?;
            let options = RestoreOptions {
                label: request.get_label()?.to_string()?,
                word_count: request.get_word_count(),
            };
            let context = restore_context(self.session.device_type)?;
            let mut device = self.session.lock_open().await?;
            device
                .restore_device(options, Some(context))
                .await
                .map_err(|err| error::device(&err))
        }
        .await;
        error::reply(results.get().init_result(), outcome, success)
    }

    async fn wipe_device(
        self: Rc<Self>,
        _: device::WipeDeviceParams,
        mut results: device::WipeDeviceResults,
    ) -> Result<(), capnp::Error> {
        let outcome = async {
            self.session.ensure_open()?;
            manageable(self.session.device_type, "wipe")?;
            let mut device = self.session.lock_open().await?;
            device
                .wipe_device()
                .await
                .map_err(|err| error::device(&err))
        }
        .await;
        error::reply(results.get().init_result(), outcome, success)
    }

    async fn backup_device(
        self: Rc<Self>,
        _: device::BackupDeviceParams,
        mut results: device::BackupDeviceResults,
    ) -> Result<(), capnp::Error> {
        let outcome = async {
            self.session.ensure_open()?;
            let mut device = self.session.lock_open().await?;
            device
                .device()
                .backup_device()
                .await
                .map_err(|err| error::device(&err))
        }
        .await;
        error::reply(results.get().init_result(), outcome, |builder, backup| {
            let mut response = builder.init_ok();
            match backup {
                DeviceBackup::Complete => response.set_complete(()),
                DeviceBackup::File(bytes) => response.set_file(&bytes),
            }
            Ok(())
        })
    }

    async fn toggle_passphrase(
        self: Rc<Self>,
        _: device::TogglePassphraseParams,
        mut results: device::TogglePassphraseResults,
    ) -> Result<(), capnp::Error> {
        let outcome = async {
            self.session.ensure_open()?;
            manageable(self.session.device_type, "toggle-passphrase")?;
            let mut device = self.session.lock_open().await?;
            #[cfg(feature = "keepkey")]
            let needs_pin_sent = self.session.device_type == DeviceType::KeepKey
                && device
                    .device()
                    .get_info()
                    .await
                    .map_err(|err| error::device(&err))?
                    .needs_pin_sent
                    == Some(true);
            #[cfg(feature = "keepkey")]
            if needs_pin_sent && !self.session.prompter.is_set() {
                return Err(Failure::new(
                    ErrorCode::NotReady,
                    "the KeepKey asks for its PIN after the toggle, and the client passed no Prompter",
                ));
            }
            let success = device
                .toggle_passphrase()
                .await
                .map_err(|err| error::device(&err))?;
            #[cfg(feature = "keepkey")]
            if needs_pin_sent {
                send_keepkey_pin(&self.session.prompter, &mut device).await?;
            }
            Ok::<_, Failure>(success)
        }
        .await;
        error::reply(results.get().init_result(), outcome, success)
    }
}

fn success(
    builder: crate::bhwi_capnp::result::Builder<'_, crate::bhwi_capnp::success::Owned>,
    success: bool,
) -> Result<(), capnp::Error> {
    builder.init_ok().set_success(success);
    Ok(())
}

/// The KeepKey interpreter ends `TogglePassphrase` on the PIN request instead of
/// routing it to the host, so the device is left holding an unanswered keypad.
#[cfg(feature = "keepkey")]
async fn send_keepkey_pin(
    prompter: &Prompter,
    device: &mut bhwi_async::device::Device,
) -> Result<(), Failure> {
    if !device
        .device()
        .prompt_pin()
        .await
        .map_err(|err| error::device(&err))?
    {
        return Err(Failure::new(
            ErrorCode::NotReady,
            "the device did not ask for a PIN",
        ));
    }
    let positions = prompter.ask_pin(PinKind::Current).await?;
    let context =
        keepkey_pin_context_from_positions(positions).map_err(|err| error::device(&err))?;
    if !device
        .device()
        .send_pin(Some(context))
        .await
        .map_err(|err| error::device(&err))?
    {
        return Err(Failure::new(
            ErrorCode::NotReady,
            "the device rejected the PIN",
        ));
    }
    Ok(())
}

fn manageable(device_type: DeviceType, command: &str) -> Result<(), Failure> {
    if supports_device_management(device_type) {
        return Ok(());
    }
    Err(Failure::new(
        ErrorCode::Unsupported,
        format!("device {command} is not supported for {device_type}"),
    ))
}

/// A device that reports no networks makes no claim, so Coldcard, BitBox02 and
/// Specter-DIY never mismatch, and Trezor echoes back the requested network.
async fn network_mismatch(
    device: &mut bhwi_async::device::Device,
    network: Network,
) -> Result<Option<String>, Failure> {
    let mismatch = device
        .network_mismatch(network)
        .await
        .map_err(|err| error::device(&err))?;
    Ok(mismatch.map(|mismatch| {
        format!(
            "the device is on {}, not {}",
            networks_string(&mismatch.reported),
            mismatch.expected
        )
    }))
}

async fn refuse_wrong_network(
    device: &mut bhwi_async::device::Device,
    network: Network,
) -> Result<(), Failure> {
    match network_mismatch(device, network).await? {
        Some(message) => Err(Failure::new(ErrorCode::WrongNetwork, message)),
        None => Ok(()),
    }
}

fn display_address_error(err: bhwi_async::display_address::DisplayAddressError) -> Failure {
    use bhwi_async::display_address::DisplayAddressError;
    match err {
        DisplayAddressError::Device(err) => error::device(&err),
        err => error::bad_argument(err),
    }
}

fn descriptor_error(err: bhwi_async::descriptors::DescriptorError, fallback: ErrorCode) -> Failure {
    use bhwi_async::descriptors::DescriptorError;
    match err {
        DescriptorError::Device(err) => error::device(&err),
        err => Failure::new(fallback, err),
    }
}

fn descriptor_context(
    device_type: DeviceType,
    name: &str,
    policy: &str,
    hmac: &[u8],
) -> Result<Option<DeviceContext>, Failure> {
    display_address_context(
        device_type,
        name,
        optional_policy(policy)?,
        optional_hmac(hmac)?,
    )
    .map_err(error::bad_argument)
}

#[cfg_attr(
    not(all(feature = "ledger", feature = "specter")),
    allow(unused_variables)
)]
fn signing_context(
    device_type: DeviceType,
    name: String,
    policy: &str,
    hmac: &[u8],
) -> Result<DeviceContext, Failure> {
    let policy = optional_policy(policy)?
        .ok_or_else(|| error::bad_argument("a registered signing policy needs its descriptor"))?;
    let hmac = optional_hmac(hmac)?;
    match device_type {
        #[cfg(feature = "ledger")]
        DeviceType::Ledger => Ok(bhwi_async::signing::ledger::registered_context(
            name, policy, hmac,
        )),
        #[cfg(feature = "specter")]
        DeviceType::Specter if hmac.is_none() => Ok(DeviceContext::Specter { policy }),
        #[cfg(feature = "specter")]
        DeviceType::Specter => Err(error::bad_argument(
            "Specter-DIY signing takes a policy without an hmac",
        )),
        _ => Err(Failure::new(
            ErrorCode::Unsupported,
            format!("registered signing policies are not supported for {device_type}"),
        )),
    }
}

fn optional_policy(policy: &str) -> Result<Option<WalletPolicy>, Failure> {
    if policy.is_empty() {
        return Ok(None);
    }
    WalletPolicy::from_str(policy)
        .map(Some)
        .map_err(error::bad_argument)
}

fn optional_hmac(hmac: &[u8]) -> Result<Option<[u8; 32]>, Failure> {
    if hmac.is_empty() {
        return Ok(None);
    }
    convert::hmac(hmac).map(Some)
}

fn setup_context(
    device_type: DeviceType,
    #[cfg_attr(not(feature = "bitbox"), allow(unused_variables))] is_emulated: bool,
) -> Result<DeviceContext, Failure> {
    match device_type {
        #[cfg(feature = "bitbox")]
        DeviceType::BitBox02 => {
            let (timestamp, timezone_offset) = host_clock()?;
            Ok(bhwi_async::management::bitbox_setup_context(
                bhwi_async::management::bitbox_setup_mode(
                    is_emulated,
                    SetupEntropy::new(host_entropy()?),
                ),
                timestamp,
                timezone_offset,
            ))
        }
        #[cfg(feature = "keepkey")]
        DeviceType::KeepKey => Ok(bhwi_async::management::keepkey_setup_context(
            host_entropy()?
        )),
        #[cfg(feature = "trezor")]
        DeviceType::Trezor => Ok(bhwi_async::management::trezor_setup_context(host_entropy()?)),
        other => Err(Failure::new(
            ErrorCode::Unsupported,
            format!("device setup is not supported for {other}"),
        )),
    }
}

fn restore_context(device_type: DeviceType) -> Result<DeviceContext, Failure> {
    match device_type {
        #[cfg(feature = "bitbox")]
        DeviceType::BitBox02 => {
            let (timestamp, timezone_offset) = host_clock()?;
            Ok(bhwi_async::management::bitbox_restore_context(
                timestamp,
                timezone_offset,
            ))
        }
        #[cfg(feature = "keepkey")]
        DeviceType::KeepKey => Ok(bhwi_async::management::keepkey_restore_context(
            u2f_counter()?,
        )),
        #[cfg(feature = "trezor")]
        DeviceType::Trezor => Ok(bhwi_async::management::trezor_restore_context(
            u2f_counter()?
        )),
        other => Err(Failure::new(
            ErrorCode::Unsupported,
            format!("device restore is not supported for {other}"),
        )),
    }
}

/// The U2F counter must never go backwards, and the clock never does.
#[cfg(any(feature = "keepkey", feature = "trezor"))]
fn u2f_counter() -> Result<u32, Failure> {
    Ok(host_clock()?.0)
}

/// Seconds since the Unix epoch, and seconds east of UTC.
#[cfg(any(feature = "bitbox", feature = "keepkey", feature = "trezor"))]
fn host_clock() -> Result<(u32, i32), Failure> {
    let now = chrono::Local::now();
    let timestamp = u32::try_from(now.timestamp())
        .map_err(|_| Failure::new(ErrorCode::Other, "the host clock does not fit in u32"))?;
    Ok((timestamp, now.offset().local_minus_utc()))
}

#[cfg(any(feature = "bitbox", feature = "keepkey", feature = "trezor"))]
fn host_entropy() -> Result<[u8; 32], Failure> {
    bhwi_async::management::host_entropy().map_err(|err| Failure::new(ErrorCode::NotReady, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "wpkh([f5acc2fd/84'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/<0;1>/*)";

    #[cfg(feature = "specter")]
    #[test]
    fn specter_signs_with_the_registered_policy_alone() {
        let context = signing_context(DeviceType::Specter, "unused".into(), POLICY, &[])
            .unwrap_or_else(|err| panic!("{}", err.message));
        assert!(matches!(context, DeviceContext::Specter { .. }));

        let err = signing_context(DeviceType::Specter, "unused".into(), POLICY, &[7; 32])
            .expect_err("Specter-DIY takes no hmac");
        assert!(matches!(err.code, ErrorCode::BadArgument));
    }

    #[cfg(feature = "ledger")]
    #[test]
    fn ledger_signs_with_the_registered_policy_and_hmac() {
        let context = signing_context(DeviceType::Ledger, "demo".into(), POLICY, &[7; 32])
            .unwrap_or_else(|err| panic!("{}", err.message));
        assert!(matches!(context, DeviceContext::Ledger { .. }));
    }

    #[test]
    fn other_devices_refuse_a_registered_policy() {
        let err = signing_context(DeviceType::Trezor, "demo".into(), POLICY, &[])
            .expect_err("Trezor has no registered signing policies");
        assert!(matches!(err.code, ErrorCode::Unsupported));
    }
}
