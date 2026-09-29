use std::rc::Rc;

use bhwi_async::ErrorKind;
#[cfg(any(feature = "keepkey", feature = "trezor"))]
use bhwi_async::HostPassphrase;
use bhwi_async::device::{
    Device as HwiDevice, DeviceManager, DeviceSelector, DeviceType, SelectError, SkippedDevice,
    no_device,
};
use bhwi_async_transport::{NativeError, NativeSource};

use crate::bhwi_capnp::{bhwi as bhwi_service, selector};
use crate::convert::{self, PassphraseSource};
use crate::device::DeviceServer;
use crate::error::{self, ErrorCode, Failure};
use crate::prompt::Prompter;
use crate::registry::{Lease, Registry};
use crate::session::Session;

type Manager = DeviceManager<NativeSource>;

/// Serves the top-level `Bhwi` capability.
pub struct BhwiServer {
    registry: Registry,
}

impl BhwiServer {
    /// Creates the capability, sharing `registry` with every other connection.
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }
}

impl bhwi_service::Server for BhwiServer {
    async fn list_devices(
        self: Rc<Self>,
        params: bhwi_service::ListDevicesParams,
        mut results: bhwi_service::ListDevicesResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            let prompter = if request.has_prompter() {
                Prompter::new(Some(request.get_prompter()?))
            } else {
                Prompter::default()
            };
            let (selector, _) = resolve_selector(request.get_selector()?, &prompter).await?;
            let network = selector.network;
            let manager = manager(selector, &prompter);
            let (mut scan, reservations) = manager
                .scan_reserved(|path| self.registry.claim(path))
                .await
                .map_err(select_error)?;

            let mut mismatches = Vec::with_capacity(scan.devices.len());
            for device in scan.devices.iter_mut() {
                mismatches.push(
                    device
                        .network_mismatch(network)
                        .await
                        .map_err(|err| error::device(&err))?,
                );
            }
            Ok::<_, Failure>((scan, mismatches, reservations))
        }
        .await;

        error::reply(
            results.get().init_result(),
            outcome,
            |builder, (scan, mismatches, _reservations)| {
                let mut list = builder.init_ok();
                {
                    let mut devices = list.reborrow().init_devices(scan.devices.len() as u32);
                    for (index, device) in scan.devices.iter().enumerate() {
                        convert::fill_device(
                            device,
                            mismatches[index].as_ref(),
                            devices.reborrow().get(index as u32),
                        )?;
                    }
                }
                let mut entries = list.init_skipped(scan.skipped.len() as u32);
                for (index, entry) in scan.skipped.iter().enumerate() {
                    convert::fill_skipped(entry, entries.reborrow().get(index as u32));
                }
                Ok(())
            },
        )
    }

    async fn open_device(
        self: Rc<Self>,
        params: bhwi_service::OpenDeviceParams,
        mut results: bhwi_service::OpenDeviceResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?;
        let outcome = async {
            let prompter = if request.has_prompter() {
                Prompter::new(Some(request.get_prompter()?))
            } else {
                Prompter::default()
            };
            let (selector, passphrase_given) =
                resolve_selector(request.get_selector()?, &prompter).await?;
            let network = selector.network;
            let manager = manager(selector, &prompter);

            let (mut device, lease, skipped) = select(&manager, &self.registry).await?;
            refuse_passphrase(passphrase_given, device.device_type())?;
            let mismatch = device
                .network_mismatch(network)
                .await
                .map_err(|err| error::device(&err))?;
            Ok::<_, Failure>((
                Session::new(device, network, prompter, lease),
                mismatch,
                skipped,
            ))
        }
        .await;

        error::reply(
            results.get().init_result(),
            outcome,
            |builder, (session, mismatch, skipped)| {
                let mut opened = builder.init_ok();
                convert::fill_network_mismatch(
                    mismatch.as_ref(),
                    opened.reborrow().init_network_mismatch(),
                );
                {
                    let mut entries = opened.reborrow().init_skipped(skipped.len() as u32);
                    for (index, entry) in skipped.iter().enumerate() {
                        convert::fill_skipped(entry, entries.reborrow().get(index as u32));
                    }
                }
                opened.set_device(capnp_rpc::new_client(DeviceServer::new(Rc::new(session))));
                Ok(())
            },
        )
    }
}

fn manager(selector: DeviceSelector, prompter: &Prompter) -> Manager {
    let mut manager = DeviceManager::new(NativeSource::default(), selector);
    if let Some(prompt) = prompter.pairing_code_prompt() {
        manager = manager.with_pairing_code_prompt(prompt);
    }
    #[cfg(any(feature = "keepkey", feature = "trezor"))]
    if prompter.is_set() {
        manager = manager.with_pin_prompt(Rc::new(prompter.clone()));
    }
    #[cfg(feature = "keepkey")]
    if prompter.is_set() {
        let prompter = prompter.clone();
        manager = manager.with_host_interaction(Rc::new(move || Box::new(prompter.clone())));
    }
    manager
}

/// The flag outlives builds that drop the passphrase, for the BitBox02 refusal.
async fn resolve_selector(
    reader: selector::Reader<'_>,
    prompter: &Prompter,
) -> Result<(DeviceSelector, bool), Failure> {
    let source = convert::passphrase_source(reader)?;
    let passphrase_given = !matches!(source, PassphraseSource::None);
    #[allow(unused_mut)]
    let mut selector = convert::selector(reader)?;
    #[cfg(any(feature = "keepkey", feature = "trezor"))]
    {
        selector.passphrase = match source {
            PassphraseSource::None => None,
            PassphraseSource::Value(value) => Some(HostPassphrase::new(value)),
            PassphraseSource::AskPrompter => Some(prompter.request_passphrase().await?),
        };
    }
    #[cfg(not(any(feature = "keepkey", feature = "trezor")))]
    let _ = (source, prompter);
    Ok((selector, passphrase_given))
}

/// BitBox02 only takes a passphrase entered on the device.
fn refuse_passphrase(passphrase_given: bool, device_type: DeviceType) -> Result<(), Failure> {
    #[cfg(feature = "bitbox")]
    if passphrase_given && device_type == DeviceType::BitBox02 {
        return Err(select_error(SelectError::HostPassphraseRejected));
    }
    let _ = (passphrase_given, device_type);
    Ok(())
}

async fn select(
    manager: &Manager,
    registry: &Registry,
) -> Result<(HwiDevice, Lease, Vec<SkippedDevice>), Failure> {
    let (device, skipped) = manager
        .select_reserved(|path| registry.claim(path))
        .await
        .map_err(select_error)?;
    if let Some((device, lease)) = device {
        return Ok((device, lease, skipped));
    }
    if !skipped.is_empty()
        && skipped
            .iter()
            .all(|entry| entry.error.kind() == ErrorKind::Busy)
    {
        return Err(Failure::new(
            ErrorCode::Busy,
            "every matching device is already open on this server",
        ));
    }
    match no_device(skipped) {
        Ok(_) => Err(Failure::new(ErrorCode::NoDevice, "no device found")),
        Err(unusable) => {
            let code = match unusable.skipped.as_slice() {
                [entry] => error::kind_code(entry.error.kind()),
                _ => ErrorCode::NoDevice,
            };
            Err(Failure::new(code, unusable))
        }
    }
}

/// Tested rather than matched: `SelectError` gains a variant with a feature
/// anything in the build can turn on, whatever this crate was compiled with.
fn select_error(err: SelectError<NativeError>) -> Failure {
    if let SelectError::Device(device) = &err {
        return error::device(device);
    }
    let code = if matches!(err, SelectError::Source(_)) {
        ErrorCode::Transport
    } else if matches!(err, SelectError::NoUsableDevice(_)) {
        ErrorCode::NoDevice
    } else {
        ErrorCode::BadArgument
    };
    Failure::new(code, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_supplied_passphrase_is_refused_only_for_bitbox02() {
        for device_type in DeviceType::ALL {
            assert_eq!(
                refuse_passphrase(true, device_type).is_err(),
                cfg!(feature = "bitbox") && device_type == DeviceType::BitBox02,
                "{device_type}"
            );
            assert!(refuse_passphrase(false, device_type).is_ok());
        }
    }
}
