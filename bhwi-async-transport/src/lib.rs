use async_trait::async_trait;
use futures::future::join_all;

#[cfg(feature = "bitbox")]
use crate::bitbox::BitBoxDevice;
#[cfg(feature = "coldcard")]
use crate::coldcard::ColdcardDevice;
#[cfg(feature = "jade")]
use crate::jade::JadeDevice;
#[cfg(feature = "keepkey")]
use crate::keepkey::KeepKeyDevice;
#[cfg(feature = "ledger")]
use crate::ledger::LedgerDevice;
#[cfg(feature = "trezor")]
use crate::trezor::TrezorDevice;

#[cfg(feature = "bitbox")]
pub mod bitbox;
#[cfg(feature = "coldcard")]
pub mod coldcard;
/// The Trezor V1 emulator framing, shared with every device that reuses it.
#[cfg(any(feature = "keepkey", feature = "trezor"))]
pub mod emulator;
pub mod error;
#[cfg(any(
    feature = "bitbox",
    feature = "coldcard",
    feature = "keepkey",
    feature = "ledger",
    feature = "trezor"
))]
pub mod hid;
#[cfg(feature = "jade")]
pub mod jade;
#[cfg(feature = "keepkey")]
pub mod keepkey;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "trezor")]
pub mod trezor;
/// udev rules grant device-node access on Linux; no other host has them.
#[cfg(target_os = "linux")]
pub mod udev;
#[cfg(any(feature = "keepkey", feature = "trezor"))]
pub mod webusb;

pub use bhwi_async::Info;
pub use bhwi_async::device::{
    ClassifiedDeviceError, Device, DeviceCandidate, DeviceErrorKind, DeviceManager, DeviceScan,
    DeviceSelector, DeviceSource, DeviceType, HostInteractionFactory, NoUsableDevice,
    PairingCodePrompt, ScanEntry, SelectError, SkippedDevice, can_sign_taproot, classify_error,
    classify_message, is_user_cancelled, networks_string, no_device, reports_device_info,
};
pub use error::{NativeError, NativeResult};

pub struct NativeSource;

impl NativeSource {
    pub fn is_supported(device_type: DeviceType) -> bool {
        match device_type {
            DeviceType::BitBox02 => cfg!(feature = "bitbox"),
            DeviceType::Coldcard => cfg!(feature = "coldcard"),
            DeviceType::Jade => cfg!(feature = "jade"),
            DeviceType::KeepKey => cfg!(feature = "keepkey"),
            DeviceType::Ledger => cfg!(feature = "ledger"),
            DeviceType::Trezor => cfg!(feature = "trezor"),
        }
    }

    async fn list_device_type(
        device_type: DeviceType,
        selector: &DeviceSelector,
    ) -> NativeResult<Vec<DeviceCandidate>> {
        Ok(match device_type {
            #[cfg(feature = "bitbox")]
            DeviceType::BitBox02 => BitBoxDevice::list(selector).await?,
            #[cfg(feature = "ledger")]
            DeviceType::Ledger => LedgerDevice::list(selector).await?,
            #[cfg(feature = "coldcard")]
            DeviceType::Coldcard => ColdcardDevice::list(selector).await?,
            #[cfg(feature = "jade")]
            DeviceType::Jade => JadeDevice::list(selector).await?,
            #[cfg(feature = "keepkey")]
            DeviceType::KeepKey => KeepKeyDevice::list(selector).await?,
            #[cfg(feature = "trezor")]
            DeviceType::Trezor => TrezorDevice::list(selector).await?,
            #[allow(unreachable_patterns)]
            _ => return Err(NativeError::NotCompiled(device_type)),
        })
    }
}

#[async_trait(?Send)]
impl DeviceSource for NativeSource {
    type Error = NativeError;

    async fn list(&self, selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>> {
        let device_types: Vec<DeviceType> = selector
            .device_type
            .map(|device_type| vec![device_type])
            .unwrap_or_else(|| {
                DeviceType::ALL
                    .into_iter()
                    .filter(|d| Self::is_supported(*d))
                    .collect()
            });
        let results = join_all(
            device_types
                .into_iter()
                .map(|device_type| Self::list_device_type(device_type, selector)),
        )
        .await;
        collect_candidates(results)
    }

    async fn open(
        &self,
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        match candidate.device_type {
            #[cfg(feature = "bitbox")]
            DeviceType::BitBox02 => {
                BitBoxDevice::open(candidate, selector, pairing_code, host_interaction).await
            }
            #[cfg(feature = "ledger")]
            DeviceType::Ledger => {
                LedgerDevice::open(candidate, selector, pairing_code, host_interaction).await
            }
            #[cfg(feature = "coldcard")]
            DeviceType::Coldcard => {
                ColdcardDevice::open(candidate, selector, pairing_code, host_interaction).await
            }
            #[cfg(feature = "jade")]
            DeviceType::Jade => {
                JadeDevice::open(candidate, selector, pairing_code, host_interaction).await
            }
            #[cfg(feature = "keepkey")]
            DeviceType::KeepKey => {
                KeepKeyDevice::open(candidate, selector, pairing_code, host_interaction).await
            }
            #[cfg(feature = "trezor")]
            DeviceType::Trezor => {
                TrezorDevice::open(candidate, selector, pairing_code, host_interaction).await
            }
            #[allow(unreachable_patterns)]
            device_type => Err(NativeError::NotCompiled(device_type)),
        }
    }
}

/// One bus failing does not hide what the others found; finding nothing reports why.
fn collect_candidates(
    results: Vec<NativeResult<Vec<DeviceCandidate>>>,
) -> NativeResult<Vec<DeviceCandidate>> {
    let mut candidates = Vec::new();
    let mut first_error = None;
    for result in results {
        match result {
            Ok(found) => candidates.extend(found),
            Err(err) if first_error.is_none() => first_error = Some(err),
            Err(_) => {}
        }
    }
    if candidates.is_empty()
        && let Some(err) = first_error
    {
        return Err(err);
    }
    Ok(candidates)
}

/// A selected path names one backend, so the other bus is not walked at all.
#[cfg(any(feature = "keepkey", feature = "trezor"))]
pub(crate) fn uses_backend(selected_path: Option<&str>, prefix: &str) -> bool {
    selected_path.is_none_or(|path| path.starts_with(prefix))
}

#[async_trait(?Send)]
pub trait DeviceEnumerator {
    /// Reads the bus without opening a device; an emulator is probed instead.
    async fn list(selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>>;

    async fn open(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(path: &str) -> DeviceCandidate {
        DeviceCandidate {
            device_type: DeviceType::Coldcard,
            name: "Coldcard".to_owned(),
            model: "coldcard".to_owned(),
            path: path.to_owned(),
            is_emulated: false,
        }
    }

    fn error(message: &'static str) -> NativeError {
        NativeError::MissingDeviceId(message)
    }

    #[test]
    fn a_list_keeps_what_the_other_buses_found() {
        let results = vec![
            Ok(vec![candidate("hid:1")]),
            Err(error("unrelated")),
            Ok(vec![candidate("hid:2")]),
        ];

        let found = collect_candidates(results).expect("one bus failing is tolerated");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_list_that_found_nothing_reports_the_first_failure() {
        let results = vec![Err(error("first")), Err(error("second"))];

        let err = collect_candidates(results).expect_err("a list that found nothing reports why");
        assert_eq!(err.to_string(), "first");
    }

    #[test]
    fn one_bus_failing_alone_reports_the_failure() {
        let results = vec![Err(error("path failed"))];

        let err = collect_candidates(results).expect_err("a list that found nothing reports why");
        assert_eq!(err.to_string(), "path failed");
    }

    #[test]
    fn a_list_that_found_something_ignores_the_failure() {
        let results = vec![Err(error("unrelated")), Ok(vec![candidate("hid:1")])];

        let found = collect_candidates(results).expect("a found device wins over an error");
        assert_eq!(found.len(), 1);
    }
}
