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
pub mod error;
#[cfg(any(
    feature = "bitbox",
    feature = "coldcard",
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
#[cfg(feature = "trezor")]
pub mod webusb;

pub use bhwi_async::Info;
pub use bhwi_async::device::{
    Device, DeviceManager, DeviceScan, DeviceSelector, DeviceSource, DeviceType,
    HostInteractionFactory, NoUsableDevice, PairingCodePrompt, ScanEntry, SelectError,
    SkippedDevice, is_user_cancelled, networks_string, no_device,
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

    async fn enumerate_device_type(
        device_type: DeviceType,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<DeviceScan> {
        Ok(match device_type {
            #[cfg(feature = "bitbox")]
            DeviceType::BitBox02 => {
                BitBoxDevice::enumerate(selector, pairing_code, host_interaction).await?
            }
            #[cfg(feature = "ledger")]
            DeviceType::Ledger => {
                LedgerDevice::enumerate(selector, pairing_code, host_interaction).await?
            }
            #[cfg(feature = "coldcard")]
            DeviceType::Coldcard => {
                ColdcardDevice::enumerate(selector, pairing_code, host_interaction).await?
            }
            #[cfg(feature = "jade")]
            DeviceType::Jade => {
                JadeDevice::enumerate(selector, pairing_code, host_interaction).await?
            }
            #[cfg(feature = "keepkey")]
            DeviceType::KeepKey => {
                KeepKeyDevice::enumerate(selector, pairing_code, host_interaction).await?
            }
            #[cfg(feature = "trezor")]
            DeviceType::Trezor => {
                TrezorDevice::enumerate(selector, pairing_code, host_interaction).await?
            }
            #[allow(unreachable_patterns)]
            _ => return Err(NativeError::NotCompiled(device_type)),
        })
    }
}

#[async_trait(?Send)]
impl DeviceSource for NativeSource {
    type Error = NativeError;

    async fn enumerate(
        &self,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<DeviceScan> {
        let device_types: Vec<DeviceType> = selector
            .device_type
            .map(|device_type| vec![device_type])
            .unwrap_or_else(|| {
                DeviceType::ALL
                    .into_iter()
                    .filter(|d| Self::is_supported(*d))
                    .collect()
            });
        let targeted = selector.device_type.is_some()
            || selector.device_path.is_some()
            || selector.fingerprint.is_some();
        let res = join_all(device_types.into_iter().map(|device_type| {
            Self::enumerate_device_type(device_type, selector, pairing_code, host_interaction)
        }))
        .await;
        collect_scans(targeted, res)
    }
}

/// One bus failing does not hide what the others found.
fn collect_scans(
    targeted: bool,
    results: Vec<NativeResult<DeviceScan>>,
) -> NativeResult<DeviceScan> {
    let mut scan = DeviceScan::default();
    let mut first_error = None;
    for result in results {
        match result {
            Ok(part) => {
                scan.devices.extend(part.devices);
                scan.skipped.extend(part.skipped);
            }
            Err(err) if first_error.is_none() => first_error = Some(err),
            Err(_) => {}
        }
    }
    if scan.devices.is_empty()
        && targeted
        && let Some(err) = first_error
    {
        return Err(err);
    }
    Ok(scan)
}

/// A selected path names one backend, so the other bus is not walked at all.
#[cfg(any(feature = "keepkey", feature = "trezor"))]
pub(crate) fn uses_backend(selected_path: Option<&str>, prefix: &str) -> bool {
    selected_path.is_none_or(|path| path.starts_with(prefix))
}

#[async_trait(?Send)]
pub trait DeviceEnumerator {
    async fn enumerate(
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<DeviceScan>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_with_skipped(path: &str) -> DeviceScan {
        DeviceScan {
            devices: Vec::new(),
            skipped: vec![SkippedDevice::new(
                DeviceType::Coldcard,
                "coldcard",
                path,
                &NativeError::MissingDeviceId("unopened"),
            )],
        }
    }

    fn error(message: &'static str) -> NativeError {
        NativeError::MissingDeviceId(message)
    }

    #[test]
    fn an_untargeted_scan_keeps_what_the_other_buses_found() {
        let results = vec![
            Ok(scan_with_skipped("hid:1")),
            Err(error("unrelated")),
            Ok(scan_with_skipped("hid:2")),
        ];

        let scan = collect_scans(false, results).expect("untargeted scan tolerates one failure");
        assert_eq!(scan.skipped.len(), 2);
    }

    #[test]
    fn a_targeted_scan_reports_the_first_failure() {
        let results = vec![Err(error("first")), Err(error("second"))];

        let err = collect_scans(true, results)
            .err()
            .expect("a targeted scan reports the failure");
        assert_eq!(err.to_string(), "first");
    }

    #[test]
    fn a_targeted_scan_that_found_nothing_reports_the_failure() {
        let results = vec![Err(error("path failed"))];

        let err = collect_scans(true, results)
            .err()
            .expect("a targeted scan reports the failure");
        assert_eq!(err.to_string(), "path failed");
    }
}
