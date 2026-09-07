use async_trait::async_trait;
use futures::future::join_all;

#[cfg(feature = "bitbox")]
use crate::bitbox::BitBoxDevice;
#[cfg(feature = "coldcard")]
use crate::coldcard::ColdcardDevice;
#[cfg(feature = "jade")]
use crate::jade::JadeDevice;
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
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "trezor")]
pub mod trezor;
pub mod udev;
#[cfg(feature = "trezor")]
pub mod webusb;

pub use bhwi_async::Info;
pub use bhwi_async::device::{
    Device, DeviceManager, DeviceScan, DeviceSelector, DeviceSource, DeviceType, NoUsableDevice,
    PairingCodePrompt, ScanEntry, SelectError, SkippedDevice, is_user_cancelled, networks_string,
    no_device,
};
pub use error::{NativeError, NativeResult};

pub struct NativeSource;

impl NativeSource {
    pub fn is_supported(device_type: DeviceType) -> bool {
        match device_type {
            DeviceType::BitBox02 => cfg!(feature = "bitbox"),
            DeviceType::Coldcard => cfg!(feature = "coldcard"),
            DeviceType::Jade => cfg!(feature = "jade"),
            DeviceType::Ledger => cfg!(feature = "ledger"),
            DeviceType::Trezor => cfg!(feature = "trezor"),
        }
    }

    async fn enumerate_device_type(
        device_type: DeviceType,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
    ) -> NativeResult<DeviceScan> {
        Ok(match device_type {
            #[cfg(feature = "bitbox")]
            DeviceType::BitBox02 => BitBoxDevice::enumerate(selector, pairing_code).await?,
            #[cfg(feature = "ledger")]
            DeviceType::Ledger => LedgerDevice::enumerate(selector, pairing_code).await?,
            #[cfg(feature = "coldcard")]
            DeviceType::Coldcard => ColdcardDevice::enumerate(selector, pairing_code).await?,
            #[cfg(feature = "jade")]
            DeviceType::Jade => JadeDevice::enumerate(selector, pairing_code).await?,
            #[cfg(feature = "trezor")]
            DeviceType::Trezor => TrezorDevice::enumerate(selector, pairing_code).await?,
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
        let res =
            join_all(device_types.into_iter().map(|device_type| {
                Self::enumerate_device_type(device_type, selector, pairing_code)
            }))
            .await
            .into_iter()
            .collect::<NativeResult<Vec<_>>>()?;
        let mut scan = DeviceScan::default();
        for part in res {
            scan.devices.extend(part.devices);
            scan.skipped.extend(part.skipped);
        }
        Ok(scan)
    }
}

#[async_trait(?Send)]
pub trait DeviceEnumerator {
    async fn enumerate(
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
    ) -> NativeResult<DeviceScan>;
}
