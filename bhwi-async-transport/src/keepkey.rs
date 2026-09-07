use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi::keepkey::{
    DEFAULT_KEEPKEY_EMULATOR, KEEPKEY_HID_PID, KEEPKEY_HID_USAGE_PAGE, KEEPKEY_VID,
    KEEPKEY_WEBUSB_PID,
};
use bhwi_async::{KeepKey, transport::trezor::TrezorTransport};
use futures::stream::{StreamExt, TryStreamExt};

use crate::NativeResult;
use crate::{
    Device, DeviceEnumerator, DeviceScan, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt, ScanEntry, SkippedDevice,
    hid::HidChannel,
    trezor::{EMULATOR_PROBE_TIMEOUT, emulator::EmulatorClient, emulator_socket, webusb_path},
    uses_backend,
    webusb::WebUsbChannel,
};

// KeepKey reuses the Trezor V1 wire format.
pub type KeepKeyHidDevice = KeepKey<TrezorTransport<HidChannel>>;
pub type KeepKeyWebUsbDevice = KeepKey<TrezorTransport<WebUsbChannel>>;
pub type KeepKeyEmulatorDevice = KeepKey<TrezorTransport<EmulatorClient>>;

const MODEL: &str = "keepkey";
const SIMULATOR_MODEL: &str = "keepkey_simulator";

pub struct KeepKeyDevice;

impl KeepKeyDevice {
    async fn hid_device(
        selector: &DeviceSelector,
        dev: HidDevice,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<ScanEntry> {
        let path = crate::trezor::hid_path(&dev);
        let opened = match dev.open().await {
            Ok(opened) => opened,
            Err(err) => return Ok(ScanEntry::skipped(DeviceType::KeepKey, MODEL, path, &err)),
        };
        let device = KeepKeyHidDevice::new(TrezorTransport::new(HidChannel::new(opened)))
            .with_network(selector.network)
            .with_passphrase(selector.passphrase.clone());
        Ok(ScanEntry::Found(Device::new(
            "KeepKey",
            DeviceType::KeepKey,
            path,
            MODEL,
            Box::new(with_host_interaction(device, host_interaction)),
            false,
        )))
    }

    async fn webusb_device(
        selector: &DeviceSelector,
        info: &nusb::DeviceInfo,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        let channel = WebUsbChannel::open(info).await?;
        let device = KeepKeyWebUsbDevice::new(TrezorTransport::new(channel))
            .with_network(selector.network)
            .with_passphrase(selector.passphrase.clone());
        Ok(Device::new(
            "KeepKey",
            DeviceType::KeepKey,
            webusb_path(info),
            MODEL,
            Box::new(with_host_interaction(device, host_interaction)),
            false,
        ))
    }

    async fn emulator_device(
        selector: &DeviceSelector,
        client: EmulatorClient,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        let device = KeepKeyEmulatorDevice::new(TrezorTransport::new(client))
            .with_network(selector.network)
            .with_passphrase(selector.passphrase.clone());
        Ok(Device::new(
            "KeepKey Emulator",
            DeviceType::KeepKey,
            DEFAULT_KEEPKEY_EMULATOR,
            SIMULATOR_MODEL,
            Box::new(with_host_interaction(device, host_interaction)),
            true,
        ))
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for KeepKeyDevice {
    async fn enumerate(
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<DeviceScan> {
        let selected_path = selector.device_path.as_deref();
        let mut scan = DeviceScan::default();

        if uses_backend(selected_path, "hid:") {
            let found: DeviceScan = HidBackend::default()
                .enumerate()
                .await?
                .map(Ok)
                .try_filter_map(|dev| async move {
                    let path = crate::trezor::hid_path(&dev);
                    if selector.matches(DeviceType::KeepKey, &path)
                        && dev.vendor_id == KEEPKEY_VID
                        && dev.product_id == KEEPKEY_HID_PID
                        && dev.usage_page == KEEPKEY_HID_USAGE_PAGE
                    {
                        Self::hid_device(selector, dev, host_interaction)
                            .await
                            .map(Some)
                    } else {
                        Ok(None)
                    }
                })
                .try_collect()
                .await?;
            scan.devices.extend(found.devices);
            scan.skipped.extend(found.skipped);
        }

        if uses_backend(selected_path, "webusb:") {
            for info in nusb::list_devices().await?.filter(|info| {
                info.vendor_id() == KEEPKEY_VID && info.product_id() == KEEPKEY_WEBUSB_PID
            }) {
                let path = webusb_path(&info);
                if !selector.matches(DeviceType::KeepKey, &path) {
                    continue;
                }
                match Self::webusb_device(selector, &info, host_interaction).await {
                    Ok(device) => scan.devices.push(device),
                    Err(err) => scan.skipped.push(SkippedDevice::new(
                        DeviceType::KeepKey,
                        MODEL,
                        path,
                        &err,
                    )),
                }
            }
        }

        if selector.include_emulators
            && matches_emulator(selector)
            && let Ok(client) = EmulatorClient::new(DEFAULT_KEEPKEY_EMULATOR).await
            && client.ping(EMULATOR_PROBE_TIMEOUT).await
        {
            scan.devices
                .push(Self::emulator_device(selector, client, host_interaction).await?);
        }

        Ok(scan)
    }
}

fn matches_emulator(selector: &DeviceSelector) -> bool {
    selector.matches(DeviceType::KeepKey, DEFAULT_KEEPKEY_EMULATOR)
        || selector.matches(
            DeviceType::KeepKey,
            emulator_socket(DEFAULT_KEEPKEY_EMULATOR),
        )
}

fn with_host_interaction<T>(
    device: KeepKey<T>,
    host_interaction: Option<&HostInteractionFactory>,
) -> KeepKey<T> {
    match host_interaction {
        Some(factory) => device.with_host_interaction(factory()),
        None => device,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emulator_selector_accepts_prefixed_and_bare_paths() {
        for path in [DEFAULT_KEEPKEY_EMULATOR, "127.0.0.1:11044"] {
            let selector = DeviceSelector {
                device_type: Some(DeviceType::KeepKey),
                device_path: Some(path.to_owned()),
                include_emulators: true,
                ..DeviceSelector::default()
            };
            assert!(matches_emulator(&selector));
        }
    }

    #[test]
    fn physical_path_selects_only_matching_backend() {
        for (path, hid, webusb) in [
            (None, true, true),
            (Some("hid:2b24:0001:keepkey"), true, false),
            (Some("webusb:1:2"), false, true),
            (Some(DEFAULT_KEEPKEY_EMULATOR), false, false),
        ] {
            assert_eq!(uses_backend(path, "hid:"), hid);
            assert_eq!(uses_backend(path, "webusb:"), webusb);
        }
    }
}
