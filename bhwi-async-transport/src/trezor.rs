use crate::{NativeError, NativeResult};
use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi::trezor::{
    TREZOR_DEVICE_ID, TREZOR_ONE_DEVICE_ID, TREZOR_ONE_PID, TREZOR_ONE_VID, TREZOR_PID, TREZOR_VID,
};
use bhwi_async::{Trezor, transport::trezor::TrezorTransport};
use futures::stream::{StreamExt, TryStreamExt};

use crate::{
    Device, DeviceEnumerator, DeviceScan, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt, ScanEntry, SkippedDevice,
    emulator::{EMULATOR_PROBE_TIMEOUT, EmulatorClient, emulator_socket},
    hid::HidChannel,
    uses_backend,
    webusb::WebUsbChannel,
};

pub type TrezorOneDevice = Trezor<TrezorTransport<HidChannel>>;
pub type TrezorWebUsbDevice = Trezor<TrezorTransport<WebUsbChannel>>;
pub type TrezorEmulatorDevice = Trezor<TrezorTransport<EmulatorClient>>;

pub struct TrezorDevice;

impl TrezorDevice {
    async fn hid_device(selector: &DeviceSelector, dev: HidDevice) -> NativeResult<ScanEntry> {
        let network = selector.network;
        let path = hid_path(&dev);
        let name = dev.name.clone();
        let model = trezor_model(dev.product_id, false);
        let opened = match dev.open().await {
            Ok(opened) => opened,
            Err(err) => return Ok(ScanEntry::skipped(DeviceType::Trezor, model, path, &err)),
        };
        Ok(ScanEntry::Found(Device::new(
            &name,
            DeviceType::Trezor,
            path,
            model,
            Box::new(
                TrezorOneDevice::new(TrezorTransport::new(HidChannel::new(opened)))
                    .with_network(network)
                    .with_passphrase(selector.passphrase.clone()),
            ),
            false,
        )))
    }

    async fn webusb_device(
        selector: &DeviceSelector,
        info: &nusb::DeviceInfo,
    ) -> NativeResult<Device> {
        let network = selector.network;
        let channel = WebUsbChannel::open(info).await?;
        Ok(Device::new(
            "Trezor",
            DeviceType::Trezor,
            webusb_path(info),
            trezor_model(info.product_id(), false),
            Box::new(
                TrezorWebUsbDevice::new(TrezorTransport::new(channel))
                    .with_network(network)
                    .with_passphrase(selector.passphrase.clone()),
            ),
            false,
        ))
    }

    async fn emulator_device(
        selector: &DeviceSelector,
        addr: &str,
        client: EmulatorClient,
    ) -> NativeResult<Device> {
        Ok(Device::new(
            "Trezor Emulator",
            DeviceType::Trezor,
            addr,
            trezor_model(0, true),
            Box::new(
                TrezorEmulatorDevice::new(TrezorTransport::new(client))
                    .with_network(selector.network)
                    .with_passphrase(selector.passphrase.clone())
                    .with_emulator(true),
            ),
            true,
        ))
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for TrezorDevice {
    async fn enumerate(
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<DeviceScan> {
        let selected_path = selector.device_path.as_deref();
        let mut scan = DeviceScan::default();

        if uses_backend(selected_path, "hid:") {
            let found: DeviceScan = HidBackend::default()
                .enumerate()
                .await?
                .map(Ok)
                .try_filter_map(|dev| async move {
                    let path = hid_path(&dev);
                    if selector.matches(DeviceType::Trezor, &path)
                        && dev.vendor_id == TREZOR_ONE_VID
                        && dev.product_id == TREZOR_ONE_PID
                        && dev.usage_page
                            == TREZOR_ONE_DEVICE_ID.usage_page.ok_or(
                                NativeError::MissingDeviceId(
                                    "trezor one usage page constant not set",
                                ),
                            )?
                    {
                        Self::hid_device(selector, dev).await.map(Some)
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
            for info in nusb::list_devices()
                .await?
                .filter(|info| info.vendor_id() == TREZOR_VID && info.product_id() == TREZOR_PID)
            {
                let path = webusb_path(&info);
                if !selector.matches(DeviceType::Trezor, &path) {
                    continue;
                }
                match Self::webusb_device(selector, &info).await {
                    Ok(device) => scan.devices.push(device),
                    Err(err) => scan.skipped.push(SkippedDevice::new(
                        DeviceType::Trezor,
                        trezor_model(info.product_id(), false),
                        path,
                        &err,
                    )),
                }
            }
        }

        if selector.include_emulators
            && let Some(addr) = TREZOR_DEVICE_ID.emulator_path
            && (selector.matches(DeviceType::Trezor, addr)
                || selector.matches(DeviceType::Trezor, emulator_socket(addr)))
            && let Ok(client) = EmulatorClient::new(addr).await
            && client.ping(EMULATOR_PROBE_TIMEOUT).await
        {
            scan.devices
                .push(Self::emulator_device(selector, addr, client).await?);
        }

        Ok(scan)
    }
}

pub(crate) fn webusb_path(info: &nusb::DeviceInfo) -> String {
    let mut path = format!("webusb:{}", bus_number(info.bus_id()));
    for port in info.port_chain() {
        path.push_str(&format!(":{port}"));
    }
    path
}

fn bus_number(bus_id: &str) -> String {
    let parsed = if cfg!(target_os = "macos") {
        u32::from_str_radix(bus_id, 16).ok()
    } else {
        bus_id.parse::<u32>().ok()
    };
    match parsed {
        Some(bus) => format!("{bus:03}"),
        None => bus_id.to_owned(),
    }
}

pub(crate) fn hid_path(dev: &HidDevice) -> String {
    let suffix = dev.serial_number.as_deref().unwrap_or(&dev.name);
    format!("hid:{:04x}:{:04x}:{suffix}", dev.vendor_id, dev.product_id)
}

fn trezor_model(product_id: u16, is_emulated: bool) -> &'static str {
    match (product_id, is_emulated) {
        (_, true) => "trezor_emulator",
        (TREZOR_ONE_PID, false) => "trezor_one",
        (TREZOR_PID, false) => "trezor_t",
        _ => "trezor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_number_is_three_digit_decimal() {
        if cfg!(target_os = "macos") {
            assert_eq!(bus_number("14"), "020");
            assert_eq!(bus_number("01"), "001");
        } else {
            assert_eq!(bus_number("001"), "001");
            assert_eq!(bus_number("20"), "020");
        }
    }

    #[test]
    fn bus_number_falls_back_to_the_raw_id() {
        assert_eq!(bus_number("PCIROOT(0)#PCI(0201)"), "PCIROOT(0)#PCI(0201)");
    }
}
