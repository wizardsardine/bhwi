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
    Device, DeviceCandidate, DeviceEnumerator, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt,
    emulator::{EMULATOR_PROBE_TIMEOUT, EmulatorClient, emulator_socket},
    hid::{HidChannel, find_hid, hid_path},
    uses_backend,
    webusb::{WebUsbChannel, webusb_path},
};

pub type TrezorOneDevice = Trezor<TrezorTransport<HidChannel>>;
pub type TrezorWebUsbDevice = Trezor<TrezorTransport<WebUsbChannel>>;
pub type TrezorEmulatorDevice = Trezor<TrezorTransport<EmulatorClient>>;

pub struct TrezorDevice;

impl TrezorDevice {
    /// A Trezor One also exposes a U2F interface at this vendor and product id.
    fn is_trezor_one(dev: &HidDevice) -> NativeResult<bool> {
        Ok(dev.vendor_id == TREZOR_ONE_VID
            && dev.product_id == TREZOR_ONE_PID
            && dev.usage_page
                == TREZOR_ONE_DEVICE_ID
                    .usage_page
                    .ok_or(NativeError::MissingDeviceId(
                        "trezor one usage page constant not set",
                    ))?)
    }

    async fn open_hid(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
    ) -> NativeResult<Device> {
        let dev = find_hid(|dev| {
            hid_path(dev) == candidate.path && Self::is_trezor_one(dev).unwrap_or(false)
        })
        .await?
        .ok_or_else(|| NativeError::Gone(candidate.path.clone()))?;
        let name = dev.name.clone();
        let opened = dev.open().await?;
        Ok(Device::new(
            &name,
            DeviceType::Trezor,
            &candidate.path,
            &candidate.model,
            Box::new(
                TrezorOneDevice::new(TrezorTransport::new(HidChannel::new(opened)))
                    .with_network(selector.network)
                    .with_passphrase(selector.passphrase.clone()),
            ),
            false,
        ))
    }

    async fn open_webusb(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
    ) -> NativeResult<Device> {
        let info = nusb::list_devices()
            .await?
            .find(|info| webusb_path(info) == candidate.path)
            .ok_or_else(|| NativeError::Gone(candidate.path.clone()))?;
        let channel = WebUsbChannel::open(&info).await?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Trezor,
            &candidate.path,
            &candidate.model,
            Box::new(
                TrezorWebUsbDevice::new(TrezorTransport::new(channel))
                    .with_network(selector.network)
                    .with_passphrase(selector.passphrase.clone()),
            ),
            false,
        ))
    }

    async fn open_emulator(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
    ) -> NativeResult<Device> {
        let client = EmulatorClient::new(&candidate.path).await?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Trezor,
            &candidate.path,
            &candidate.model,
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
    async fn list(selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>> {
        let selected_path = selector.device_path.as_deref();
        let mut candidates = Vec::new();

        if uses_backend(selected_path, "hid:") {
            let found: Vec<DeviceCandidate> = HidBackend::default()
                .enumerate()
                .await?
                .map(Ok::<HidDevice, NativeError>)
                .try_filter_map(|dev| async move {
                    let path = hid_path(&dev);
                    if selector.matches(DeviceType::Trezor, &path) && Self::is_trezor_one(&dev)? {
                        Ok(Some(DeviceCandidate {
                            device_type: DeviceType::Trezor,
                            name: dev.name.clone(),
                            model: trezor_model(dev.product_id, false).to_owned(),
                            path,
                            is_emulated: false,
                        }))
                    } else {
                        Ok(None)
                    }
                })
                .try_collect()
                .await?;
            candidates.extend(found);
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
                candidates.push(DeviceCandidate {
                    device_type: DeviceType::Trezor,
                    name: "Trezor".to_owned(),
                    model: trezor_model(info.product_id(), false).to_owned(),
                    path,
                    is_emulated: false,
                });
            }
        }

        // The emulator answers a UDP ping, which is how it is told apart from a
        // socket nobody is serving.
        if selector.include_emulators
            && let Some(addr) = TREZOR_DEVICE_ID.emulator_path
            && (selector.matches(DeviceType::Trezor, addr)
                || selector.matches(DeviceType::Trezor, emulator_socket(addr)))
            && let Ok(client) = EmulatorClient::new(addr).await
            && client.ping(EMULATOR_PROBE_TIMEOUT).await
        {
            candidates.push(DeviceCandidate {
                device_type: DeviceType::Trezor,
                name: "Trezor Emulator".to_owned(),
                model: trezor_model(0, true).to_owned(),
                path: addr.to_owned(),
                is_emulated: true,
            });
        }

        Ok(candidates)
    }

    async fn open(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        if candidate.is_emulated {
            Self::open_emulator(candidate, selector).await
        } else if candidate.path.starts_with("webusb:") {
            Self::open_webusb(candidate, selector).await
        } else {
            Self::open_hid(candidate, selector).await
        }
    }
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
    fn model_comes_from_the_product_id() {
        assert_eq!(trezor_model(TREZOR_ONE_PID, false), "trezor_one");
        assert_eq!(trezor_model(TREZOR_PID, false), "trezor_t");
        assert_eq!(trezor_model(TREZOR_PID, true), "trezor_emulator");
    }
}
