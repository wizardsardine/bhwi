use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi::keepkey::{
    DEFAULT_KEEPKEY_EMULATOR, KEEPKEY_HID_PID, KEEPKEY_HID_USAGE_PAGE, KEEPKEY_VID,
    KEEPKEY_WEBUSB_PID,
};
use bhwi_async::{KeepKey, transport::trezor::TrezorTransport};
use futures::stream::{StreamExt, TryStreamExt};

use crate::{
    Device, DeviceCandidate, DeviceEnumerator, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt,
    emulator::{EMULATOR_PROBE_TIMEOUT, EmulatorClient, emulator_socket},
    hid::{HidChannel, find_hid, hid_path},
    uses_backend,
    webusb::{WebUsbChannel, webusb_path},
};
use crate::{NativeError, NativeResult};

// KeepKey reuses the Trezor V1 wire format.
pub type KeepKeyHidDevice = KeepKey<TrezorTransport<HidChannel>>;
pub type KeepKeyWebUsbDevice = KeepKey<TrezorTransport<WebUsbChannel>>;
pub type KeepKeyEmulatorDevice = KeepKey<TrezorTransport<EmulatorClient>>;

const MODEL: &str = "keepkey";
const SIMULATOR_MODEL: &str = "keepkey_simulator";

pub struct KeepKeyDevice;

impl KeepKeyDevice {
    /// A KeepKey also exposes a U2F interface at this vendor and product id.
    fn is_keepkey(dev: &HidDevice) -> bool {
        dev.vendor_id == KEEPKEY_VID
            && dev.product_id == KEEPKEY_HID_PID
            && dev.usage_page == KEEPKEY_HID_USAGE_PAGE
    }

    async fn open_hid(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        let dev = find_hid(|dev| hid_path(dev) == candidate.path && Self::is_keepkey(dev))
            .await?
            .ok_or_else(|| NativeError::Gone(candidate.path.clone()))?;
        let opened = dev.open().await?;
        let device = KeepKeyHidDevice::new(TrezorTransport::new(HidChannel::new(opened)))
            .with_network(selector.network)
            .with_passphrase(selector.passphrase.clone());
        Ok(Device::new(
            &candidate.name,
            DeviceType::KeepKey,
            &candidate.path,
            &candidate.model,
            Box::new(with_host_interaction(device, host_interaction)),
            false,
        ))
    }

    async fn open_webusb(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        let info = nusb::list_devices()
            .await?
            .find(|info| webusb_path(info) == candidate.path)
            .ok_or_else(|| NativeError::Gone(candidate.path.clone()))?;
        let channel = WebUsbChannel::open(&info).await?;
        let device = KeepKeyWebUsbDevice::new(TrezorTransport::new(channel))
            .with_network(selector.network)
            .with_passphrase(selector.passphrase.clone());
        Ok(Device::new(
            &candidate.name,
            DeviceType::KeepKey,
            &candidate.path,
            &candidate.model,
            Box::new(with_host_interaction(device, host_interaction)),
            false,
        ))
    }

    async fn open_emulator(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        let client = EmulatorClient::new(&candidate.path).await?;
        let device = KeepKeyEmulatorDevice::new(TrezorTransport::new(client))
            .with_network(selector.network)
            .with_passphrase(selector.passphrase.clone());
        Ok(Device::new(
            &candidate.name,
            DeviceType::KeepKey,
            &candidate.path,
            &candidate.model,
            Box::new(with_host_interaction(device, host_interaction)),
            true,
        ))
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for KeepKeyDevice {
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
                    if selector.matches(DeviceType::KeepKey, &path) && Self::is_keepkey(&dev) {
                        Ok(Some(DeviceCandidate {
                            device_type: DeviceType::KeepKey,
                            name: "KeepKey".to_owned(),
                            model: MODEL.to_owned(),
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
            for info in nusb::list_devices().await?.filter(|info| {
                info.vendor_id() == KEEPKEY_VID && info.product_id() == KEEPKEY_WEBUSB_PID
            }) {
                let path = webusb_path(&info);
                if !selector.matches(DeviceType::KeepKey, &path) {
                    continue;
                }
                candidates.push(DeviceCandidate {
                    device_type: DeviceType::KeepKey,
                    name: "KeepKey".to_owned(),
                    model: MODEL.to_owned(),
                    path,
                    is_emulated: false,
                });
            }
        }

        // The emulator answers a UDP ping, which is how it is told apart from a
        // socket nobody is serving.
        if selector.include_emulators
            && matches_emulator(selector)
            && let Ok(client) = EmulatorClient::new(DEFAULT_KEEPKEY_EMULATOR).await
            && client.ping(EMULATOR_PROBE_TIMEOUT).await
        {
            candidates.push(DeviceCandidate {
                device_type: DeviceType::KeepKey,
                name: "KeepKey Emulator".to_owned(),
                model: SIMULATOR_MODEL.to_owned(),
                path: DEFAULT_KEEPKEY_EMULATOR.to_owned(),
                is_emulated: true,
            });
        }

        Ok(candidates)
    }

    async fn open(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        if candidate.is_emulated {
            Self::open_emulator(candidate, selector, host_interaction).await
        } else if candidate.path.starts_with("webusb:") {
            Self::open_webusb(candidate, selector, host_interaction).await
        } else {
            Self::open_hid(candidate, selector, host_interaction).await
        }
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
