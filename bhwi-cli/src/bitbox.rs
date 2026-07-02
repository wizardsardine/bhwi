use anyhow::Context;
use anyhow::Result;
use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi_async::{
    bitbox::BitBox,
    transport::{
        DeviceId,
        bitbox::hid::{
            BITBOX02_DEVICE_ID, BITBOX02_HID_USAGE_PAGE, BITBOX02_PRODUCT_STRINGS,
            BitBoxTransportHID,
        },
    },
};
use futures::StreamExt;
use futures::TryStreamExt;

use crate::{Device, DeviceEnumerator, DeviceType, config::DeviceSelector, hid::HidChannel};

pub struct BitBoxDevice;

impl BitBoxDevice {
    async fn hid_device(hid_dev: HidDevice, network: bitcoin::Network) -> Result<Option<Device>> {
        let path = hid_path(&hid_dev);
        let name = hid_dev.name.clone();
        // No cached pairing data yet — a filesystem-backed store can be plugged in later.
        // First-time pairing: the interpreter fires a hook the moment the code is
        // computed (before it blocks on the device's verification response), so the CLI
        // can print it while the user confirms on the device.
        let mut bb = BitBox::new(
            BitBoxTransportHID::new(HidChannel::new(hid_dev.open().await?)),
            None,
        )
        .with_network(network);
        bb.set_pairing_code_hook(Box::new(|code| {
            eprintln!("\nBitBox02 pairing code — confirm on device:\n\n{code}\n");
        }));
        Ok(Some(
            Device::new(
                &name,
                DeviceType::BitBox02,
                path,
                "bitbox02",
                Box::new(bb),
                false,
            )
            .await?,
        ))
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for BitBoxDevice {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>> {
        let DeviceId { vid, pid, .. } = BITBOX02_DEVICE_ID;
        let pid = pid.context("bitbox02 pid not set")?;
        let devices: Vec<Device> = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok)
            .try_filter_map(|dev| async move {
                let path = hid_path(&dev);
                // A BitBox02 also exposes a FIDO/U2F HID interface (usage page 0xf1d0);
                // only the firmware interface speaks the HWW protocol.
                let is_bitbox = dev.vendor_id == vid
                    && dev.product_id == pid
                    && dev.usage_page == BITBOX02_HID_USAGE_PAGE
                    && BITBOX02_PRODUCT_STRINGS
                        .iter()
                        .any(|s| dev.name.contains(s));
                if selector.matches(DeviceType::BitBox02, &path) && is_bitbox {
                    Self::hid_device(dev, selector.network).await
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;
        Ok(devices)
    }
}

fn hid_path(dev: &HidDevice) -> String {
    let suffix = dev.serial_number.as_deref().unwrap_or(&dev.name);
    format!("hid:{:04x}:{:04x}:{suffix}", dev.vendor_id, dev.product_id)
}
