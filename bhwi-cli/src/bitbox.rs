use std::{io, sync::Arc, time::Duration};

use anyhow::Context;
use anyhow::Result;
use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi_async::{
    bitbox::BitBox,
    transport::{
        Channel, DeviceId,
        bitbox::hid::{
            BITBOX02_DEVICE_ID, BITBOX02_HID_USAGE_PAGE, BITBOX02_PRODUCT_STRINGS,
            BitBoxTransportHID,
        },
    },
};
use futures::StreamExt;
use futures::TryStreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

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

    async fn simulator_device(
        path: &str,
        stream: TcpStream,
        network: bitcoin::Network,
    ) -> Result<Device> {
        // The simulator speaks the same U2F-HID framing as real hardware, so the only
        // difference from the HID path is the underlying byte channel (a TCP stream here).
        // No pairing-code hook: the simulator auto-confirms pairing, so surfacing a code
        // would only add noise (and stderr) to scripted/emulator runs.
        let bb = BitBox::new(BitBoxTransportHID::new(BitBoxTcpChannel::new(stream)), None)
            .with_network(network);
        Device::new(
            "BitBox02 Simulator",
            DeviceType::BitBox02,
            path,
            "bitbox02_simulator",
            Box::new(bb),
            true,
        )
        .await
    }
}

fn simulator_tcp_addr(path: &str) -> &str {
    path.strip_prefix("tcp:").unwrap_or(path)
}

#[async_trait(?Send)]
impl DeviceEnumerator for BitBoxDevice {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>> {
        let DeviceId {
            vid,
            pid,
            emulator_path,
            ..
        } = BITBOX02_DEVICE_ID;
        let pid = pid.context("bitbox02 pid not set")?;
        let mut devices: Vec<Device> = HidBackend::default()
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
        if selector.include_emulators
            && let Some(path) = emulator_path
            && {
                let addr = simulator_tcp_addr(path);
                selector.matches(DeviceType::BitBox02, path)
                    || selector.matches(DeviceType::BitBox02, addr)
            }
            && let Ok(stream) = TcpStream::connect(simulator_tcp_addr(path)).await
        {
            devices.push(Self::simulator_device(path, stream, selector.network).await?);
        }
        Ok(devices)
    }
}

fn hid_path(dev: &HidDevice) -> String {
    let suffix = dev.serial_number.as_deref().unwrap_or(&dev.name);
    format!("hid:{:04x}:{:04x}:{suffix}", dev.vendor_id, dev.product_id)
}

/// A `Channel` over a raw TCP connection to the BitBox02 simulator.
pub struct BitBoxTcpChannel {
    stream: Arc<Mutex<TcpStream>>,
}

impl BitBoxTcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
        }
    }
}

#[async_trait(?Send)]
impl Channel for BitBoxTcpChannel {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        let mut stream = self.stream.lock().await;
        stream.write_all(data).await?;
        stream.flush().await?;
        Ok(data.len())
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut stream = self.stream.lock().await;
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(data))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "BitBox02 response timed out")
            })??;
        Ok(data.len())
    }
}
