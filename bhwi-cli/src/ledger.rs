use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi_async::{
    Ledger,
    transport::{
        Channel, DeviceId,
        ledger::{
            hid::{LEDGER_DEVICE_ID, LedgerTransportHID},
            speculos::LedgerTransportTcp,
        },
    },
};
use futures::stream::{StreamExt, TryStreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::{Device, DeviceEnumerator, DeviceType, config::DeviceSelector, hid::HidChannel};

pub type LedgerHidDevice = Ledger<LedgerTransportHID<HidChannel>>;
pub type LedgerSpeculosDevice = Ledger<LedgerTransportTcp<SpeculosTcpChannel>>;

pub struct LedgerDevice;

impl LedgerDevice {
    async fn hid_device(dev: HidDevice) -> Result<Option<Device>> {
        let path = hid_path(&dev);
        let name = dev.name.clone();
        Ok(Some(
            Device::new(
                &name,
                DeviceType::Ledger,
                path,
                ledger_model(dev.product_id, false),
                Box::new(LedgerHidDevice::new(LedgerTransportHID::new(
                    HidChannel::new(dev.open().await?),
                ))),
                false,
            )
            .await?,
        ))
    }

    async fn speculos_device(path: &str, stream: TcpStream) -> Result<Device> {
        Device::new(
            "Ledger Speculos Emulator",
            DeviceType::Ledger,
            path,
            ledger_model(0x1000, true),
            Box::new(LedgerSpeculosDevice::new(LedgerTransportTcp::new(
                SpeculosTcpChannel {
                    stream: Arc::new(Mutex::new(stream)),
                },
            ))),
            true,
        )
        .await
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for LedgerDevice {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>> {
        let DeviceId {
            vid,
            usage_page,
            emulator_path,
            ..
        } = LEDGER_DEVICE_ID;
        let mut devices: Vec<Device> = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok)
            .try_filter_map(|dev| async move {
                let path = hid_path(&dev);
                if selector.matches(DeviceType::Ledger, &path)
                    && dev.vendor_id == vid
                    && dev.usage_page == usage_page.context("ledger usage page constant not set")?
                {
                    Self::hid_device(dev).await
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;
        if selector.include_emulators
            && let Some(path) = emulator_path
            && selector.matches(DeviceType::Ledger, path)
            && let Ok(stream) = TcpStream::connect(path).await
        {
            devices.push(Self::speculos_device(path, stream).await?);
        }
        Ok(devices)
    }
}

fn hid_path(dev: &HidDevice) -> String {
    let suffix = dev.serial_number.as_deref().unwrap_or(&dev.name);
    format!("hid:{:04x}:{:04x}:{suffix}", dev.vendor_id, dev.product_id)
}

fn ledger_model(product_id: u16, is_emulated: bool) -> &'static str {
    match (product_id >> 8, product_id, is_emulated) {
        (0x10, _, true) => "ledger_nano_s_simulator",
        (0x10, _, false) | (_, 0x0001, false) => "ledger_nano_s",
        (0x40, _, false) | (_, 0x0004, false) => "ledger_nano_x",
        (0x50, _, false) => "ledger_nano_s_plus",
        (0x60, _, false) => "ledger_stax",
        (0x70, _, false) => "ledger_flex",
        _ => "ledger",
    }
}

pub struct SpeculosTcpChannel {
    stream: Arc<Mutex<TcpStream>>,
}

impl SpeculosTcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
        }
    }
}

#[async_trait(?Send)]
impl Channel for SpeculosTcpChannel {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.stream.lock().await.write_all(data).await?;
        Ok(data.len())
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        self.stream.lock().await.read_exact(data).await
    }
}
