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
use futures::stream::{StreamExt, TryStreamExt, iter};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::{Device, DeviceEnumerator, config::Config, hid::HidChannel};

pub type LedgerHidDevice = Ledger<LedgerTransportHID<HidChannel>>;
pub type LedgerSpeculosDevice = Ledger<LedgerTransportTcp<SpeculosTcpChannel>>;

pub struct LedgerDevice;

impl LedgerDevice {
    async fn hid_device(dev: HidDevice) -> Result<Option<Device>> {
        Ok(Some(
            Device::new(
                &dev.name,
                Box::new(LedgerHidDevice::new(LedgerTransportHID::new(
                    HidChannel::new(dev.open().await?),
                ))),
                false,
            )
            .await?,
        ))
    }

    async fn speculos_device(stream: TcpStream) -> Result<Device> {
        Device::new(
            "Ledger Speculos Emulator",
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
    async fn enumerate(_config: &Config) -> Result<Vec<Device>> {
        let DeviceId {
            vid,
            usage_page,
            emulator_path,
            ..
        } = LEDGER_DEVICE_ID;
        let devices = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok)
            .try_filter_map(|dev| async move {
                if dev.vendor_id == vid
                    && dev.usage_page == usage_page.context("ledger usage page constant not set")?
                {
                    Self::hid_device(dev).await
                } else {
                    Ok(None)
                }
            })
            .chain(
                iter(emulator_path.map(Ok).into_iter()).try_filter_map(|path| async move {
                    if let Ok(stream) = TcpStream::connect(path).await {
                        Ok(Some(Self::speculos_device(stream).await?))
                    } else {
                        Ok(None)
                    }
                }),
            )
            .try_collect()
            .await?;
        Ok(devices)
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
