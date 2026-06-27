use anyhow::Context;
use anyhow::Result;
use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi_async::{
    coldcard::Coldcard,
    transport::{
        DeviceId,
        coldcard::hid::{COLDCARD_DEVICE_ID, ColdcardTransportHID},
    },
};
use futures::StreamExt;
use futures::TryStreamExt;
use rand_core::OsRng;

use crate::{Device, DeviceEnumerator, DeviceType, config::DeviceSelector, hid::HidChannel};

pub type ColdcardHidDevice = Coldcard<ColdcardTransportHID<HidChannel>>;

pub struct ColdcardDevice;

impl ColdcardDevice {
    async fn hid_device(hid_dev: HidDevice, rng: &mut OsRng) -> Result<Option<Device>> {
        let path = hid_path(&hid_dev);
        let name = hid_dev.name.clone();
        Ok(Some(
            Device::new(
                &name,
                DeviceType::Coldcard,
                path,
                "coldcard",
                Box::new(Coldcard::new(
                    ColdcardTransportHID::new(HidChannel::new(hid_dev.open().await?)),
                    rng,
                )),
                false,
            )
            .await?,
        ))
    }

    #[cfg(unix)]
    async fn emulator_device(path: &str, rng: &mut OsRng) -> Result<Option<Device>> {
        if std::fs::exists(path)? {
            let Ok(client) = emulator::EmulatorClient::new(path).await else {
                return Ok(None);
            };
            let device = Device::new(
                "Coldcard Emulator",
                DeviceType::Coldcard,
                path,
                "coldcard_simulator",
                Box::new(Coldcard::new(ColdcardTransportHID::new(client), rng)),
                true,
            )
            .await?;
            Ok(Some(device))
        } else {
            Ok(None)
        }
    }

    #[cfg(not(unix))]
    async fn emulator_device(_path: &str, _rng: &mut OsRng) -> Result<Option<Device>> {
        Ok(None)
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for ColdcardDevice {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>> {
        let DeviceId {
            vid,
            pid,
            emulator_path,
            ..
        } = COLDCARD_DEVICE_ID;
        let mut rng = OsRng;
        let mut devices: Vec<Device> = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok)
            .try_filter_map(|dev| async move {
                let path = hid_path(&dev);
                if selector.matches(DeviceType::Coldcard, &path)
                    && dev.vendor_id == vid
                    && dev.product_id == pid.context("coldcard pid not set")?
                {
                    Self::hid_device(dev, &mut rng).await
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;
        if selector.include_emulators
            && let Some(path) = emulator_path
            && selector.matches(DeviceType::Coldcard, path)
            && let Some(device) = Self::emulator_device(path, &mut rng).await?
        {
            devices.push(device);
        }
        Ok(devices)
    }
}

fn hid_path(dev: &HidDevice) -> String {
    let suffix = dev.serial_number.as_deref().unwrap_or(&dev.name);
    format!("hid:{:04x}:{:04x}:{suffix}", dev.vendor_id, dev.product_id)
}

#[cfg(unix)]
pub mod emulator {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use anyhow::Result;
    use async_trait::async_trait;
    use bhwi_async::{
        coldcard::Coldcard,
        transport::{Channel, coldcard::hid::ColdcardTransportHID},
    };
    use tokio::net::UnixDatagram;

    static CLIENT_SOCKET_COUNTER: AtomicUsize = AtomicUsize::new(0);

    pub type ColdcardSocketDevice = Coldcard<ColdcardTransportHID<EmulatorClient>>;

    #[derive(Clone)]
    pub struct EmulatorClient {
        /// the ckcc simulator socket (used for ckcc cli too)
        socket: Arc<UnixDatagram>,
    }

    impl EmulatorClient {
        pub async fn new(socket_path: &str) -> Result<Self> {
            let socket_id = CLIENT_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
            let client_socket = format!(
                "/tmp/bhwi-ckcc-client-{}-{socket_id}.sock",
                std::process::id()
            );
            let _ = std::fs::remove_file(&client_socket);
            let socket = UnixDatagram::bind(client_socket)?;
            socket.connect(socket_path)?;
            Ok(Self {
                socket: Arc::new(socket),
            })
        }
    }

    #[async_trait(?Send)]
    impl Channel for EmulatorClient {
        async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
            self.socket.send(data).await?;
            Ok(data.len())
        }

        async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
            Ok(self.socket.recv(data).await?)
        }
    }
}
