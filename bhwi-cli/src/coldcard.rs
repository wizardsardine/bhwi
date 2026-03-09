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
use futures::stream::iter;
use rand_core::OsRng;

use crate::{Device, DeviceEnumerator, config::Config, hid::HidChannel};

pub type ColdcardHidDevice = Coldcard<ColdcardTransportHID<HidChannel>>;

pub struct ColdcardDevice;

impl ColdcardDevice {
    async fn hid_device(hid_dev: HidDevice, rng: &mut OsRng) -> Result<Option<Device>> {
        Ok(Some(
            Device::new(
                &hid_dev.name,
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
            Ok(Some(
                Device::new(
                    "Coldcard Emulator",
                    Box::new(Coldcard::new(
                        ColdcardTransportHID::new(emulator::EmulatorClient::new(path).await?),
                        rng,
                    )),
                    true,
                )
                .await?,
            ))
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
    async fn enumerate(_config: &Config) -> Result<Vec<Device>> {
        let DeviceId {
            vid,
            pid,
            emulator_path,
            ..
        } = COLDCARD_DEVICE_ID;
        let mut rng = OsRng;
        let devices = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok)
            .try_filter_map(|dev| async move {
                if dev.vendor_id == vid && dev.product_id == pid.context("coldcard pid not set")? {
                    Self::hid_device(dev, &mut rng).await
                } else {
                    Ok(None)
                }
            })
            .chain(
                iter(emulator_path.map(Ok).into_iter()).try_filter_map(|path| async move {
                    Self::emulator_device(path, &mut rng).await
                }),
            )
            .try_collect()
            .await?;
        Ok(devices)
    }
}

#[cfg(unix)]
pub mod emulator {
    use std::sync::Arc;

    use anyhow::Result;
    use async_trait::async_trait;
    use bhwi_async::{
        coldcard::Coldcard,
        transport::{Channel, coldcard::hid::ColdcardTransportHID},
    };
    use tokio::net::UnixDatagram;

    const CLIENT_SOCKET: &str = "/tmp/bhwi-ckcc-client.sock";

    pub type ColdcardSocketDevice = Coldcard<ColdcardTransportHID<EmulatorClient>>;

    #[derive(Clone)]
    pub struct EmulatorClient {
        /// the ckcc simulator socket (used for ckcc cli too)
        socket: Arc<UnixDatagram>,
    }

    impl EmulatorClient {
        pub async fn new(socket_path: &str) -> Result<Self> {
            let _ = std::fs::remove_file(CLIENT_SOCKET);
            let socket = UnixDatagram::bind(CLIENT_SOCKET)?;
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
