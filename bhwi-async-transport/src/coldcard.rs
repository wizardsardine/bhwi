use crate::{NativeError, NativeResult};
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

use crate::{
    Device, DeviceEnumerator, DeviceScan, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt, ScanEntry, hid::HidChannel,
};

pub type ColdcardHidDevice = Coldcard<ColdcardTransportHID<HidChannel>>;

pub struct ColdcardDevice;

impl ColdcardDevice {
    async fn hid_device(hid_dev: HidDevice, rng: &mut OsRng) -> NativeResult<ScanEntry> {
        let path = hid_path(&hid_dev);
        let name = hid_dev.name.clone();
        let opened = match hid_dev.open().await {
            Ok(opened) => opened,
            Err(err) => {
                return Ok(ScanEntry::skipped(
                    DeviceType::Coldcard,
                    "coldcard",
                    path,
                    &err,
                ));
            }
        };
        Ok(ScanEntry::Found(Device::new(
            &name,
            DeviceType::Coldcard,
            path,
            "coldcard",
            Box::new(Coldcard::new(
                ColdcardTransportHID::new(HidChannel::new(opened)),
                rng,
            )),
            false,
        )))
    }

    #[cfg(unix)]
    async fn emulator_device(path: &str, rng: &mut OsRng) -> NativeResult<Option<ScanEntry>> {
        if !std::fs::exists(path)? {
            return Ok(None);
        }
        let client = match emulator::EmulatorClient::new(path).await {
            Ok(client) => client,
            Err(err) => {
                return Ok(Some(ScanEntry::skipped(
                    DeviceType::Coldcard,
                    "coldcard_simulator",
                    path,
                    &err,
                )));
            }
        };
        Ok(Some(ScanEntry::Found(Device::new(
            "Coldcard Emulator",
            DeviceType::Coldcard,
            path,
            "coldcard_simulator",
            Box::new(Coldcard::new(ColdcardTransportHID::new(client), rng)),
            true,
        ))))
    }

    #[cfg(not(unix))]
    async fn emulator_device(_path: &str, _rng: &mut OsRng) -> NativeResult<Option<ScanEntry>> {
        Ok(None)
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for ColdcardDevice {
    async fn enumerate(
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<DeviceScan> {
        let DeviceId {
            vid,
            pid,
            emulator_path,
            ..
        } = COLDCARD_DEVICE_ID;
        let mut rng = OsRng;
        let mut scan: DeviceScan = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok)
            .try_filter_map(|dev| async move {
                let path = hid_path(&dev);
                if selector.matches(DeviceType::Coldcard, &path)
                    && dev.vendor_id == vid
                    && dev.product_id
                        == pid.ok_or(NativeError::MissingDeviceId("coldcard pid not set"))?
                {
                    Self::hid_device(dev, &mut rng).await.map(Some)
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;
        if selector.include_emulators
            && let Some(path) = emulator_path
            && selector.matches(DeviceType::Coldcard, path)
            && let Some(entry) = Self::emulator_device(path, &mut rng).await?
        {
            scan.extend([entry]);
        }
        Ok(scan)
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
        pub async fn new(socket_path: &str) -> std::io::Result<Self> {
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
