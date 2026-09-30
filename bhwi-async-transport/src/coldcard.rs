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
    Device, DeviceCandidate, DeviceEnumerator, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt,
    hid::{HidChannel, find_hid, hid_path},
};

pub type ColdcardHidDevice = Coldcard<ColdcardTransportHID<HidChannel>>;

pub struct ColdcardDevice;

impl ColdcardDevice {
    fn is_coldcard(dev: &HidDevice) -> bool {
        let DeviceId { vid, pid, .. } = COLDCARD_DEVICE_ID;
        dev.vendor_id == vid && Some(dev.product_id) == pid
    }

    async fn open_hid(candidate: &DeviceCandidate) -> NativeResult<Device> {
        let dev = find_hid(|dev| hid_path(dev) == candidate.path && Self::is_coldcard(dev))
            .await?
            .ok_or_else(|| NativeError::Gone(candidate.path.clone()))?;
        let name = dev.name.clone();
        let opened = dev.open().await?;
        Ok(Device::new(
            &name,
            DeviceType::Coldcard,
            &candidate.path,
            &candidate.model,
            Box::new(Coldcard::new(
                ColdcardTransportHID::new(HidChannel::new(opened)),
                &mut OsRng,
            )),
            false,
        ))
    }

    #[cfg(unix)]
    async fn open_emulator(candidate: &DeviceCandidate) -> NativeResult<Device> {
        let client = emulator::EmulatorClient::new(&candidate.path).await?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Coldcard,
            &candidate.path,
            &candidate.model,
            Box::new(Coldcard::new(ColdcardTransportHID::new(client), &mut OsRng)),
            true,
        ))
    }

    #[cfg(not(unix))]
    async fn open_emulator(candidate: &DeviceCandidate) -> NativeResult<Device> {
        Err(NativeError::Gone(candidate.path.clone()))
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for ColdcardDevice {
    async fn list(selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>> {
        let DeviceId { emulator_path, .. } = COLDCARD_DEVICE_ID;
        let mut candidates: Vec<DeviceCandidate> = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok::<HidDevice, NativeError>)
            .try_filter_map(|dev| async move {
                if selector.matches(DeviceType::Coldcard, &hid_path(&dev))
                    && Self::is_coldcard(&dev)
                {
                    Ok(Some(DeviceCandidate {
                        device_type: DeviceType::Coldcard,
                        name: dev.name.clone(),
                        model: "coldcard".to_owned(),
                        path: hid_path(&dev),
                        is_emulated: false,
                    }))
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;
        if selector.include_emulators
            && let Some(path) = emulator_path
            && selector.matches(DeviceType::Coldcard, path)
            && std::fs::exists(path)?
        {
            candidates.push(DeviceCandidate {
                device_type: DeviceType::Coldcard,
                name: "Coldcard Emulator".to_owned(),
                model: "coldcard_simulator".to_owned(),
                path: path.to_owned(),
                is_emulated: true,
            });
        }
        Ok(candidates)
    }

    async fn open(
        candidate: &DeviceCandidate,
        _selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        if candidate.is_emulated {
            Self::open_emulator(candidate).await
        } else {
            Self::open_hid(candidate).await
        }
    }
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
