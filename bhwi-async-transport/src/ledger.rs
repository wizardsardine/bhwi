use std::sync::Arc;

use crate::{NativeError, NativeResult};
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

use crate::{
    Device, DeviceCandidate, DeviceEnumerator, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt,
    hid::{HidChannel, find_hid, hid_path},
};

pub type LedgerHidDevice = Ledger<LedgerTransportHID<HidChannel>>;
pub type LedgerSpeculosDevice = Ledger<LedgerTransportTcp<SpeculosTcpChannel>>;

pub struct LedgerDevice;

impl LedgerDevice {
    /// A Ledger also exposes a U2F interface at this vendor id.
    fn is_ledger(dev: &HidDevice) -> NativeResult<bool> {
        let DeviceId {
            vid, usage_page, ..
        } = LEDGER_DEVICE_ID;
        Ok(dev.vendor_id == vid
            && dev.usage_page
                == usage_page.ok_or(NativeError::MissingDeviceId(
                    "ledger usage page constant not set",
                ))?)
    }

    async fn open_hid(candidate: &DeviceCandidate) -> NativeResult<Device> {
        let dev = find_hid(|dev| {
            hid_path(dev) == candidate.path && Self::is_ledger(dev).unwrap_or(false)
        })
        .await?
        .ok_or_else(|| NativeError::Gone(candidate.path.clone()))?;
        let name = dev.name.clone();
        let opened = dev.open().await?;
        Ok(Device::new(
            &name,
            DeviceType::Ledger,
            &candidate.path,
            &candidate.model,
            Box::new(LedgerHidDevice::new(LedgerTransportHID::new(
                HidChannel::new(opened),
            ))),
            false,
        ))
    }

    async fn open_speculos(candidate: &DeviceCandidate) -> NativeResult<Device> {
        let stream = TcpStream::connect(speculos_tcp_addr(&candidate.path)).await?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Ledger,
            &candidate.path,
            &candidate.model,
            Box::new(LedgerSpeculosDevice::new(LedgerTransportTcp::new(
                SpeculosTcpChannel {
                    stream: Arc::new(Mutex::new(stream)),
                },
            ))),
            true,
        ))
    }
}

fn speculos_tcp_addr(path: &str) -> &str {
    path.strip_prefix("tcp:").unwrap_or(path)
}

#[async_trait(?Send)]
impl DeviceEnumerator for LedgerDevice {
    async fn list(selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>> {
        let DeviceId { emulator_path, .. } = LEDGER_DEVICE_ID;
        let mut candidates: Vec<DeviceCandidate> = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok::<HidDevice, NativeError>)
            .try_filter_map(|dev| async move {
                let path = hid_path(&dev);
                if selector.matches(DeviceType::Ledger, &path) && Self::is_ledger(&dev)? {
                    Ok(Some(DeviceCandidate {
                        device_type: DeviceType::Ledger,
                        name: dev.name.clone(),
                        model: ledger_model(dev.product_id, false).to_owned(),
                        path,
                        is_emulated: false,
                    }))
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;
        // Only a connection tells us speculos is there; it is dropped again.
        if selector.include_emulators
            && let Some(path) = emulator_path
            && {
                let addr = speculos_tcp_addr(path);
                selector.matches(DeviceType::Ledger, path)
                    || selector.matches(DeviceType::Ledger, addr)
            }
            && TcpStream::connect(speculos_tcp_addr(path)).await.is_ok()
        {
            candidates.push(DeviceCandidate {
                device_type: DeviceType::Ledger,
                name: "Ledger Speculos Emulator".to_owned(),
                model: ledger_model(0x1000, true).to_owned(),
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
            Self::open_speculos(candidate).await
        } else {
            Self::open_hid(candidate).await
        }
    }
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
