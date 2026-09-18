use std::{io, sync::Arc, time::Duration};

use crate::{NativeError, NativeResult};
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

use crate::{
    Device, DeviceCandidate, DeviceEnumerator, DeviceSelector, DeviceType, HostInteractionFactory,
    PairingCodePrompt,
    hid::{HidChannel, find_hid, hid_path},
};

pub struct BitBoxDevice;

impl BitBoxDevice {
    /// A BitBox02 also exposes a FIDO/U2F HID interface (usage page 0xf1d0);
    /// only the firmware interface speaks the HWW protocol.
    fn is_bitbox(dev: &HidDevice) -> NativeResult<bool> {
        let DeviceId { vid, pid, .. } = BITBOX02_DEVICE_ID;
        let pid = pid.ok_or(NativeError::MissingDeviceId("bitbox02 pid not set"))?;
        Ok(dev.vendor_id == vid
            && dev.product_id == pid
            && dev.usage_page == BITBOX02_HID_USAGE_PAGE
            && BITBOX02_PRODUCT_STRINGS
                .iter()
                .any(|s| dev.name.contains(s)))
    }

    async fn open_hid(
        candidate: &DeviceCandidate,
        network: bitcoin::Network,
        pairing_code: Option<&PairingCodePrompt>,
    ) -> NativeResult<Device> {
        let dev = find_hid(|dev| {
            hid_path(dev) == candidate.path && Self::is_bitbox(dev).unwrap_or(false)
        })
        .await?
        .ok_or_else(|| NativeError::Gone(candidate.path.clone()))?;
        let name = dev.name.clone();
        let opened = dev.open().await?;
        // No cached pairing data yet — a filesystem-backed store can be plugged in later.
        // First-time pairing: the interpreter fires a hook the moment the code is
        // computed (before it blocks on the device's verification response), so the CLI
        // can print it while the user confirms on the device.
        let mut bb = BitBox::new(BitBoxTransportHID::new(HidChannel::new(opened)), None)
            .with_network(network);
        if let Some(prompt) = pairing_code.cloned() {
            bb.set_pairing_code_hook(Box::new(move |code| prompt(code)));
        }
        Ok(Device::new(
            &name,
            DeviceType::BitBox02,
            &candidate.path,
            &candidate.model,
            Box::new(bb),
            false,
        ))
    }

    async fn open_simulator(
        candidate: &DeviceCandidate,
        network: bitcoin::Network,
    ) -> NativeResult<Device> {
        // The simulator speaks the same U2F-HID framing as real hardware, so the only
        // difference from the HID path is the underlying byte channel (a TCP stream here).
        // No pairing-code hook: the simulator auto-confirms pairing, so surfacing a code
        // would only add noise (and stderr) to scripted/emulator runs.
        let stream = TcpStream::connect(simulator_tcp_addr(&candidate.path)).await?;
        let bb = BitBox::new(BitBoxTransportHID::new(BitBoxTcpChannel::new(stream)), None)
            .with_network(network);
        Ok(Device::new(
            &candidate.name,
            DeviceType::BitBox02,
            &candidate.path,
            &candidate.model,
            Box::new(bb),
            true,
        ))
    }
}

fn simulator_tcp_addr(path: &str) -> &str {
    path.strip_prefix("tcp:").unwrap_or(path)
}

#[async_trait(?Send)]
impl DeviceEnumerator for BitBoxDevice {
    async fn list(selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>> {
        let DeviceId { emulator_path, .. } = BITBOX02_DEVICE_ID;
        let mut candidates: Vec<DeviceCandidate> = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok::<HidDevice, NativeError>)
            .try_filter_map(|dev| async move {
                let path = hid_path(&dev);
                if selector.matches(DeviceType::BitBox02, &path) && Self::is_bitbox(&dev)? {
                    Ok(Some(DeviceCandidate {
                        device_type: DeviceType::BitBox02,
                        name: dev.name.clone(),
                        model: "bitbox02".to_owned(),
                        path,
                        is_emulated: false,
                    }))
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;
        // Only a connection tells us the simulator is there; it is dropped again.
        if selector.include_emulators
            && let Some(path) = emulator_path
            && {
                let addr = simulator_tcp_addr(path);
                selector.matches(DeviceType::BitBox02, path)
                    || selector.matches(DeviceType::BitBox02, addr)
            }
            && TcpStream::connect(simulator_tcp_addr(path)).await.is_ok()
        {
            candidates.push(DeviceCandidate {
                device_type: DeviceType::BitBox02,
                name: "BitBox02 Simulator".to_owned(),
                model: "bitbox02_simulator".to_owned(),
                path: path.to_owned(),
                is_emulated: true,
            });
        }
        Ok(candidates)
    }

    async fn open(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        if candidate.is_emulated {
            Self::open_simulator(candidate, selector.network).await
        } else {
            Self::open_hid(candidate, selector.network, pairing_code).await
        }
    }
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
