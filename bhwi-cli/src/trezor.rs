use std::time::Duration;

use anyhow::{Context, Result};
use async_hid::Device as HidDevice;
use async_hid::HidBackend;
use async_trait::async_trait;
use bhwi::trezor::{
    TREZOR_DEVICE_ID, TREZOR_ONE_DEVICE_ID, TREZOR_ONE_PID, TREZOR_ONE_VID, TREZOR_PID, TREZOR_VID,
};
use bhwi_async::{Trezor, transport::trezor::TrezorTransport};
use futures::stream::{StreamExt, TryStreamExt};

use crate::{
    Device, DeviceEnumerator, DeviceType, config::DeviceSelector, hid::HidChannel,
    trezor::emulator::EmulatorClient, webusb::WebUsbChannel,
};

pub type TrezorOneDevice = Trezor<TrezorTransport<HidChannel>>;
pub type TrezorWebUsbDevice = Trezor<TrezorTransport<WebUsbChannel>>;
pub type TrezorEmulatorDevice = Trezor<TrezorTransport<EmulatorClient>>;

const EMULATOR_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

pub struct TrezorDevice;

impl TrezorDevice {
    async fn hid_device(selector: &DeviceSelector, dev: HidDevice) -> Result<Option<Device>> {
        let network = selector.network;
        let path = hid_path(&dev);
        let name = dev.name.clone();
        let model = trezor_model(dev.product_id, false);
        let opened = match dev.open().await {
            Ok(opened) => opened,
            Err(err) => {
                eprintln!("Warning: skipping Trezor at {path}: {err}");
                return Ok(None);
            }
        };
        Ok(Some(
            Device::new(
                &name,
                DeviceType::Trezor,
                path,
                model,
                Box::new(
                    TrezorOneDevice::new(TrezorTransport::new(HidChannel::new(opened)))
                        .with_network(network)
                        .with_passphrase(selector.passphrase.clone()),
                ),
                false,
            )
            .await?,
        ))
    }

    async fn webusb_device(selector: &DeviceSelector, info: &nusb::DeviceInfo) -> Result<Device> {
        let network = selector.network;
        let channel = WebUsbChannel::open(info).await?;
        Device::new(
            "Trezor",
            DeviceType::Trezor,
            webusb_path(info),
            trezor_model(info.product_id(), false),
            Box::new(
                TrezorWebUsbDevice::new(TrezorTransport::new(channel))
                    .with_network(network)
                    .with_passphrase(selector.passphrase.clone()),
            ),
            false,
        )
        .await
    }

    async fn emulator_device(
        selector: &DeviceSelector,
        addr: &str,
        client: EmulatorClient,
    ) -> Result<Device> {
        Device::new(
            "Trezor Emulator",
            DeviceType::Trezor,
            addr,
            trezor_model(0, true),
            Box::new(
                TrezorEmulatorDevice::new(TrezorTransport::new(client))
                    .with_network(selector.network)
                    .with_passphrase(selector.passphrase.clone())
                    .with_emulator(true),
            ),
            true,
        )
        .await
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for TrezorDevice {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>> {
        let mut devices: Vec<Device> = HidBackend::default()
            .enumerate()
            .await?
            .map(Ok)
            .try_filter_map(|dev| async move {
                let path = hid_path(&dev);
                if selector.matches(DeviceType::Trezor, &path)
                    && dev.vendor_id == TREZOR_ONE_VID
                    && dev.product_id == TREZOR_ONE_PID
                    && dev.usage_page
                        == TREZOR_ONE_DEVICE_ID
                            .usage_page
                            .context("trezor one usage page constant not set")?
                {
                    Self::hid_device(selector, dev).await
                } else {
                    Ok(None)
                }
            })
            .try_collect()
            .await?;

        for info in nusb::list_devices()
            .await?
            .filter(|info| info.vendor_id() == TREZOR_VID && info.product_id() == TREZOR_PID)
        {
            let path = webusb_path(&info);
            if !selector.matches(DeviceType::Trezor, &path) {
                continue;
            }
            match Self::webusb_device(selector, &info).await {
                Ok(device) => devices.push(device),
                Err(err) => eprintln!("Warning: skipping Trezor at {path}: {err}"),
            }
        }

        if selector.include_emulators
            && let Some(addr) = TREZOR_DEVICE_ID.emulator_path
            && (selector.matches(DeviceType::Trezor, addr)
                || selector.matches(DeviceType::Trezor, emulator_socket(addr)))
            && let Ok(client) = EmulatorClient::new(addr).await
            && client.ping(EMULATOR_PROBE_TIMEOUT).await
        {
            devices.push(Self::emulator_device(selector, addr, client).await?);
        }

        Ok(devices)
    }
}

fn emulator_socket(path: &str) -> &str {
    path.strip_prefix("udp:").unwrap_or(path)
}

fn webusb_path(info: &nusb::DeviceInfo) -> String {
    let mut path = format!("webusb:{}", bus_number(info.bus_id()));
    for port in info.port_chain() {
        path.push_str(&format!(":{port}"));
    }
    path
}

fn bus_number(bus_id: &str) -> String {
    let parsed = if cfg!(target_os = "macos") {
        u32::from_str_radix(bus_id, 16).ok()
    } else {
        bus_id.parse::<u32>().ok()
    };
    match parsed {
        Some(bus) => format!("{bus:03}"),
        None => bus_id.to_owned(),
    }
}

fn hid_path(dev: &HidDevice) -> String {
    let suffix = dev.serial_number.as_deref().unwrap_or(&dev.name);
    format!("hid:{:04x}:{:04x}:{suffix}", dev.vendor_id, dev.product_id)
}

fn trezor_model(product_id: u16, is_emulated: bool) -> &'static str {
    match (product_id, is_emulated) {
        (_, true) => "trezor_emulator",
        (TREZOR_ONE_PID, false) => "trezor_one",
        (TREZOR_PID, false) => "trezor_t",
        _ => "trezor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_number_is_three_digit_decimal() {
        if cfg!(target_os = "macos") {
            assert_eq!(bus_number("14"), "020");
            assert_eq!(bus_number("01"), "001");
        } else {
            assert_eq!(bus_number("001"), "001");
            assert_eq!(bus_number("20"), "020");
        }
    }

    #[test]
    fn bus_number_falls_back_to_the_raw_id() {
        assert_eq!(bus_number("PCIROOT(0)#PCI(0201)"), "PCIROOT(0)#PCI(0201)");
    }

    #[test]
    fn emulator_socket_accepts_both_forms() {
        assert_eq!(emulator_socket("udp:127.0.0.1:21324"), "127.0.0.1:21324");
        assert_eq!(emulator_socket("127.0.0.1:21324"), "127.0.0.1:21324");
    }
}

pub mod emulator {
    use std::time::Duration;

    use anyhow::Result;
    use async_trait::async_trait;
    use bhwi_async::transport::Channel;
    use tokio::net::UdpSocket;

    pub use bhwi::trezor::DEFAULT_TREZOR_EMULATOR as DEFAULT_EMULATOR_ADDR;

    const PING: &[u8; 8] = b"PINGPING";
    const PONG: &[u8; 8] = b"PONGPONG";

    pub struct EmulatorClient {
        socket: UdpSocket,
    }

    impl EmulatorClient {
        pub async fn new(addr: &str) -> Result<Self> {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(super::emulator_socket(addr)).await?;
            Ok(Self { socket })
        }

        // UDP has no connect to probe, so absence shows up only as no answer.
        pub async fn ping(&self, timeout: Duration) -> bool {
            if self.socket.send(PING).await.is_err() {
                return false;
            }
            let mut buf = [0u8; PONG.len()];
            matches!(
                tokio::time::timeout(timeout, self.socket.recv(&mut buf)).await,
                Ok(Ok(read)) if read == PONG.len() && &buf == PONG
            )
        }
    }

    #[async_trait(?Send)]
    impl Channel for EmulatorClient {
        async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
            self.socket.send(data).await
        }

        async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
            self.socket.recv(data).await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use bhwi_async::Transport;
        use bhwi_async::transport::trezor::TrezorTransport;

        const REPORT_SIZE: usize = 64;

        fn v1_frame(msg_type: u16, payload: &[u8]) -> Vec<u8> {
            let mut frame = b"##".to_vec();
            frame.extend_from_slice(&msg_type.to_be_bytes());
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(payload);
            frame
        }

        async fn peer() -> (UdpSocket, String) {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap().to_string();
            (socket, addr)
        }

        #[tokio::test]
        async fn ping_detects_a_listening_emulator() {
            let (socket, addr) = peer().await;
            tokio::spawn(async move {
                let mut buf = [0u8; REPORT_SIZE];
                let (read, from) = socket.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..read], PING);
                socket.send_to(PONG, from).await.unwrap();
            });

            let client = EmulatorClient::new(&addr).await.unwrap();
            assert!(client.ping(Duration::from_secs(5)).await);
        }

        #[tokio::test]
        async fn ping_reports_a_missing_emulator() {
            let (socket, addr) = peer().await;
            drop(socket);

            let client = EmulatorClient::new(&addr).await.unwrap();
            assert!(!client.ping(Duration::from_millis(250)).await);
        }

        #[tokio::test]
        async fn reports_round_trip_over_udp() {
            let (socket, addr) = peer().await;
            let reply = v1_frame(30, &[0xab; 100]);
            let replied = reply.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; REPORT_SIZE];
                let (_, from) = socket.recv_from(&mut buf).await.unwrap();
                for chunk in replied.chunks(REPORT_SIZE - 1) {
                    let mut report = [0u8; REPORT_SIZE];
                    report[0] = 0x3f;
                    report[1..1 + chunk.len()].copy_from_slice(chunk);
                    socket.send_to(&report, from).await.unwrap();
                }
            });

            let client = EmulatorClient::new(&addr).await.unwrap();
            let mut transport = TrezorTransport::new(client);
            let out = transport.exchange(&v1_frame(29, b""), false).await.unwrap();
            assert_eq!(out, reply);
        }
    }
}
