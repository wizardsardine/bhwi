use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bhwi_async::{
    HttpClient, Jade, Transport,
    transport::jade::{CborStream, JADE_DEVICE_IDS, tcp::TcpTransport},
};
use bitcoin::Network;
use futures::{TryStreamExt, stream::iter};
use reqwest::Client;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_serial::{
    SerialPort, SerialPortBuilderExt, SerialPortType, SerialStream, UsbPortInfo, available_ports,
};

use crate::{Device, DeviceEnumerator, config::Config};

pub type JadeSerialDevice = Jade<SerialTransport, PinServerClient>;
pub type JadeQemuDevice = Jade<TcpTransport<TcpClient>, PinServerClient>;

pub const DEFAULT_JADE_BAUD_RATE: u32 = 115200;
pub const DEFAULT_JADE_QEMU_ADDRESS: &str = "localhost:30121";

pub struct SerialTransport {
    stream: Arc<Mutex<SerialStream>>,
}

impl SerialTransport {
    pub fn new(port_name: &str) -> Result<Self> {
        let mut transport =
            tokio_serial::new(port_name, DEFAULT_JADE_BAUD_RATE).open_native_async()?;
        // Ensure RTS and DTR are not set (as this can cause the hw to reboot)
        // according to https://github.com/Blockstream/Jade/blob/master/jadepy/jade_serial.py#L56
        transport.write_request_to_send(false)?;
        transport.write_data_terminal_ready(false)?;
        Ok(Self {
            stream: Arc::new(Mutex::new(transport)),
        })
    }
}

#[async_trait(?Send)]
impl Transport for SerialTransport {
    type Error = std::io::Error;
    async fn exchange(&mut self, command: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        self.write_all(command).await?;
        self.read_cbor_message().await
    }
}

#[async_trait(?Send)]
impl CborStream for SerialTransport {
    async fn write_all(&mut self, command: &[u8]) -> Result<(), std::io::Error> {
        let mut stream = self.stream.lock().await;
        Ok(stream.write_all(command).await?)
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut stream = self.stream.lock().await;
        Ok(stream.read(buf).await?)
    }
}

pub struct JadeDevice;

impl JadeDevice {
    fn valid_usb(info: &UsbPortInfo) -> bool {
        JADE_DEVICE_IDS
            .iter()
            .find(|id| id.vid == info.vid && id.pid == Some(info.pid))
            .is_some()
    }

    async fn serial_device(
        network: Network,
        port_name: &str,
        info: UsbPortInfo,
    ) -> Result<Option<Device>> {
        Ok(Some(
            Device::new(
                &format!(
                    "{} {}",
                    info.product.unwrap_or_else(|| "Jade".into()),
                    info.manufacturer.unwrap_or_else(|| "Blockstream".into())
                ),
                Box::new(JadeSerialDevice::new(
                    network,
                    SerialTransport::new(port_name)?,
                    PinServerClient::new(),
                )),
                false,
            )
            .await?,
        ))
    }

    async fn qemu_device(network: Network, stream: TcpStream) -> Result<Device> {
        Device::new(
            "Jade QEMU Emulator",
            Box::new(JadeQemuDevice::new(
                network,
                TcpTransport::new(TcpClient::new(stream)),
                PinServerClient::new(),
            )),
            true,
        )
        .await
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for JadeDevice {
    async fn enumerate(config: &Config) -> Result<Vec<Device>> {
        let mut devices: Vec<Device> = iter(available_ports()?.into_iter().map(Ok))
            .try_filter_map(|info| async move {
                match info.port_type {
                    SerialPortType::UsbPort(usb) if Self::valid_usb(&usb) => {
                        Self::serial_device(config.network, &info.port_name, usb).await
                    }
                    _ => Ok(None),
                }
            })
            .try_collect()
            .await?;
        if let Ok(stream) = TcpStream::connect(DEFAULT_JADE_QEMU_ADDRESS).await {
            devices.push(Self::qemu_device(config.network, stream).await?);
        }
        Ok(devices)
    }
}

pub struct PinServerClient {
    inner: Client,
}

impl PinServerClient {
    pub fn new() -> Self {
        Self {
            inner: Client::new(),
        }
    }
}

impl Default for PinServerClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl HttpClient for PinServerClient {
    type Error = reqwest::Error;

    async fn request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self
            .inner
            .post(url)
            .header("Content-Type", "application/json")
            .body(request.to_vec())
            .send()
            .await?
            .bytes()
            .await?
            .to_vec())
    }
}

pub struct TcpClient {
    stream: TcpStream,
}

impl TcpClient {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

#[async_trait(?Send)]
impl CborStream for TcpClient {
    async fn write_all(&mut self, command: &[u8]) -> Result<(), std::io::Error> {
        Ok(self.stream.write_all(command).await?)
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        Ok(self.stream.read(buf).await?)
    }
}
