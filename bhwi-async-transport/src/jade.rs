//! Native Jade serial sessions, QEMU connections, and PIN-server HTTP I/O.

use std::sync::Arc;

use crate::NativeResult;
use crate::serial::{is_macos_dialin, require_tty_sysfs};
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

use crate::{
    Device, DeviceCandidate, DeviceEnumerator, DeviceSelector, DeviceType, HostInteractionFactory,
    NativeError, PairingCodePrompt,
};

/// A Jade serial session with native PIN-server HTTP support.
pub type JadeSerialDevice = Jade<SerialTransport, PinServerClient>;
/// A Jade QEMU session over TCP with native PIN-server HTTP support.
pub type JadeQemuDevice = Jade<TcpTransport<TcpClient>, PinServerClient>;

/// The Jade serial baud rate, in bits per second.
pub const DEFAULT_JADE_BAUD_RATE: u32 = 115200;
/// The default Jade QEMU endpoint, including the `tcp:` discovery prefix.
pub const DEFAULT_JADE_QEMU_ADDRESS: &str = "tcp:127.0.0.1:30121";

fn jade_tcp_addr(path: &str) -> &str {
    path.strip_prefix("tcp:").unwrap_or(path)
}

/// A native serial transport for Jade CBOR requests and responses.
pub struct SerialTransport {
    stream: Arc<Mutex<SerialStream>>,
}

impl SerialTransport {
    /// Opens `port_name` at [`DEFAULT_JADE_BAUD_RATE`].
    ///
    /// Clears RTS and DTR to avoid rebooting the device.
    pub fn new(port_name: &str) -> Result<Self, tokio_serial::Error> {
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

/// The native Jade enumerator for USB serial ports and the QEMU endpoint.
///
/// Listing can briefly connect to QEMU. Opened sessions use the selector's
/// network and [`PinServerClient`] for PIN-server requests.
pub struct JadeDevice;

impl JadeDevice {
    fn valid_usb(info: &UsbPortInfo) -> bool {
        JADE_DEVICE_IDS
            .iter()
            .find(|id| id.vid == info.vid && id.pid == Some(info.pid))
            .is_some()
    }

    fn usb_name(info: &UsbPortInfo) -> String {
        format!(
            "{} {}",
            info.product.clone().unwrap_or_else(|| "Jade".into()),
            info.manufacturer
                .clone()
                .unwrap_or_else(|| "Blockstream".into())
        )
    }

    async fn open_serial(candidate: &DeviceCandidate, network: Network) -> NativeResult<Device> {
        let transport = SerialTransport::new(&candidate.path)?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Jade,
            &candidate.path,
            &candidate.model,
            Box::new(JadeSerialDevice::new(
                network,
                transport,
                PinServerClient::new(),
            )),
            false,
        ))
    }

    async fn open_qemu(candidate: &DeviceCandidate, network: Network) -> NativeResult<Device> {
        let stream = TcpStream::connect(jade_tcp_addr(&candidate.path)).await?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Jade,
            &candidate.path,
            &candidate.model,
            Box::new(JadeQemuDevice::new(
                network,
                TcpTransport::new(TcpClient::new(stream)),
                PinServerClient::new(),
            )),
            true,
        ))
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for JadeDevice {
    async fn list(selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>> {
        require_tty_sysfs()?;
        let mut candidates: Vec<DeviceCandidate> =
            iter(available_ports()?.into_iter().map(Ok::<_, NativeError>))
                .try_filter_map(|info| async move {
                    match info.port_type {
                        SerialPortType::UsbPort(usb)
                            if selector.matches(DeviceType::Jade, &info.port_name)
                                && !is_macos_dialin(&info.port_name)
                                && Self::valid_usb(&usb) =>
                        {
                            Ok(Some(DeviceCandidate {
                                device_type: DeviceType::Jade,
                                name: Self::usb_name(&usb),
                                model: "jade".to_owned(),
                                path: info.port_name.clone(),
                                is_emulated: false,
                            }))
                        }
                        _ => Ok(None),
                    }
                })
                .try_collect()
                .await?;
        // Only a connection tells us the emulator is there; it is dropped again.
        if selector.include_emulators
            && (selector.matches(DeviceType::Jade, DEFAULT_JADE_QEMU_ADDRESS)
                || selector.matches(DeviceType::Jade, jade_tcp_addr(DEFAULT_JADE_QEMU_ADDRESS)))
            && TcpStream::connect(jade_tcp_addr(DEFAULT_JADE_QEMU_ADDRESS))
                .await
                .is_ok()
        {
            candidates.push(DeviceCandidate {
                device_type: DeviceType::Jade,
                name: "Jade QEMU Emulator".to_owned(),
                model: "jade_simulator".to_owned(),
                path: DEFAULT_JADE_QEMU_ADDRESS.to_owned(),
                is_emulated: true,
            });
        }
        Ok(candidates)
    }

    async fn open(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        if candidate.is_emulated {
            Self::open_qemu(candidate, selector.network).await
        } else {
            Self::open_serial(candidate, selector.network).await
        }
    }
}

/// A `reqwest` HTTP client for Jade PIN-server requests.
///
/// Requests are POSTed with a JSON content type. Response bodies are returned
/// without rejecting HTTP error status codes.
pub struct PinServerClient {
    inner: Client,
}

impl PinServerClient {
    /// Creates a PIN-server client with the default `reqwest` configuration.
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

/// A TCP stream adapter for Jade CBOR framing.
pub struct TcpClient {
    stream: TcpStream,
}

impl TcpClient {
    /// Creates an adapter from an already-connected TCP stream.
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
