use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bhwi_async::{
    Specter,
    transport::specter::{
        DEFAULT_CONFIRMATION_TIMEOUT, SpecterStream, SpecterStreamError, SpecterTransport,
    },
};
use bitcoin::Network;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{Instant as TokioInstant, timeout, timeout_at},
};
use tokio_serial::{
    SerialPortBuilderExt, SerialPortType, SerialStream, UsbPortInfo, available_ports,
};

use crate::serial::{is_macos_dialin, require_tty_sysfs};
use crate::{
    Device, DeviceEnumerator, DeviceScan, DeviceSelector, DeviceType, HostInteractionFactory,
    NativeResult, PairingCodePrompt, ScanEntry,
};

/// Specter-DIY's MicroPython USB vendor identifier.
pub const SPECTER_USB_VID: u16 = 0xf055;
pub const SPECTER_BAUD_RATE: u32 = 115_200;
pub const DEFAULT_SPECTER_SIMULATOR_ADDRESS: &str = "tcp:127.0.0.1:8789";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub type SpecterSerialDevice = Specter<SpecterTransport<SerialSpecterStream>>;
pub type SpecterTcpDevice = Specter<SpecterTransport<TcpSpecterStream>>;

/// A serial stream whose reads honor the deadline supplied by the generic
/// Specter transport.
pub struct SerialSpecterStream {
    stream: SerialStream,
}

impl SerialSpecterStream {
    fn open(port_name: &str) -> Result<Self, tokio_serial::Error> {
        Ok(Self {
            stream: tokio_serial::new(port_name, SPECTER_BAUD_RATE).open_native_async()?,
        })
    }
}

/// A simulator TCP stream whose reads honor the deadline supplied by the
/// generic Specter transport.
pub struct TcpSpecterStream {
    stream: TcpStream,
}

impl TcpSpecterStream {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

fn tokio_deadline(value: Instant) -> TokioInstant {
    TokioInstant::from_std(value)
}

fn stream_error(error: io::Error) -> SpecterStreamError<io::Error> {
    match error.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::UnexpectedEof => SpecterStreamError::Disconnected,
        _ => SpecterStreamError::Io(error),
    }
}

async fn write_until<W: AsyncWrite + Unpin>(
    stream: &mut W,
    request: &[u8],
    deadline: Instant,
) -> Result<(), SpecterStreamError<io::Error>> {
    match timeout_at(tokio_deadline(deadline), stream.write_all(request)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(stream_error(error)),
        Err(_) => Err(SpecterStreamError::Timeout),
    }
}

macro_rules! impl_specter_stream {
    ($stream:ty) => {
        #[async_trait(?Send)]
        impl SpecterStream for $stream {
            type Error = io::Error;

            async fn write_all(
                &mut self,
                request: &[u8],
            ) -> Result<(), SpecterStreamError<Self::Error>> {
                write_until(
                    &mut self.stream,
                    request,
                    Instant::now() + DEFAULT_CONFIRMATION_TIMEOUT,
                )
                .await
            }

            async fn read_until(
                &mut self,
                buffer: &mut [u8],
                deadline: Instant,
            ) -> Result<usize, SpecterStreamError<Self::Error>> {
                match timeout_at(tokio_deadline(deadline), self.stream.read(buffer)).await {
                    Ok(Ok(read)) => Ok(read),
                    Ok(Err(error)) => Err(stream_error(error)),
                    Err(_) => Err(SpecterStreamError::Timeout),
                }
            }
        }
    };
}

impl_specter_stream!(SerialSpecterStream);
impl_specter_stream!(TcpSpecterStream);

pub struct SpecterDevice;

impl SpecterDevice {
    fn valid_usb(info: &UsbPortInfo) -> bool {
        info.vid == SPECTER_USB_VID
    }

    async fn serial_device(network: Network, port_name: &str, info: UsbPortInfo) -> ScanEntry {
        let stream = match SerialSpecterStream::open(port_name) {
            Ok(stream) => stream,
            Err(err) => {
                return ScanEntry::skipped(DeviceType::Specter, "specter_diy", port_name, &err);
            }
        };
        let device = Device::new(
            &info.product.unwrap_or_else(|| "Specter-DIY".into()),
            DeviceType::Specter,
            port_name,
            "specter_diy",
            Box::new(SpecterSerialDevice::new(
                network,
                SpecterTransport::new(stream),
            )),
            false,
        );
        Self::probe(device).await
    }

    fn tcp_device(network: Network, path: &str, stream: TcpStream) -> Device {
        Device::new(
            "Specter-DIY Simulator",
            DeviceType::Specter,
            path,
            "specter_diy_simulator",
            Box::new(SpecterTcpDevice::new(
                network,
                SpecterTransport::new(TcpSpecterStream::new(stream)),
            )),
            true,
        )
    }

    /// The MicroPython VID is shared by every MicroPython board, so only a
    /// fingerprint reply identifies a Specter-DIY.
    async fn probe(mut device: Device) -> ScanEntry {
        match device.fingerprint().await {
            Ok(_) => ScanEntry::Found(device),
            Err(err) => {
                ScanEntry::skipped(DeviceType::Specter, device.model(), device.path(), &err)
            }
        }
    }
}

fn tcp_address(path: &str) -> Option<&str> {
    path.strip_prefix("tcp:")
        .or_else(|| path.parse::<SocketAddr>().ok().map(|_| path))
}

fn selected_tcp_address(selector: &DeviceSelector) -> Option<&str> {
    selector.device_path.as_deref().and_then(tcp_address)
}

async fn connect_tcp(address: &str) -> io::Result<TcpStream> {
    timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connecting to Specter-DIY at {address} timed out"),
            )
        })?
}

#[async_trait(?Send)]
impl DeviceEnumerator for SpecterDevice {
    async fn enumerate(
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<DeviceScan> {
        let mut scan = DeviceScan::default();

        // An explicit TCP selector only ever opens the named simulator.
        if let Some(address) = selected_tcp_address(selector) {
            let stream = connect_tcp(address).await?;
            let path = format!("tcp:{address}");
            let device = Self::tcp_device(selector.network, &path, stream);
            scan.extend([Self::probe(device).await]);
            return Ok(scan);
        }

        require_tty_sysfs()?;
        for port in available_ports()? {
            let SerialPortType::UsbPort(usb) = port.port_type else {
                continue;
            };
            if !Self::valid_usb(&usb)
                || is_macos_dialin(&port.port_name)
                || !selector.matches(DeviceType::Specter, &port.port_name)
            {
                continue;
            }
            let selected = selector.device_path.as_deref() == Some(port.port_name.as_str());
            match Self::serial_device(selector.network, &port.port_name, usb).await {
                entry @ ScanEntry::Found(_) => scan.extend([entry]),
                // Another MicroPython board on the same VID is not a Specter-DIY.
                entry @ ScanEntry::Skipped(_) if selected => scan.extend([entry]),
                ScanEntry::Skipped(_) => {}
            }
        }

        if selector.include_emulators
            && selector.matches(DeviceType::Specter, DEFAULT_SPECTER_SIMULATOR_ADDRESS)
            && let Some(address) = tcp_address(DEFAULT_SPECTER_SIMULATOR_ADDRESS)
            && let Ok(stream) = connect_tcp(address).await
        {
            let device =
                Self::tcp_device(selector.network, DEFAULT_SPECTER_SIMULATOR_ADDRESS, stream);
            if let entry @ ScanEntry::Found(_) = Self::probe(device).await {
                scan.extend([entry]);
            }
        }
        Ok(scan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_the_specter_micropython_vid() {
        let port = |vid| UsbPortInfo {
            vid,
            pid: 0x9800,
            serial_number: None,
            manufacturer: None,
            product: None,
        };
        assert!(SpecterDevice::valid_usb(&port(SPECTER_USB_VID)));
        assert!(!SpecterDevice::valid_usb(&port(0x1209)));
    }

    #[test]
    fn accepts_only_explicit_tcp_selectors() {
        assert_eq!(tcp_address("tcp:127.0.0.1:8789"), Some("127.0.0.1:8789"));
        assert_eq!(tcp_address("127.0.0.1:8789"), Some("127.0.0.1:8789"));
        assert_eq!(tcp_address("/dev/ttyACM0"), None);
        assert_eq!(
            tcp_address(DEFAULT_SPECTER_SIMULATOR_ADDRESS),
            Some("127.0.0.1:8789")
        );
    }

    #[test]
    fn classifies_disconnect_io_errors() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NotConnected,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(matches!(
                stream_error(io::Error::from(kind)),
                SpecterStreamError::Disconnected
            ));
        }
    }

    #[tokio::test]
    async fn write_deadline_returns_a_typed_timeout() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let result = write_until(
            &mut writer,
            b"two bytes",
            Instant::now() + Duration::from_millis(1),
        )
        .await;
        assert!(matches!(result, Err(SpecterStreamError::Timeout)));
    }

    #[tokio::test]
    async fn tcp_stream_times_out_at_the_supplied_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(address).await.unwrap();
        let mut stream = TcpSpecterStream::new(client);
        let _server = accept.await.unwrap();
        let mut buffer = [0u8; 1];
        let result = stream
            .read_until(&mut buffer, Instant::now() + Duration::from_millis(1))
            .await;
        assert!(matches!(result, Err(SpecterStreamError::Timeout)));
    }
}
