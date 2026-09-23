//! Native serial and TCP selection for Specter-DIY.

use std::{
    io,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bhwi_async::{
    Specter,
    transport::specter::{
        DEFAULT_CONFIRMATION_TIMEOUT, SpecterStream, SpecterStreamError, SpecterTransport,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{Instant as TokioInstant, timeout, timeout_at},
};
use tokio_serial::{
    SerialPortBuilderExt, SerialPortType, SerialStream, UsbPortInfo, available_ports,
};

use crate::{Device, DeviceEnumerator, DeviceType, config::DeviceSelector};

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
    fn open(port_name: &str) -> Result<Self> {
        Ok(Self {
            stream: tokio_serial::new(port_name, SPECTER_BAUD_RATE)
                .open_native_async()
                .with_context(|| format!("opening Specter serial port {port_name}"))?,
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

    async fn serial_device(
        selector: &DeviceSelector,
        port_name: &str,
        info: UsbPortInfo,
    ) -> Result<Device> {
        let name = info.product.unwrap_or_else(|| "Specter-DIY".into());
        let mut device = Device::new(
            &name,
            DeviceType::Specter,
            port_name,
            "specter_diy",
            Box::new(SpecterSerialDevice::new(
                selector.network,
                SpecterTransport::new(SerialSpecterStream::open(port_name)?),
            )),
            false,
        )
        .await?;
        Self::probe(&mut device).await?;
        Ok(device)
    }

    async fn tcp_device(
        selector: &DeviceSelector,
        path: &str,
        stream: TcpStream,
    ) -> Result<Device> {
        let mut device = Device::new(
            "Specter-DIY Simulator",
            DeviceType::Specter,
            path,
            "specter_diy_simulator",
            Box::new(SpecterTcpDevice::new(
                selector.network,
                SpecterTransport::new(TcpSpecterStream::new(stream)),
            )),
            true,
        )
        .await?;
        Self::probe(&mut device).await?;
        Ok(device)
    }

    /// A matching USB VID is shared by MicroPython devices.  Require the
    /// protocol fingerprint response before representing one as Specter-DIY.
    async fn probe(device: &mut Device) -> Result<()> {
        device
            .fingerprint()
            .await
            .context("probing Specter-DIY fingerprint")?;
        Ok(())
    }
}

fn tcp_address(path: &str) -> Option<&str> {
    path.strip_prefix("tcp:")
        .or_else(|| path.parse::<SocketAddr>().ok().map(|_| path))
}

fn is_macos_dialin(port_name: &str) -> bool {
    port_name.starts_with("/dev/tty.")
}

fn require_linux_tty_sysfs(is_linux: bool, sysfs_exists: bool) -> Result<()> {
    if is_linux && !sysfs_exists {
        anyhow::bail!("serial port enumeration unavailable: /sys/class/tty is missing");
    }
    Ok(())
}

async fn connect_tcp(address: &str) -> Result<TcpStream> {
    timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| anyhow::anyhow!("connecting to Specter-DIY at {address} timed out"))?
        .with_context(|| format!("connecting to Specter-DIY at {address}"))
}

fn selected_tcp_path(selector: &DeviceSelector) -> Option<&str> {
    selector.device_path.as_deref().and_then(tcp_address)
}

fn requires_serial_enumeration(selector: &DeviceSelector) -> bool {
    selected_tcp_path(selector).is_none()
}

#[async_trait(?Send)]
impl DeviceEnumerator for SpecterDevice {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>> {
        let mut devices = Vec::new();

        // An explicit TCP selector only ever opens the named simulator.
        if let Some(address) = selected_tcp_path(selector) {
            let stream = connect_tcp(address).await?;
            devices.push(Self::tcp_device(selector, &format!("tcp:{address}"), stream).await?);
            return Ok(devices);
        }

        if requires_serial_enumeration(selector) {
            require_linux_tty_sysfs(
                cfg!(target_os = "linux"),
                Path::new("/sys/class/tty").exists(),
            )?;
        }

        // Only inspect USB serial entries that already identify as the
        // MicroPython VID used by Specter-DIY.  Do not open unrelated ports.
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
            match Self::serial_device(selector, &port.port_name, usb).await {
                Ok(device) => devices.push(device),
                Err(error) if selector.device_path.as_deref() == Some(port.port_name.as_str()) => {
                    return Err(error);
                }
                Err(_) => {}
            }
        }

        if selector.include_emulators
            && selector.matches(DeviceType::Specter, DEFAULT_SPECTER_SIMULATOR_ADDRESS)
            && let Ok(stream) =
                connect_tcp(specter_tcp_addr(DEFAULT_SPECTER_SIMULATOR_ADDRESS)).await
            && let Ok(device) =
                Self::tcp_device(selector, DEFAULT_SPECTER_SIMULATOR_ADDRESS, stream).await
        {
            devices.push(device);
        }
        Ok(devices)
    }
}

fn specter_tcp_addr(path: &str) -> &str {
    path.strip_prefix("tcp:").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn matches_only_the_specter_micropython_vid() {
        assert!(SpecterDevice::valid_usb(&UsbPortInfo {
            vid: SPECTER_USB_VID,
            pid: 0x9800,
            serial_number: None,
            manufacturer: None,
            product: None,
        }));
        assert!(!SpecterDevice::valid_usb(&UsbPortInfo {
            vid: 0x1209,
            pid: 0x9800,
            serial_number: None,
            manufacturer: None,
            product: None,
        }));
    }

    #[test]
    fn accepts_only_explicit_tcp_selectors() {
        assert_eq!(tcp_address("tcp:127.0.0.1:8789"), Some("127.0.0.1:8789"));
        assert_eq!(tcp_address("127.0.0.1:8789"), Some("127.0.0.1:8789"));
        assert_eq!(tcp_address("/dev/ttyACM0"), None);
        assert_eq!(
            specter_tcp_addr(DEFAULT_SPECTER_SIMULATOR_ADDRESS),
            "127.0.0.1:8789"
        );
    }

    #[test]
    fn absent_linux_tty_sysfs_errors_before_port_enumeration() {
        let result: anyhow::Result<()> =
            require_linux_tty_sysfs(true, false).map(|_| panic!("enumerator invoked"));
        assert_eq!(
            result.unwrap_err().to_string(),
            "serial port enumeration unavailable: /sys/class/tty is missing"
        );
    }

    #[test]
    fn tcp_selectors_bypass_serial_port_enumeration() {
        let tcp = DeviceSelector {
            device_type: Some(DeviceType::Specter),
            device_path: Some("tcp:127.0.0.1:8789".into()),
            ..DeviceSelector::default()
        };
        let serial = DeviceSelector {
            device_type: Some(DeviceType::Specter),
            device_path: Some("/dev/ttyACM0".into()),
            ..DeviceSelector::default()
        };
        assert!(!requires_serial_enumeration(&tcp));
        assert!(requires_serial_enumeration(&serial));
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
