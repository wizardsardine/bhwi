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
    Device, DeviceCandidate, DeviceEnumerator, DeviceSelector, DeviceType, HostInteractionFactory,
    NativeError, NativeResult, PairingCodePrompt,
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

    fn simulator(path: String) -> DeviceCandidate {
        DeviceCandidate {
            device_type: DeviceType::Specter,
            name: "Specter-DIY Simulator".to_owned(),
            model: "specter_diy_simulator".to_owned(),
            path,
            is_emulated: true,
        }
    }

    fn open_serial(candidate: &DeviceCandidate, network: Network) -> NativeResult<Device> {
        let stream = SerialSpecterStream::open(&candidate.path)?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Specter,
            &candidate.path,
            &candidate.model,
            Box::new(SpecterSerialDevice::new(
                network,
                SpecterTransport::new(stream),
            )),
            false,
        ))
    }

    async fn open_tcp(candidate: &DeviceCandidate, network: Network) -> NativeResult<Device> {
        let address = tcp_address(&candidate.path).unwrap_or(&candidate.path);
        let stream = connect_tcp(address).await?;
        Ok(Device::new(
            &candidate.name,
            DeviceType::Specter,
            &candidate.path,
            &candidate.model,
            Box::new(SpecterTcpDevice::new(
                network,
                SpecterTransport::new(TcpSpecterStream::new(stream)),
            )),
            true,
        ))
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
    async fn list(selector: &DeviceSelector) -> NativeResult<Vec<DeviceCandidate>> {
        if let Some(address) = selected_tcp_address(selector) {
            return Ok(vec![Self::simulator(format!("tcp:{address}"))]);
        }

        require_tty_sysfs()?;
        let mut candidates: Vec<DeviceCandidate> = available_ports()?
            .into_iter()
            .filter_map(|port| match port.port_type {
                SerialPortType::UsbPort(usb)
                    if Self::valid_usb(&usb)
                        && !is_macos_dialin(&port.port_name)
                        && selector.matches(DeviceType::Specter, &port.port_name) =>
                {
                    Some(DeviceCandidate {
                        device_type: DeviceType::Specter,
                        name: usb.product.unwrap_or_else(|| "Specter-DIY".into()),
                        model: "specter_diy".to_owned(),
                        path: port.port_name,
                        is_emulated: false,
                    })
                }
                _ => None,
            })
            .collect();

        // Only a connection tells us the simulator is there; it is dropped again.
        if selector.include_emulators
            && selector.matches(DeviceType::Specter, DEFAULT_SPECTER_SIMULATOR_ADDRESS)
            && let Some(address) = tcp_address(DEFAULT_SPECTER_SIMULATOR_ADDRESS)
            && connect_tcp(address).await.is_ok()
        {
            candidates.push(Self::simulator(
                DEFAULT_SPECTER_SIMULATOR_ADDRESS.to_owned(),
            ));
        }
        Ok(candidates)
    }

    async fn open(
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        _pairing_code: Option<&PairingCodePrompt>,
        _host_interaction: Option<&HostInteractionFactory>,
    ) -> NativeResult<Device> {
        let mut device = if candidate.is_emulated {
            Self::open_tcp(candidate, selector.network).await?
        } else {
            Self::open_serial(candidate, selector.network)?
        };
        // Every MicroPython board shares the VID; only a fingerprint reply proves a Specter-DIY.
        device
            .fingerprint()
            .await
            .map_err(|source| NativeError::Probe {
                device_type: DeviceType::Specter,
                source,
            })?;
        Ok(device)
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

    #[tokio::test]
    async fn tcp_selectors_bypass_serial_port_enumeration() {
        let selector = DeviceSelector {
            device_type: Some(DeviceType::Specter),
            device_path: Some("tcp:127.0.0.1:1".into()),
            ..DeviceSelector::default()
        };
        let candidates = SpecterDevice::list(&selector).await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, "tcp:127.0.0.1:1");
        assert!(candidates[0].is_emulated);
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
