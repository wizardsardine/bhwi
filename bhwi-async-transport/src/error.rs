//! Native discovery and transport errors.

use bhwi_async::{ErrorKind, ErrorKindOf, transport::io_error_kind};

use crate::DeviceType;

/// A result from native device discovery or opening.
pub type NativeResult<T> = Result<T, NativeError>;

/// A failure while discovering, opening, or probing a native device.
#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    /// Support for the requested device type is disabled in this build.
    #[error("{0} support is not compiled into this build")]
    NotCompiled(
        /// The requested device type.
        DeviceType,
    ),

    /// A device-identifier constant required by discovery is unset.
    #[error("{0}")]
    MissingDeviceId(
        /// A description of the missing identifier.
        &'static str,
    ),

    /// Listed on the bus, but no longer there when it was opened.
    #[error("{0} is no longer connected")]
    Gone(
        /// The discovery path that could not be found.
        String,
    ),

    /// Native HID enumeration or opening failed.
    #[cfg(any(
        feature = "bitbox",
        feature = "coldcard",
        feature = "keepkey",
        feature = "ledger",
        feature = "trezor"
    ))]
    #[error("hid enumeration failed: {0}")]
    Hid(
        /// The underlying HID error.
        #[from]
        async_hid::HidError,
    ),

    /// A native channel or filesystem operation failed.
    #[error("{0}")]
    Io(
        /// The underlying I/O error.
        #[from]
        std::io::Error,
    ),

    /// Native USB enumeration failed.
    #[cfg(any(feature = "keepkey", feature = "trezor"))]
    #[error("usb enumeration failed: {0}")]
    Usb(
        /// The underlying `nusb` error.
        #[from]
        nusb::Error,
    ),

    /// Serial-port enumeration or opening failed.
    #[cfg(any(feature = "jade", feature = "specter"))]
    #[error("serial port enumeration failed: {0}")]
    Serial(
        /// The underlying serial-port error.
        #[from]
        tokio_serial::Error,
    ),

    /// Linux serial enumeration cannot access `/sys/class/tty`.
    #[cfg(any(feature = "jade", feature = "specter"))]
    #[error("serial port enumeration unavailable: /sys/class/tty is missing")]
    SerialSysfsMissing,

    /// The port opened, but the device did not answer as the expected type.
    #[cfg(feature = "specter")]
    #[error("probing {device_type}: {source}")]
    Probe {
        /// The device type expected on the opened channel.
        device_type: DeviceType,
        /// The failed protocol probe.
        source: bhwi_async::HWIDeviceError,
    },
}

impl NativeError {
    /// Returns the failure kind of a discovery or opening error.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::NotCompiled(_) => ErrorKind::Unsupported,
            Self::MissingDeviceId(_) => ErrorKind::InvalidInput,
            Self::Gone(_) => ErrorKind::Disconnected,
            Self::Io(error) => io_error_kind(error),
            #[cfg(any(
                feature = "bitbox",
                feature = "coldcard",
                feature = "keepkey",
                feature = "ledger",
                feature = "trezor"
            ))]
            Self::Hid(async_hid::HidError::Disconnected | async_hid::HidError::NotConnected) => {
                ErrorKind::Disconnected
            }
            #[cfg(any(
                feature = "bitbox",
                feature = "coldcard",
                feature = "keepkey",
                feature = "ledger",
                feature = "trezor"
            ))]
            Self::Hid(_) => ErrorKind::Transport,
            #[cfg(any(feature = "keepkey", feature = "trezor"))]
            Self::Usb(_) => ErrorKind::Transport,
            #[cfg(any(feature = "jade", feature = "specter"))]
            Self::Serial(_) | Self::SerialSysfsMissing => ErrorKind::Transport,
            #[cfg(feature = "specter")]
            Self::Probe { source, .. } => source.kind().unwrap_or(ErrorKind::Other),
        }
    }
}

impl ErrorKindOf for NativeError {
    fn error_kind(&self) -> ErrorKind {
        self.kind()
    }
}
