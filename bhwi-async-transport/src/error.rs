use crate::DeviceType;

pub type NativeResult<T> = Result<T, NativeError>;

#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    #[error("{0} support is not compiled into this build")]
    NotCompiled(DeviceType),

    /// A `DeviceId` field the enumerator needs was left unset.
    #[error("{0}")]
    MissingDeviceId(&'static str),

    #[cfg(any(
        feature = "bitbox",
        feature = "coldcard",
        feature = "ledger",
        feature = "trezor"
    ))]
    #[error("hid enumeration failed: {0}")]
    Hid(#[from] async_hid::HidError),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "trezor")]
    #[error("usb enumeration failed: {0}")]
    Usb(#[from] nusb::Error),

    #[cfg(feature = "jade")]
    #[error("serial port enumeration failed: {0}")]
    Serial(#[from] tokio_serial::Error),

    #[cfg(feature = "jade")]
    #[error("serial port enumeration unavailable: /sys/class/tty is missing")]
    SerialSysfsMissing,
}
