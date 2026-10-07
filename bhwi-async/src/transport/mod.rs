/// BitBox02 firmware framing.
#[cfg(feature = "bitbox")]
pub mod bitbox;
/// Coldcard packet framing.
#[cfg(feature = "coldcard")]
pub mod coldcard;
/// Jade CBOR stream framing.
#[cfg(feature = "jade")]
pub mod jade;
/// Ledger HID and Speculos framing.
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "specter")]
pub mod specter;
/// Trezor and KeepKey packet framing.
#[cfg(any(feature = "trezor", feature = "keepkey"))]
pub mod trezor;

use async_trait::async_trait;

pub use bhwi::device::DeviceId;

use crate::ErrorKind;

/// Asynchronous packet I/O supplied to device-specific framing adapters.
///
/// Futures need not be `Send`; implementations choose their I/O runtime and
/// timeout policy. Return byte counts so adapters can detect short transfers.
#[async_trait(?Send)]
pub trait Channel {
    /// Sends bytes and returns the number written.
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error>;
    /// Receives bytes into `data` and returns the number read.
    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error>;
}

/// Returns [`ErrorKind::Disconnected`] for I/O errors that mean the device went away,
/// and [`ErrorKind::Transport`] otherwise.
pub fn io_error_kind(error: &std::io::Error) -> ErrorKind {
    use std::io::ErrorKind as Io;
    match error.kind() {
        Io::BrokenPipe
        | Io::UnexpectedEof
        | Io::NotConnected
        | Io::ConnectionReset
        | Io::ConnectionAborted => ErrorKind::Disconnected,
        _ => ErrorKind::Transport,
    }
}
