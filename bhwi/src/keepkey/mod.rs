//! KeepKey commands and its Trezor-compatible wire protocol.
//!
//! The common adapter rejects descriptor display, wallet registration, and backup.
//! Setup and restore require caller-supplied management context; the common
//! setup adapter does not use the backup-passphrase option.

pub mod api;
pub mod interpreter;
pub mod proto;

use crate::device::DeviceId;

/// KeepKey reuses the Trezor V1 wire format, so these are the same types.
pub use crate::trezor::{
    HostPin, TrezorDeviceInfo as KeepKeyDeviceInfo,
    TrezorMultisigAddress as KeepKeyMultisigAddress,
    TrezorMultisigAddressType as KeepKeyMultisigAddressType, TrezorResponse as KeepKeyResponse,
};
pub use interpreter::{KeepKeyCommand, KeepKeyInterpreter};

/// A Trezor-engine error from a KeepKey, whose failure codes use KeepKey's numbering.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct KeepKeyError(#[from] pub crate::trezor::TrezorError);

/// KeepKey USB vendor identifier.
pub const KEEPKEY_VID: u16 = 0x2b24;
/// KeepKey HID product identifier.
pub const KEEPKEY_HID_PID: u16 = 0x0001;
/// KeepKey WebUSB product identifier.
pub const KEEPKEY_WEBUSB_PID: u16 = 0x0002;
/// KeepKey firmware HID usage page.
pub const KEEPKEY_HID_USAGE_PAGE: u16 = 0xff00;
/// Default UDP endpoint of the KeepKey emulator.
pub const DEFAULT_KEEPKEY_EMULATOR: &str = "udp:127.0.0.1:11044";
/// Error message for a locked KeepKey requiring host PIN entry.
pub const KEEPKEY_LOCKED: &str =
    "Keepkey is locked. Unlock by using 'promptpin' and then 'sendpin'.";

/// KeepKey HID identifiers and default emulator endpoint.
pub const KEEPKEY_HID_DEVICE_ID: DeviceId = DeviceId::new(KEEPKEY_VID)
    .with_pid(KEEPKEY_HID_PID)
    .with_usage_page(KEEPKEY_HID_USAGE_PAGE)
    .with_emulator_path(DEFAULT_KEEPKEY_EMULATOR);
/// KeepKey WebUSB identifiers.
pub const KEEPKEY_WEBUSB_DEVICE_ID: DeviceId =
    DeviceId::new(KEEPKEY_VID).with_pid(KEEPKEY_WEBUSB_PID);

/// External data needed by KeepKey management commands while keeping the interpreter sans-I/O.
#[derive(Clone, Debug)]
pub enum ManagementContext {
    /// Entropy for initializing a new wallet.
    Setup {
        /// Caller-generated entropy mixed with device entropy.
        host_entropy: [u8; 32],
    },
    /// Initial U2F counter for restoring a wallet.
    Restore {
        /// Caller-selected U2F counter value.
        u2f_counter: u32,
    },
    /// Scrambled keypad positions for a pending PIN request.
    Pin(
        /// Scrambled keypad positions, not literal PIN digits.
        HostPin,
    ),
}
