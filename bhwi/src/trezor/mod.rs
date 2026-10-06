//! Trezor commands, protobuf framing, and host-interaction state machines.
//!
//! The common adapter rejects descriptor display, wallet registration, and backup.
//! Setup and restore require caller-supplied management context; the common
//! setup adapter does not use the backup-passphrase option.

pub mod api;
pub mod error;
pub mod interpreter;
/// Generated Trezor protobuf messages.
pub mod proto;

use crate::device::DeviceId;

pub use error::TrezorError;

/// Scrambled keypad positions, never the PIN digits themselves.
///
/// Debug output is redacted and stored positions are zeroized on drop.
#[derive(Clone, Default, zeroize::Zeroize, zeroize_derive::ZeroizeOnDrop)]
pub struct HostPin(String);

impl HostPin {
    /// Creates positions from nonempty ASCII digits.
    ///
    /// Validation does not restrict digits to the keypad's 1–9 range.
    pub fn new(positions: String) -> Result<Self, TrezorError> {
        if positions.is_empty() || !positions.chars().all(|c| c.is_ascii_digit()) {
            return Err(TrezorError::NonNumericPin);
        }
        Ok(Self(positions))
    }

    /// Returns the scrambled keypad-position string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for HostPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostPin(<redacted>)")
    }
}

pub use interpreter::{
    TrezorCommand, TrezorDeviceInfo, TrezorInterpreter, TrezorMultisigAddress,
    TrezorMultisigAddressType, TrezorResponse,
};

/// External data needed by Trezor management commands while keeping the interpreter sans-I/O.
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

/// USB vendor identifier of current Trezor devices.
pub const TREZOR_VID: u16 = 0x1209;
/// USB product identifier of current Trezor firmware.
pub const TREZOR_PID: u16 = 0x53c1;
/// USB product identifier of the Trezor bootloader.
pub const TREZOR_BOOTLOADER_PID: u16 = 0x53c0;
/// USB vendor identifier of Trezor One.
pub const TREZOR_ONE_VID: u16 = 0x534c;
/// USB product identifier of Trezor One.
pub const TREZOR_ONE_PID: u16 = 0x0001;

/// Default UDP endpoint of the Trezor emulator.
pub const DEFAULT_TREZOR_EMULATOR: &str = "udp:127.0.0.1:21324";

/// Current Trezor firmware identifiers and default emulator endpoint.
pub const TREZOR_DEVICE_ID: DeviceId = DeviceId::new(TREZOR_VID)
    .with_pid(TREZOR_PID)
    .with_emulator_path(DEFAULT_TREZOR_EMULATOR);
/// Trezor One identifiers and firmware HID usage page.
pub const TREZOR_ONE_DEVICE_ID: DeviceId = DeviceId::new(TREZOR_ONE_VID)
    .with_pid(TREZOR_ONE_PID)
    .with_usage_page(0xff00);
