pub mod api;
pub mod error;
pub mod interpreter;
pub mod proto;

use crate::device::DeviceId;

pub use error::TrezorError;

#[derive(Clone, Default, zeroize::Zeroize, zeroize_derive::ZeroizeOnDrop)]
pub struct HostPassphrase(String);

pub const MAX_PASSPHRASE_LENGTH: usize = 50;

impl HostPassphrase {
    pub fn new(passphrase: String) -> Self {
        use unicode_normalization::UnicodeNormalization;
        Self(passphrase.nfkd().collect())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_too_long(&self) -> bool {
        self.0.chars().count() > MAX_PASSPHRASE_LENGTH
    }
}

impl core::fmt::Debug for HostPassphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostPassphrase(<redacted>)")
    }
}
pub use interpreter::{TrezorCommand, TrezorInterpreter, TrezorResponse};

pub const TREZOR_VID: u16 = 0x1209;
pub const TREZOR_PID: u16 = 0x53c1;
pub const TREZOR_BOOTLOADER_PID: u16 = 0x53c0;
pub const TREZOR_ONE_VID: u16 = 0x534c;
pub const TREZOR_ONE_PID: u16 = 0x0001;

pub const DEFAULT_TREZOR_EMULATOR: &str = "udp:127.0.0.1:21324";

pub const TREZOR_DEVICE_ID: DeviceId = DeviceId::new(TREZOR_VID)
    .with_pid(TREZOR_PID)
    .with_emulator_path(DEFAULT_TREZOR_EMULATOR);
pub const TREZOR_ONE_DEVICE_ID: DeviceId = DeviceId::new(TREZOR_ONE_VID)
    .with_pid(TREZOR_ONE_PID)
    .with_usage_page(0xff00);
