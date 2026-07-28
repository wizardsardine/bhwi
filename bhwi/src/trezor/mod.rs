pub mod api;
pub mod error;
pub mod interpreter;
pub mod proto;

use crate::device::DeviceId;

pub use error::TrezorError;
pub use interpreter::{TrezorCommand, TrezorInterpreter, TrezorResponse};

pub const TREZOR_VID: u16 = 0x1209;
pub const TREZOR_PID: u16 = 0x53c1;
pub const TREZOR_BOOTLOADER_PID: u16 = 0x53c0;
pub const TREZOR_ONE_VID: u16 = 0x534c;
pub const TREZOR_ONE_PID: u16 = 0x0001;

pub const DEFAULT_TREZOR_EMULATOR: &str = "127.0.0.1:21324";

pub const TREZOR_DEVICE_ID: DeviceId = DeviceId::new(TREZOR_VID)
    .with_pid(TREZOR_PID)
    .with_emulator_path(DEFAULT_TREZOR_EMULATOR);
pub const TREZOR_ONE_DEVICE_ID: DeviceId = DeviceId::new(TREZOR_ONE_VID)
    .with_pid(TREZOR_ONE_PID)
    .with_usage_page(0xff00);
