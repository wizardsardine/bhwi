pub mod api;
pub mod error;
pub mod interpreter;
pub mod proto;

pub use error::TrezorError;
pub use interpreter::{TrezorCommand, TrezorInterpreter, TrezorResponse};

pub const TREZOR_VID: u16 = 0x1209;
pub const TREZOR_PID: u16 = 0x53c1;
pub const TREZOR_BOOTLOADER_PID: u16 = 0x53c0;
pub const TREZOR_ONE_VID: u16 = 0x534c;
pub const TREZOR_ONE_PID: u16 = 0x0001;
