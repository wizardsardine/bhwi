pub mod api;
pub mod interpreter;
pub mod proto;

use crate::device::DeviceId;

pub use crate::trezor::{
    HostPassphrase, HostPin, TrezorDeviceInfo as KeepKeyDeviceInfo, TrezorError as KeepKeyError,
    TrezorMultisigAddress as KeepKeyMultisigAddress,
    TrezorMultisigAddressType as KeepKeyMultisigAddressType, TrezorResponse as KeepKeyResponse,
};
pub use interpreter::{KeepKeyCommand, KeepKeyInterpreter};

pub const KEEPKEY_VID: u16 = 0x2b24;
pub const KEEPKEY_HID_PID: u16 = 0x0001;
pub const KEEPKEY_WEBUSB_PID: u16 = 0x0002;
pub const KEEPKEY_HID_USAGE_PAGE: u16 = 0xff00;
pub const DEFAULT_KEEPKEY_EMULATOR: &str = "udp:127.0.0.1:11044";
pub const KEEPKEY_LOCKED: &str =
    "Keepkey is locked. Unlock by using 'promptpin' and then 'sendpin'.";

pub const KEEPKEY_HID_DEVICE_ID: DeviceId = DeviceId::new(KEEPKEY_VID)
    .with_pid(KEEPKEY_HID_PID)
    .with_usage_page(KEEPKEY_HID_USAGE_PAGE)
    .with_emulator_path(DEFAULT_KEEPKEY_EMULATOR);
pub const KEEPKEY_WEBUSB_DEVICE_ID: DeviceId =
    DeviceId::new(KEEPKEY_VID).with_pid(KEEPKEY_WEBUSB_PID);

/// External data needed by KeepKey management commands while keeping the interpreter sans-I/O.
#[derive(Clone, Debug)]
pub enum ManagementContext {
    Setup { host_entropy: [u8; 32] },
    Restore { u2f_counter: u32 },
    Pin(HostPin),
}
