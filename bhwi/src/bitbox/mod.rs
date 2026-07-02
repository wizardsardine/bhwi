pub mod antiklepto;
pub mod api;
pub mod error;
pub mod interpreter;
pub mod keypath;
pub mod noise;
pub mod policy;
pub mod proto;
pub mod sign;
pub mod u2f;

pub use interpreter::{BitBoxCommand, BitBoxInterpreter, BitBoxResponse};

/// USB VID/PID of the BitBox02.
pub const BITBOX02_VID: u16 = 0x03eb;
pub const BITBOX02_PID: u16 = 0x2403;

/// HID usage page of the BitBox02 firmware (HWW) interface. The device also exposes a
/// FIDO/U2F interface (usage page 0xf1d0) that does not understand the firmware command,
/// so enumeration must select this usage page.
pub const BITBOX02_HID_USAGE_PAGE: u16 = 0xffff;

/// HID product strings for genuine BitBox02 firmware (used to exclude the bootloader).
pub const BITBOX02_PRODUCT_STRINGS: &[&str] = &[
    "BitBox02",
    "BitBox02BTC",
    "BitBox02 Nova Multi",
    "BitBox02 Nova BTC-only",
];

pub const OP_UNLOCK: u8 = b'u';
pub const OP_I_CAN_HAS_HANDSHAEK: u8 = b'h';
pub const OP_HER_COMEZ_TEH_HANDSHAEK: u8 = b'H';
pub const OP_I_CAN_HAS_PAIRIN_VERIFICASHUN: u8 = b'v';
pub const OP_NOISE_MSG: u8 = b'n';
pub const RESPONSE_SUCCESS: u8 = 0x00;
