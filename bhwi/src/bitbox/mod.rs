//! BitBox02 commands, encrypted sessions, and Bitcoin protocol helpers.
//!
//! Common descriptor display requires BitBox policy context; single-key PSBT
//! signing may infer its configuration without that context. Setup requires
//! caller-supplied management inputs and rejects a nonempty backup passphrase.

pub mod antiklepto;
pub mod api;
pub mod error;
pub mod interpreter;
pub mod noise;
pub mod policy;
/// Generated BitBox02 protobuf messages.
pub mod proto;
pub mod sign;
pub mod u2f;

pub use interpreter::{
    BitBoxCommand, BitBoxDeviceInfo, BitBoxInterpreter, BitBoxResponse, BitBoxTransmit,
};

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Host entropy used when initializing a new BitBox02 wallet.
///
/// The custom `Debug` implementation prevents seed material from being exposed by callers
/// logging a command or device context.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SetupEntropy([u8; 32]);

impl SetupEntropy {
    /// Creates entropy from 32 caller-supplied bytes.
    pub fn new(entropy: [u8; 32]) -> Self {
        Self(entropy)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SetupEntropy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SetupEntropy([REDACTED])")
    }
}

/// Device-specific setup behavior selected by the transport-facing caller.
#[derive(Clone, Debug)]
pub enum SetupMode {
    /// Initialize a physical device with fresh host entropy, then create its backup.
    NewWallet {
        /// Caller-generated entropy for the new wallet.
        entropy: SetupEntropy,
    },
    /// Run the device's mnemonic restore flow. The simulator uses its fixed test mnemonic.
    RestoreFromMnemonic,
}

/// External data needed by BitBox02 management commands while keeping the interpreter sans-I/O.
#[derive(Clone, Debug)]
pub enum ManagementContext {
    /// Inputs for wallet initialization and its initial SD-card backup.
    Setup {
        /// Whether to create or restore a wallet.
        mode: SetupMode,
        /// Backup timestamp as Unix seconds.
        timestamp: u32,
        /// Local timezone offset from UTC, in seconds.
        timezone_offset: i32,
    },
    /// Inputs for the on-device mnemonic restore flow.
    Restore {
        /// Restore timestamp as Unix seconds.
        timestamp: u32,
        /// Local timezone offset from UTC, in seconds.
        timezone_offset: i32,
    },
}

/// USB vendor identifier of the BitBox02.
pub const BITBOX02_VID: u16 = 0x03eb;
/// USB product identifier of the BitBox02.
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

/// Opcode requesting device unlock.
pub const OP_UNLOCK: u8 = b'u';
/// Opcode requesting permission to begin a Noise handshake.
pub const OP_I_CAN_HAS_HANDSHAEK: u8 = b'h';
/// Opcode carrying a Noise handshake message.
pub const OP_HER_COMEZ_TEH_HANDSHAEK: u8 = b'H';
/// Opcode requesting pairing-code confirmation on the device.
pub const OP_I_CAN_HAS_PAIRIN_VERIFICASHUN: u8 = b'v';
/// Opcode carrying an encrypted Noise message.
pub const OP_NOISE_MSG: u8 = b'n';
/// Status byte indicating a successful operation.
pub const RESPONSE_SUCCESS: u8 = 0x00;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_entropy_debug_is_redacted() {
        let entropy = SetupEntropy::new([42; 32]);
        let debug = format!("{entropy:?}");
        assert_eq!(debug, "SetupEntropy([REDACTED])");
        assert!(!debug.contains("42"));
    }
}
