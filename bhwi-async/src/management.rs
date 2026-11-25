use std::fmt;

#[cfg(feature = "bitbox")]
use bhwi::bitbox::{ManagementContext, SetupMode};
#[cfg(any(feature = "bitbox", feature = "keepkey", feature = "trezor"))]
use bhwi::common::DeviceContext;

#[cfg(feature = "host-entropy")]
use rand_core::{OsRng, RngCore};

#[cfg(feature = "bitbox")]
pub use bhwi::bitbox::SetupEntropy;
#[cfg(feature = "trezor")]
pub use bhwi::trezor::HostPin;

/// Host randomness mixed into a new wallet's seed.
///
/// Only [`HostEntropy::from_os`] creates one, so a setup is never handed fixed
/// or zero bytes.
pub struct HostEntropy([u8; 32]);

impl HostEntropy {
    /// Reads 32 bytes from the operating system, with no fallback.
    #[cfg(feature = "host-entropy")]
    pub fn from_os() -> Result<Self, HostEntropyError> {
        let mut entropy = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut entropy)
            .map_err(HostEntropyError)?;
        Ok(Self(entropy))
    }
}

impl fmt::Debug for HostEntropy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostEntropy([REDACTED])")
    }
}

/// The operating system could not supply entropy for device setup.
#[cfg(feature = "host-entropy")]
#[derive(Debug, thiserror::Error)]
#[error("the operating system has no entropy available: {0}")]
pub struct HostEntropyError(rand_core::Error);

/// Creates Trezor setup context with OS-generated host entropy.
#[cfg(feature = "trezor")]
pub fn trezor_setup_context(entropy: HostEntropy) -> DeviceContext {
    DeviceContext::TrezorManagement(bhwi::trezor::ManagementContext::Setup {
        host_entropy: entropy.0,
    })
}

/// Creates Trezor PIN context from validated scrambled keypad positions.
#[cfg(feature = "trezor")]
pub fn trezor_pin_context(pin: bhwi::trezor::HostPin) -> DeviceContext {
    DeviceContext::TrezorManagement(bhwi::trezor::ManagementContext::Pin(pin))
}

/// Creates Trezor PIN context from a nonempty ASCII-digit position string.
///
/// Positions are not literal PIN digits; no 1–9 range check is performed.
#[cfg(feature = "trezor")]
pub fn trezor_pin_context_from_positions(
    positions: String,
) -> Result<DeviceContext, crate::HWIDeviceError> {
    let pin = bhwi::trezor::HostPin::new(positions)
        .map_err(|e| crate::HWIDeviceError::with_kind(e, crate::ErrorKind::InvalidInput))?;
    Ok(trezor_pin_context(pin))
}

/// Creates Trezor recovery context with the caller-supplied U2F counter.
#[cfg(feature = "trezor")]
pub fn trezor_restore_context(u2f_counter: u32) -> DeviceContext {
    DeviceContext::TrezorManagement(bhwi::trezor::ManagementContext::Restore { u2f_counter })
}

/// Chooses mnemonic restoration for an emulator or new-wallet setup with `entropy`.
#[cfg(feature = "bitbox")]
pub fn bitbox_setup_mode(is_emulated: bool, entropy: HostEntropy) -> SetupMode {
    if is_emulated {
        SetupMode::RestoreFromMnemonic
    } else {
        SetupMode::NewWallet {
            entropy: SetupEntropy::new(entropy.0),
        }
    }
}

/// Creates BitBox02 setup context with Unix seconds and a timezone offset in seconds.
#[cfg(feature = "bitbox")]
pub fn bitbox_setup_context(
    mode: SetupMode,
    timestamp: u32,
    timezone_offset: i32,
) -> DeviceContext {
    DeviceContext::BitBoxManagement(ManagementContext::Setup {
        mode,
        timestamp,
        timezone_offset,
    })
}

/// Creates BitBox02 restore context with Unix seconds and a timezone offset in seconds.
#[cfg(feature = "bitbox")]
pub fn bitbox_restore_context(timestamp: u32, timezone_offset: i32) -> DeviceContext {
    DeviceContext::BitBoxManagement(ManagementContext::Restore {
        timestamp,
        timezone_offset,
    })
}

/// Creates KeepKey setup context with OS-generated host entropy.
#[cfg(feature = "keepkey")]
pub fn keepkey_setup_context(entropy: HostEntropy) -> DeviceContext {
    DeviceContext::KeepKeyManagement(bhwi::keepkey::ManagementContext::Setup {
        host_entropy: entropy.0,
    })
}

/// Creates KeepKey PIN context from validated scrambled keypad positions.
#[cfg(feature = "keepkey")]
pub fn keepkey_pin_context(pin: bhwi::keepkey::HostPin) -> DeviceContext {
    DeviceContext::KeepKeyManagement(bhwi::keepkey::ManagementContext::Pin(pin))
}

/// Creates KeepKey PIN context from a nonempty ASCII-digit position string.
///
/// Positions are not literal PIN digits; no 1–9 range check is performed.
#[cfg(feature = "keepkey")]
pub fn keepkey_pin_context_from_positions(
    positions: String,
) -> Result<DeviceContext, crate::HWIDeviceError> {
    let pin = bhwi::keepkey::HostPin::new(positions)
        .map_err(|e| crate::HWIDeviceError::with_kind(e, crate::ErrorKind::InvalidInput))?;
    Ok(keepkey_pin_context(pin))
}

/// Creates KeepKey recovery context with the caller-supplied U2F counter.
#[cfg(feature = "keepkey")]
pub fn keepkey_restore_context(u2f_counter: u32) -> DeviceContext {
    DeviceContext::KeepKeyManagement(bhwi::keepkey::ManagementContext::Restore { u2f_counter })
}

#[cfg(all(test, feature = "host-entropy"))]
mod tests {
    use super::*;

    #[test]
    fn host_entropy_is_fresh_on_every_call() {
        let first = HostEntropy::from_os().unwrap();
        let second = HostEntropy::from_os().unwrap();
        assert_ne!(first.0, [0u8; 32]);
        assert_ne!(first.0, second.0);
        assert_eq!(format!("{first:?}"), "HostEntropy([REDACTED])");
    }
}
