#[cfg(feature = "bitbox")]
use bhwi::bitbox::{ManagementContext, SetupMode};
#[cfg(any(feature = "bitbox", feature = "keepkey", feature = "trezor"))]
use bhwi::common::DeviceContext;

#[cfg(feature = "bitbox")]
pub use bhwi::bitbox::SetupEntropy;
#[cfg(feature = "trezor")]
pub use bhwi::trezor::HostPin;

/// Creates Trezor setup context with 32 bytes of caller-generated entropy.
#[cfg(feature = "trezor")]
pub fn trezor_setup_context(host_entropy: [u8; 32]) -> DeviceContext {
    DeviceContext::TrezorManagement(bhwi::trezor::ManagementContext::Setup { host_entropy })
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
pub fn bitbox_setup_mode(is_emulated: bool, entropy: SetupEntropy) -> SetupMode {
    if is_emulated {
        SetupMode::RestoreFromMnemonic
    } else {
        SetupMode::NewWallet { entropy }
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

/// Creates KeepKey setup context with 32 bytes of caller-generated entropy.
#[cfg(feature = "keepkey")]
pub fn keepkey_setup_context(host_entropy: [u8; 32]) -> DeviceContext {
    DeviceContext::KeepKeyManagement(bhwi::keepkey::ManagementContext::Setup { host_entropy })
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
