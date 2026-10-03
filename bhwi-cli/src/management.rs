//! Management contexts built from local entropy, time, and PIN-position input.
//!
//! These helpers prepare host data; they do not perform device I/O.

#[cfg(any(feature = "bitbox", feature = "keepkey", feature = "trezor"))]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "bitbox")]
use bhwi::bitbox::{SetupEntropy, SetupMode};
use bhwi::common::DeviceContext;
#[cfg(any(feature = "bitbox", feature = "keepkey", feature = "trezor"))]
use chrono::Local;
use rand_core::{OsRng, RngCore};

/// Creates Trezor setup context with 32 bytes of OS-generated entropy.
///
/// # Panics
///
/// Panics if the operating system cannot supply random entropy.
#[cfg(feature = "trezor")]
pub fn trezor_setup_context() -> DeviceContext {
    let mut host_entropy = [0; 32];
    OsRng.fill_bytes(&mut host_entropy);
    bhwi_async::management::trezor_setup_context(host_entropy)
}

/// Creates Trezor PIN context from nonempty ASCII-digit keypad positions.
///
/// Positions are not literal PIN digits; no 1–9 range check is performed.
///
/// # Errors
///
/// Returns an error for empty input or non-ASCII digits.
#[cfg(feature = "trezor")]
pub fn trezor_pin_context(positions: String) -> Result<DeviceContext> {
    Ok(bhwi_async::management::trezor_pin_context_from_positions(
        positions,
    )?)
}

/// Creates Trezor recovery context using the current Unix time as its U2F counter.
///
/// # Errors
///
/// Returns an error if the timestamp does not fit in `u32`.
#[cfg(feature = "trezor")]
pub fn trezor_restore_context() -> Result<DeviceContext> {
    let u2f_counter = u2f_counter_from(Local::now().timestamp())?;
    Ok(bhwi_async::management::trezor_restore_context(u2f_counter))
}

/// Creates KeepKey setup context with 32 bytes of OS-generated entropy.
///
/// # Panics
///
/// Panics if the operating system cannot supply random entropy.
#[cfg(feature = "keepkey")]
pub fn keepkey_setup_context() -> DeviceContext {
    let mut host_entropy = [0; 32];
    OsRng.fill_bytes(&mut host_entropy);
    bhwi_async::management::keepkey_setup_context(host_entropy)
}

/// Creates KeepKey PIN context from nonempty ASCII-digit keypad positions.
///
/// Positions are not literal PIN digits; no 1–9 range check is performed.
///
/// # Errors
///
/// Returns an error for empty input or non-ASCII digits.
#[cfg(feature = "keepkey")]
pub fn keepkey_pin_context(positions: String) -> Result<DeviceContext> {
    Ok(bhwi_async::management::keepkey_pin_context_from_positions(
        positions,
    )?)
}

/// Creates KeepKey recovery context using the current Unix time as its U2F counter.
///
/// # Errors
///
/// Returns an error if the timestamp does not fit in `u32`.
#[cfg(feature = "keepkey")]
pub fn keepkey_restore_context() -> Result<DeviceContext> {
    let u2f_counter = u2f_counter_from(Local::now().timestamp())?;
    Ok(bhwi_async::management::keepkey_restore_context(u2f_counter))
}

#[cfg(any(feature = "keepkey", feature = "trezor"))]
fn u2f_counter_from(timestamp: i64) -> Result<u32> {
    u32::try_from(timestamp).context("current timestamp does not fit in u32")
}

/// Creates BitBox02 setup context with the current Unix time and local UTC offset.
///
/// Both time values are in seconds. Emulators use mnemonic restoration; physical
/// devices use new-wallet setup with 32 bytes of OS-generated entropy.
///
/// # Errors
///
/// Returns an error if the timestamp does not fit in `u32`.
///
/// # Panics
///
/// Panics if a physical device is selected and the operating system cannot supply entropy.
#[cfg(feature = "bitbox")]
pub fn bitbox_setup_context(is_emulated: bool) -> Result<DeviceContext> {
    let (timestamp, timezone_offset) = timestamp_and_timezone_offset()?;
    let mode = if is_emulated {
        SetupMode::RestoreFromMnemonic
    } else {
        let mut entropy = [0; 32];
        OsRng.fill_bytes(&mut entropy);
        SetupMode::NewWallet {
            entropy: SetupEntropy::new(entropy),
        }
    };
    Ok(bhwi_async::management::bitbox_setup_context(
        mode,
        timestamp,
        timezone_offset,
    ))
}

/// Creates BitBox02 mnemonic-restoration context with the current time and UTC offset.
///
/// Both time values are in seconds.
///
/// # Errors
///
/// Returns an error if the Unix timestamp does not fit in `u32`.
#[cfg(feature = "bitbox")]
pub fn bitbox_restore_context() -> Result<DeviceContext> {
    let (timestamp, timezone_offset) = timestamp_and_timezone_offset()?;
    Ok(bhwi_async::management::bitbox_restore_context(
        timestamp,
        timezone_offset,
    ))
}

#[cfg(feature = "bitbox")]
fn timestamp_and_timezone_offset() -> Result<(u32, i32)> {
    let now = Local::now();
    timestamp_and_timezone_offset_from(now.timestamp(), now.offset().local_minus_utc())
}

#[cfg(feature = "bitbox")]
fn timestamp_and_timezone_offset_from(timestamp: i64, timezone_offset: i32) -> Result<(u32, i32)> {
    let timestamp = u32::try_from(timestamp).context("current timestamp does not fit in u32")?;
    Ok((timestamp, timezone_offset))
}

#[cfg(all(test, feature = "bitbox"))]
mod tests {
    use super::*;
    use bhwi::bitbox::ManagementContext;

    #[test]
    fn simulator_setup_uses_mnemonic_restore_without_entropy() {
        assert!(matches!(
            bitbox_setup_context(true).unwrap(),
            DeviceContext::BitBoxManagement(ManagementContext::Setup {
                mode: SetupMode::RestoreFromMnemonic,
                ..
            })
        ));
        assert!(matches!(
            bitbox_setup_context(false).unwrap(),
            DeviceContext::BitBoxManagement(ManagementContext::Setup {
                mode: SetupMode::NewWallet { .. },
                ..
            })
        ));
    }

    #[test]
    fn timestamp_and_timezone_offset_preserves_seconds_east_of_utc() {
        assert_eq!(
            timestamp_and_timezone_offset_from(1_750_000_000, 3 * 60 * 60).unwrap(),
            (1_750_000_000, 3 * 60 * 60)
        );
        assert_eq!(
            timestamp_and_timezone_offset_from(1_750_000_000, -7 * 60 * 60).unwrap(),
            (1_750_000_000, -7 * 60 * 60)
        );
    }

    #[test]
    fn restore_context_contains_host_time() {
        assert!(matches!(
            bitbox_restore_context().unwrap(),
            DeviceContext::BitBoxManagement(ManagementContext::Restore { timestamp, .. })
                if timestamp > 0
        ));
    }

    #[test]
    #[cfg(feature = "keepkey")]
    fn keepkey_contexts_use_keepkey_management_variants() {
        assert!(matches!(
            keepkey_setup_context(),
            DeviceContext::KeepKeyManagement(bhwi::keepkey::ManagementContext::Setup { .. })
        ));
        assert!(matches!(
            keepkey_restore_context().unwrap(),
            DeviceContext::KeepKeyManagement(bhwi::keepkey::ManagementContext::Restore {
                u2f_counter
            }) if u2f_counter > 0
        ));
        assert!(matches!(
            keepkey_pin_context("7913".to_owned()).unwrap(),
            DeviceContext::KeepKeyManagement(bhwi::keepkey::ManagementContext::Pin(_))
        ));
        assert!(keepkey_pin_context("not-a-pin".to_owned()).is_err());
    }
}
