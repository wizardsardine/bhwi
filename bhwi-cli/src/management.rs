use anyhow::{Context, Result};
use bhwi::{
    bitbox::{ManagementContext, SetupEntropy, SetupMode},
    common::DeviceContext,
};
use chrono::Local;
use rand_core::{OsRng, RngCore};

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
    Ok(DeviceContext::BitBoxManagement(ManagementContext::Setup {
        mode,
        timestamp,
        timezone_offset,
    }))
}

pub fn bitbox_restore_context() -> Result<DeviceContext> {
    let (timestamp, timezone_offset) = timestamp_and_timezone_offset()?;
    Ok(DeviceContext::BitBoxManagement(
        ManagementContext::Restore {
            timestamp,
            timezone_offset,
        },
    ))
}

fn timestamp_and_timezone_offset() -> Result<(u32, i32)> {
    let now = Local::now();
    timestamp_and_timezone_offset_from(now.timestamp(), now.offset().local_minus_utc())
}

fn timestamp_and_timezone_offset_from(timestamp: i64, timezone_offset: i32) -> Result<(u32, i32)> {
    let timestamp = u32::try_from(timestamp).context("current timestamp does not fit in u32")?;
    Ok((timestamp, timezone_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulator_setup_uses_mnemonic_restore_without_entropy() {
        let context = bitbox_setup_context(true).unwrap();
        assert!(matches!(
            context,
            DeviceContext::BitBoxManagement(ManagementContext::Setup {
                mode: SetupMode::RestoreFromMnemonic,
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
}
