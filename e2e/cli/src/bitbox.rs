use anyhow::Result;

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

// The BitBox02 simulator restores a fixed mnemonic, so its master fingerprint is
// deterministic (network-independent). See `e2e/bitbox` for the seed details.
const BITBOX_FINGERPRINT: &str = "4c00739d";
const BITBOX_PATH: &str = "tcp:127.0.0.1:15423";

fn management_cli() -> Cli {
    Cli::global().with_args(["--device-type", "bitbox02", "--device-path", BITBOX_PATH])
}

#[test]
#[ignore = "requires a fresh uninitialized simulator and ends by resetting it"]
fn bitbox_setup_management_lifecycle() -> Result<()> {
    let cli = management_cli();

    assert_eq!(cli.run_ok(["device", "list"])?, format!("{BITBOX_PATH}\n"));
    assert!(
        cli.run_ok(["device", "setup", "--label", "BHWI Setup"])?
            .is_empty()
    );
    assert_eq!(cli.run_ok(["device", "list"])?.trim(), BITBOX_FINGERPRINT);
    assert!(cli.run_ok(["device", "toggle-passphrase"])?.is_empty());
    assert!(cli.run_ok(["device", "toggle-passphrase"])?.is_empty());
    assert!(cli.run_ok(["device", "wipe"])?.is_empty());
    Ok(())
}

#[test]
#[ignore = "requires a fresh uninitialized simulator"]
fn bitbox_restore_management_lifecycle() -> Result<()> {
    let cli = management_cli();

    assert_eq!(cli.run_ok(["device", "list"])?, format!("{BITBOX_PATH}\n"));
    assert!(
        cli.run_ok(["device", "restore", "--label", "BHWI Restore"])?
            .is_empty()
    );
    assert_eq!(cli.run_ok(["device", "list"])?.trim(), BITBOX_FINGERPRINT);
    Ok(())
}

#[test]
fn bitbox_device_list() -> Result<()> {
    assert_command(CommandCase {
        name: "device list",
        cli: Cli::global(),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(BITBOX_FINGERPRINT),
    })
}

#[test]
fn bitbox_device_backup() -> Result<()> {
    let stdout = Cli::for_device(BITBOX_FINGERPRINT).run_ok(["device", "backup"])?;
    assert!(stdout.is_empty());
    Ok(())
}

#[test]
fn bitbox_descriptor_pubkeys() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor pubkeys account 0",
        cli: Cli::for_device(BITBOX_FINGERPRINT),
        args: &["descriptor", "pubkeys", "--account", "0"],
        expected: ExpectedOutput::DescriptorPubkeys {
            fingerprint: BITBOX_FINGERPRINT,
            account: 0,
        },
    })
}

#[test]
fn bitbox_keypool_get() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor keypool m/84'/1'/0' 0-4",
        cli: Cli::for_device(BITBOX_FINGERPRINT),
        args: &[
            "descriptor",
            "keypool",
            "--path",
            "m/84'/1'/0'",
            "--start",
            "0",
            "--end",
            "4",
        ],
        expected: ExpectedOutput::Keypool {
            fingerprint: BITBOX_FINGERPRINT,
            purpose: 84,
            account: 0,
            branch: 0,
            start: 0,
            end: 4,
            internal: false,
        },
    })
}
