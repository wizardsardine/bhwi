use anyhow::Result;

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

const COLDCARD_FINGERPRINT: &str = "0f056943";
const COLDCARD_XPUB_44: &str = "tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB";

#[test]
fn coldcard_device_list() -> Result<()> {
    assert_command(CommandCase {
        name: "device list",
        cli: Cli::global(),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(COLDCARD_FINGERPRINT),
    })
}

#[test]
fn coldcard_xpub_get() -> Result<()> {
    assert_command(CommandCase {
        name: "xpub get m/44'/1'/0'",
        cli: Cli::for_device(COLDCARD_FINGERPRINT),
        args: &["xpub", "get", "m/44'/1'/0'"],
        expected: ExpectedOutput::Exact(COLDCARD_XPUB_44),
    })
}

#[test]
fn coldcard_descriptor_pubkeys() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor pubkeys account 0",
        cli: Cli::for_device(COLDCARD_FINGERPRINT),
        args: &["descriptor", "pubkeys", "--account", "0"],
        expected: ExpectedOutput::DescriptorPubkeys {
            fingerprint: COLDCARD_FINGERPRINT,
            account: 0,
        },
    })
}

#[test]
fn coldcard_keypool_get() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor keypool m/84'/1'/0' 0-4",
        cli: Cli::for_device(COLDCARD_FINGERPRINT),
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
            fingerprint: COLDCARD_FINGERPRINT,
            purpose: 84,
            account: 0,
            branch: 0,
            start: 0,
            end: 4,
            internal: false,
        },
    })
}
