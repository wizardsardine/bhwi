use anyhow::Result;

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

const TREZOR_FINGERPRINT: &str = "5c9e228d";
const TREZOR_EMULATOR_PATH: &str = "udp:127.0.0.1:21324";
const TREZOR_XPUB_44: &str = "tpubDDKn3FtHc74CaRrRbi1WFdJNaaenZkDWqq9NsEhcafnDZ4VuKeuLG2aKHm5SuwuLgAhRkkfHqcCxpnVNSrs5kJYZXwa6Ud431VnevzzzK3U";
const TREZOR_XPUB_84: &str = "tpubDCZB6sR48s4T5Cr8qHUYSZEFCQMMHRg8AoVKVmvcAP5bRw7ArDKeoNwKAJujV3xCPkBvXH5ejSgbgyN6kREmF7sMd41NdbuHa8n1DZNxSMg";

#[test]
fn trezor_device_list() -> Result<()> {
    assert_command(CommandCase {
        name: "device list",
        cli: Cli::global().with_args(["--device-path", TREZOR_EMULATOR_PATH]),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(TREZOR_FINGERPRINT),
    })
}

#[test]
fn trezor_xpub_get() -> Result<()> {
    assert_command(CommandCase {
        name: "xpub get m/44'/1'/0'",
        cli: Cli::for_device(TREZOR_FINGERPRINT),
        args: &["xpub", "get", "m/44'/1'/0'"],
        expected: ExpectedOutput::Exact(TREZOR_XPUB_44),
    })
}

#[test]
fn trezor_native_segwit_xpub_get() -> Result<()> {
    assert_command(CommandCase {
        name: "xpub get m/84'/1'/0'",
        cli: Cli::for_device(TREZOR_FINGERPRINT),
        args: &["xpub", "get", "m/84'/1'/0'"],
        expected: ExpectedOutput::Exact(TREZOR_XPUB_84),
    })
}

#[test]
fn trezor_descriptor_pubkeys() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor pubkeys account 0",
        cli: Cli::for_device(TREZOR_FINGERPRINT),
        args: &["descriptor", "pubkeys", "--account", "0"],
        expected: ExpectedOutput::DescriptorPubkeys {
            fingerprint: TREZOR_FINGERPRINT,
            account: 0,
        },
    })
}
