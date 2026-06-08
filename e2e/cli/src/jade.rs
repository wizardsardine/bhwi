use anyhow::Result;

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

const JADE_FINGERPRINT: &str = "e3ebcc79";
const JADE_XPUB_44: &str = "tpubDCKD5cdxMEFd2i4cNa3PJUbUHMsGDxsnfqjxVpMoG1ymWYUQUaZzTcHQo3JwYgaKe2FyKGA2FzGPSVczBoAiHGyERuA1mZ2UkGKufEnUxKk";

#[test]
fn jade_device_list() -> Result<()> {
    assert_command(CommandCase {
        name: "device list",
        cli: Cli::global(),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(JADE_FINGERPRINT),
    })
}

#[test]
fn jade_xpub_get() -> Result<()> {
    assert_command(CommandCase {
        name: "xpub get m/44'/1'/0'",
        cli: Cli::for_device(JADE_FINGERPRINT),
        args: &["xpub", "get", "m/44'/1'/0'"],
        expected: ExpectedOutput::Exact(JADE_XPUB_44),
    })
}

#[test]
fn jade_descriptor_pubkeys() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor pubkeys account 0",
        cli: Cli::for_device(JADE_FINGERPRINT),
        args: &["descriptor", "pubkeys", "--account", "0"],
        expected: ExpectedOutput::DescriptorPubkeys {
            fingerprint: JADE_FINGERPRINT,
            account: 0,
        },
    })
}

#[test]
fn jade_sign_message() -> Result<()> {
    assert_command(CommandCase {
        name: "sign message hello",
        cli: Cli::for_device(JADE_FINGERPRINT),
        args: &[
            "sign-message",
            "--message",
            "hello",
            "--path",
            "m/44'/1'/0'",
        ],
        expected: ExpectedOutput::Exact(
            "H+SvKg15TSz+2C5ra6Q8/e8BaImOZVEeS0rOL6GCEt4vO+4xRRt+YYKavSqgAJBYZaGEiTqr7f9imyyElMNhYXU=",
        ),
    })
}
