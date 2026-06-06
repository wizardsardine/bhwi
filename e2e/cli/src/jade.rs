use anyhow::Result;

use crate::support::{Cli, CommandCase, ExpectedOutput, basic_cli_cases, run_command_cases};

const JADE_FINGERPRINT: &str = "e3ebcc79";
const JADE_XPUB_44: &str = "tpubDCKD5cdxMEFd2i4cNa3PJUbUHMsGDxsnfqjxVpMoG1ymWYUQUaZzTcHQo3JwYgaKe2FyKGA2FzGPSVczBoAiHGyERuA1mZ2UkGKufEnUxKk";

#[test]
fn jade_basic_cli_commands() -> Result<()> {
    run_command_cases(&basic_cli_cases(JADE_FINGERPRINT, JADE_XPUB_44))
}

#[test]
fn jade_sign_message() -> Result<()> {
    run_command_cases(&[CommandCase {
        name: "sign message hello",
        cli: Cli::for_device(JADE_FINGERPRINT),
        args: &[
            "sign-message",
            "--message",
            "hello",
            "--path",
            "m/44'/1'/0'",
        ],
        expected: ExpectedOutput::Static(
            "H+SvKg15TSz+2C5ra6Q8/e8BaImOZVEeS0rOL6GCEt4vO+4xRRt+YYKavSqgAJBYZaGEiTqr7f9imyyElMNhYXU=",
        ),
    }])
}

#[test]
fn jade_address_by_path_is_unsupported() -> Result<()> {
    Cli::for_device(JADE_FINGERPRINT).assert_failure_contains(
        ["address", "get", "--from-path", "m/84'/1'/0'/0/0"],
        "Jade does not support path-based address display",
    )
}
