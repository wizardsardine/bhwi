use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use bhwi_e2e_trezor::debuglink::{
    DEFAULT_DEBUGLINK_ADDR, DebugButton, button_reports, input_reports,
};

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

const TREZOR_FINGERPRINT: &str = "5c9e228d";
const TREZOR_EMULATOR_PATH: &str = "udp:127.0.0.1:21324";
const TREZOR_RESTORE_MNEMONIC: &str =
    "alcohol woman abuse must during monitor noble actual mixed trade anger aisle";
const TREZOR_RESTORE_FINGERPRINT: &str = "95d8f670";
const TREZOR_RESTORE_PIN: &str = "1234";
const TREZOR_XPUB_44: &str = "tpubDDKn3FtHc74CaRrRbi1WFdJNaaenZkDWqq9NsEhcafnDZ4VuKeuLG2aKHm5SuwuLgAhRkkfHqcCxpnVNSrs5kJYZXwa6Ud431VnevzzzK3U";
const TREZOR_XPUB_84: &str = "tpubDCZB6sR48s4T5Cr8qHUYSZEFCQMMHRg8AoVKVmvcAP5bRw7ArDKeoNwKAJujV3xCPkBvXH5ejSgbgyN6kREmF7sMd41NdbuHa8n1DZNxSMg";

fn management_cli() -> Cli {
    Cli::global().with_args(["--device-path", TREZOR_EMULATOR_PATH])
}

fn send(socket: &UdpSocket, reports: Vec<[u8; 64]>) -> Result<()> {
    for report in reports {
        socket.send(&report)?;
    }
    Ok(())
}

fn drive_trezor_recovery() -> Result<()> {
    let screen = Duration::from_millis(1200);
    let key = Duration::from_millis(350);
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.connect(DEFAULT_DEBUGLINK_ADDR)?;

    thread::sleep(screen);
    send(&socket, button_reports(DebugButton::Yes))?;
    thread::sleep(screen);
    send(&socket, input_reports(TREZOR_RESTORE_PIN))?;
    thread::sleep(screen);
    send(&socket, input_reports(TREZOR_RESTORE_PIN))?;
    thread::sleep(screen);
    send(&socket, input_reports("12"))?;
    thread::sleep(screen);
    send(&socket, button_reports(DebugButton::Yes))?;
    thread::sleep(screen);
    for word in TREZOR_RESTORE_MNEMONIC.split_whitespace() {
        send(&socket, input_reports(word))?;
        thread::sleep(key);
    }
    thread::sleep(screen);
    send(&socket, button_reports(DebugButton::Yes))
}

#[test]
#[ignore = "requires a fresh uninitialized Model T and leaves it initialized"]
fn trezor_restore_management_lifecycle() -> Result<()> {
    let cli = management_cli();
    let driver = thread::spawn(drive_trezor_recovery);

    let stdout = cli.run_ok(["device", "restore", "--word-count", "12"])?;
    assert!(stdout.is_empty());
    driver.join().expect("recovery driver panicked")?;

    assert_eq!(
        cli.run_ok(["device", "list"])?.trim(),
        TREZOR_RESTORE_FINGERPRINT
    );
    Ok(())
}

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
