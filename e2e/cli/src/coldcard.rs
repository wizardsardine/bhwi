use anyhow::{Context, Result, bail};
use bhwi_async::{Transport, transport::coldcard::DEFAULT_CKCC_SOCKET};
use bhwi_cli::coldcard::emulator::EmulatorClient;
use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::Duration,
};

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

#[test]
fn coldcard_device_backup() -> Result<()> {
    let output = backup_output_path();
    let output_arg = output.to_string_lossy().to_string();

    let output_result = run_backup_command(&output_arg)?;

    assert!(output_result.stdout.is_empty());
    assert!(output_result.stderr.is_empty());
    let backup = fs::read(&output)?;
    assert!(backup.starts_with(b"7z\xbc\xaf'\x1c"));
    assert!(backup.len() > 1024);
    fs::remove_file(output)?;
    Ok(())
}

fn backup_output_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "bhwi-coldcard-backup-{}-{}.7z",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ))
}

fn run_backup_command(output: &str) -> Result<Output> {
    let bin = env::var("BHWI_BIN").context("BHWI_BIN must point to the built bhwi binary")?;
    let mut child = Command::new(bin)
        .args([
            "--network",
            "testnet",
            "--fingerprint",
            COLDCARD_FINGERPRINT,
            "device",
            "backup",
            "--output",
            output,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn bhwi backup command")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    runtime.block_on(async {
        let mut client = bhwi_async::transport::coldcard::hid::ColdcardTransportHID::new(
            EmulatorClient::new(DEFAULT_CKCC_SOCKET).await?,
        );
        for attempt in 0..240 {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            let key = if attempt < 8 { b"XKEYy" } else { b"XKEY1" };
            let _ = client.exchange(key, false).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let _ = child.kill();
        bail!("timed out waiting for bhwi device backup")
    })?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "bhwi device backup failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}
