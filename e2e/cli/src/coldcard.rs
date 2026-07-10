use anyhow::{Context, Result, bail};
use bhwi_async::{
    Transport,
    transport::coldcard::{DEFAULT_CKCC_SOCKET, hid::ColdcardTransportHID},
};
use bhwi_cli::coldcard::emulator::EmulatorClient;
use bitcoin::{
    Network,
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use std::{
    env, fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
    str::FromStr,
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
fn coldcard_register_wallet_reports_pending_and_persists() -> Result<()> {
    let cli = Cli::for_device(COLDCARD_FINGERPRINT);
    let account_path: DerivationPath = "48'/1'/0'/2'".parse()?;
    let device_xpub = Xpub::from_str(cli.run_ok(["xpub", "get", "48'/1'/0'/2'"])?.trim())?;
    let secp = Secp256k1::new();
    let cosigner_master = Xpriv::new_master(Network::Testnet, &[10u8; 32])?;
    let cosigner_fingerprint = cosigner_master.fingerprint(&secp);
    let cosigner_xpriv = cosigner_master.derive_priv(&secp, &account_path)?;
    let cosigner_xpub = Xpub::from_priv(&secp, &cosigner_xpriv);
    let descriptor = format!(
        "wsh(sortedmulti(2,[{COLDCARD_FINGERPRINT}/{account_path}]{device_xpub}/<0;1>/*,[{cosigner_fingerprint}/{account_path}]{cosigner_xpub}/<0;1>/*))"
    );

    let output = run_register_command(&descriptor)?;
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "Wallet registration is pending confirmation on the device.\n"
    );
    Ok(())
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

fn run_register_command(descriptor: &str) -> Result<Output> {
    let bin = env::var("BHWI_BIN").context("BHWI_BIN must point to the built bhwi binary")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let mut control =
            ColdcardTransportHID::new(EmulatorClient::new(DEFAULT_CKCC_SOCKET).await?);
        control
            .exchange(b"EXECsettings.set('multisig', []); settings.save()", false)
            .await?;
        Ok::<_, anyhow::Error>(())
    })?;

    let mut child = Command::new(bin)
        .args([
            "--network",
            "testnet",
            "--fingerprint",
            COLDCARD_FINGERPRINT,
            "register-wallet",
            "--name",
            "cold-cli",
            "--descriptor",
            descriptor,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn bhwi register-wallet command")?;

    let persisted = runtime.block_on(async {
        let mut control =
            ColdcardTransportHID::new(EmulatorClient::new(DEFAULT_CKCC_SOCKET).await?);
        for _ in 0..240 {
            if child.try_wait()?.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if child.try_wait()?.is_none() {
            let _ = child.kill();
            bail!("timed out waiting for bhwi register-wallet acknowledgement");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        control.exchange(b"XKEYy", false).await?;
        for _ in 0..40 {
            let response = control
                .exchange(b"EVALsettings.get('multisig', [])", false)
                .await?;
            if response
                .strip_prefix(b"biny")
                .is_some_and(|value| String::from_utf8_lossy(value).contains("cold-cli"))
            {
                return Ok(true);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(false)
    })?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "bhwi register-wallet failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if !persisted {
        bail!(
            "Coldcard multisig registration was not persisted\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}
