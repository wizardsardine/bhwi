use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
    str::FromStr,
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use bitcoin::{
    PublicKey,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bip32::{ChildNumber, DerivationPath, Xpub},
    secp256k1::Secp256k1,
    sign_message::{MessageSignature, signed_msg_hash},
};
use serde_json::Value;

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

const FINGERPRINT: &str = "73c5da0a";
const PREFIXED_TCP: &str = "tcp:127.0.0.1:8789";
const BARE_TCP: &str = "127.0.0.1:8789";

fn cli(path: &str) -> Cli {
    Cli::bitcoin().with_args(["--device-type", "specter", "--device-path", path])
}

fn confirm_cli_command(cli: Cli, args: &[&str]) -> Result<String> {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let port = env::var("SPECTER_GUI_PORT").unwrap_or_else(|_| "8787".into());
    let mut gui = TcpStream::connect(format!("127.0.0.1:{port}"))
        .context("connect Specter GUI controller")?;
    gui.set_read_timeout(Some(Duration::from_secs(15)))?;
    // The pinned TCPHost polls connections every 30ms. This gives it three
    // polls to adopt the socket; readiness of the actual approval still comes
    // from the following screen notification.
    thread::sleep(Duration::from_millis(100));
    let command = thread::spawn(move || cli.run_ok(args));
    let mut screen = [0; 128];
    let received = gui
        .read(&mut screen)
        .context("wait for Specter GUI confirmation screen")?;
    anyhow::ensure!(
        received > 0,
        "Specter GUI controller disconnected before confirmation"
    );
    gui.write_all(b"true\r\n")
        .context("confirm Specter GUI request")?;
    command.join().expect("Specter CLI command thread")
}

#[test]
fn specter_prefixed_tcp_lists_and_gets_xpub() -> Result<()> {
    assert_command(CommandCase {
        name: "Specter device list",
        cli: cli(PREFIXED_TCP),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(FINGERPRINT),
    })?;
    let xpub = cli(PREFIXED_TCP).run_ok(["xpub", "get", "m/84'/0'/0'"])?;
    assert!(xpub.trim().starts_with("xpub"));
    Ok(())
}

#[test]
fn specter_bare_tcp_selector_gets_fingerprint() -> Result<()> {
    assert_command(CommandCase {
        name: "Specter bare TCP device list",
        cli: cli(BARE_TCP),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(FINGERPRINT),
    })
}

#[test]
fn specter_list_pretty_and_json_keep_firmware_unavailable() -> Result<()> {
    let pretty = cli(PREFIXED_TCP).run_ok(["--format", "pretty", "device", "list"])?;
    assert!(pretty.contains("Specter-DIY"));
    assert!(pretty.contains("unavailable"));

    let json = cli(PREFIXED_TCP).run_ok(["--format", "json", "device", "list"])?;
    let devices: Vec<Value> = serde_json::from_str(json.trim())?;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["fingerprint"], FINGERPRINT);
    assert!(devices[0].get("firmware").is_none());
    assert!(devices[0].get("version").is_none());
    Ok(())
}

#[test]
fn specter_descriptor_address_requires_the_policy() -> Result<()> {
    let output = cli(PREFIXED_TCP).run_output([
        "--fingerprint",
        FINGERPRINT,
        "address",
        "get",
        "--from-descriptor",
        "specter-cli",
    ])?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--wallet-descriptor is required"));
    Ok(())
}

#[test]
fn specter_registers_wallet_and_displays_descriptor_address() -> Result<()> {
    let cli = cli(PREFIXED_TCP).with_args(["--fingerprint", FINGERPRINT]);
    let account = std::process::id() % 10_000;
    let account_path = format!("m/44'/0'/{account}'");
    let xpub = cli.run_ok(["xpub", "get", &account_path])?;
    let descriptor = format!(
        "wpkh([{FINGERPRINT}/{}]{}/<0;1>/*)",
        account_path.trim_start_matches("m/"),
        xpub.trim()
    );

    let name = format!("specter-cli-{}", std::process::id());
    let registered = confirm_cli_command(
        cli.clone(),
        &[
            "register-wallet",
            "--name",
            &name,
            "--descriptor",
            &descriptor,
        ],
    )?;
    assert!(registered.is_empty());

    let address = confirm_cli_command(
        cli,
        &[
            "address",
            "get",
            "--from-descriptor",
            &name,
            "--wallet-descriptor",
            &descriptor,
            "--display",
        ],
    )?;
    assert!(address.trim().starts_with("bc1q"));
    Ok(())
}

#[test]
fn specter_sign_message_returns_a_compact_signature() -> Result<()> {
    let cli = cli(PREFIXED_TCP).with_args(["--fingerprint", FINGERPRINT]);
    let xpub = Xpub::from_str(cli.run_ok(["xpub", "get", "m/84'/0'/0'"])?.trim())?;
    let message = "BHWI Specter-DIY CLI fixture";
    let signature = confirm_cli_command(
        cli,
        &[
            "sign-message",
            "--message",
            message,
            "--path",
            "m/84'/0'/0'/0/0",
        ],
    )?;
    let payload = BASE64_STANDARD
        .decode(signature.trim())
        .context("Specter CLI message signature is not base64")?;
    let signature = MessageSignature::from_slice(&payload)
        .context("Specter CLI message signature is not recoverable")?;
    let secp = Secp256k1::verification_only();
    let path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(0)?,
        ChildNumber::from_normal_idx(0)?,
    ]);
    let expected = PublicKey::new(xpub.derive_pub(&secp, &path)?.public_key);
    assert_eq!(
        signature.recover_pubkey(&secp, signed_msg_hash(message))?,
        expected
    );
    Ok(())
}
