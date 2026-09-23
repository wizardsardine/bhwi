use std::{
    env,
    io::{ErrorKind, Read, Write},
    net::TcpStream,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
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
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MENU_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SCREEN_LINE: usize = 128;

fn cli(path: &str) -> Cli {
    Cli::bitcoin().with_args(["--device-type", "specter", "--device-path", path])
}

#[derive(Default)]
struct ScreenCodec(Vec<u8>);

impl ScreenCodec {
    fn push(&mut self, data: &[u8]) -> Result<()> {
        self.0.extend_from_slice(data);
        if self.0.len() > MAX_SCREEN_LINE {
            bail!("Specter GUI screen line exceeded the bounded controller buffer");
        }
        Ok(())
    }

    fn next(&mut self) -> Result<Option<String>> {
        let Some(end) = self.0.iter().position(|byte| *byte == b'\n') else {
            return Ok(None);
        };
        let mut line = self.0.drain(..=end).collect::<Vec<_>>();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            bail!("Specter GUI sent an empty screen line");
        }
        if !line.iter().all(u8::is_ascii_alphanumeric) {
            bail!("Specter GUI sent a non-screen controller line");
        }
        Ok(Some(
            String::from_utf8(line).context("Specter GUI screen name is UTF-8")?,
        ))
    }
}

struct GuiController {
    stream: TcpStream,
    codec: ScreenCodec,
}

impl GuiController {
    fn connect() -> Result<Self> {
        let port = env::var("SPECTER_GUI_PORT").unwrap_or_else(|_| "8787".into());
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .context("connect Specter GUI controller")?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        // TCPHost polls the accepted controller every 30ms. Prompt readiness
        // itself is driven by complete CRLF-delimited screen notifications.
        thread::sleep(Duration::from_millis(100));
        Ok(Self {
            stream,
            codec: ScreenCodec::default(),
        })
    }

    fn try_next_screen(&mut self, scenario: &str) -> Result<Option<String>> {
        if let Some(screen) = self.codec.next()? {
            return Ok(Some(screen));
        }
        let mut bytes = [0; 64];
        match self.stream.read(&mut bytes) {
            Ok(0) => bail!("{scenario}: Specter GUI controller closed before a screen line"),
            Ok(received) => {
                self.codec.push(&bytes[..received])?;
                self.codec.next()
            }
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                Ok(None)
            }
            Err(error) => Err(error).context(format!("{scenario}: read Specter GUI controller")),
        }
    }

    fn expect_menu(&mut self, scenario: &str) -> Result<()> {
        let deadline = Instant::now() + MENU_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(screen) = self.try_next_screen(scenario)? {
                if screen == "Menu" {
                    return Ok(());
                }
                bail!("{scenario}: expected trailing GUI Menu");
            }
        }
        bail!("{scenario}: timed out waiting for trailing GUI Menu")
    }

    fn confirm_cli_command(&mut self, scenario: &str, cli: Cli, args: &[&str]) -> Result<String> {
        let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let worker = thread::spawn(move || cli.run_ok(args));
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let mut saw_menu = false;

        while Instant::now() < deadline {
            if worker.is_finished() {
                let result = worker.join().map_err(|_| {
                    anyhow::anyhow!("{scenario}: Specter CLI command thread panicked")
                })?;
                if !saw_menu {
                    self.expect_menu(scenario)?;
                }
                return result;
            }
            if let Some(screen) = self.try_next_screen(scenario)? {
                if screen == "Menu" {
                    saw_menu = true;
                } else {
                    self.stream
                        .write_all(b"true\r\n")
                        .with_context(|| format!("{scenario}: confirm Specter GUI screen"))?;
                }
            }
        }
        bail!("{scenario}: Specter CLI command timed out")
    }
}

fn prefixed_tcp_lists_and_gets_xpub() -> Result<()> {
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

fn bare_tcp_selector_gets_fingerprint() -> Result<()> {
    assert_command(CommandCase {
        name: "Specter bare TCP device list",
        cli: cli(BARE_TCP),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(FINGERPRINT),
    })
}

fn list_pretty_and_json_keep_firmware_unavailable() -> Result<()> {
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

fn descriptor_address_requires_the_policy() -> Result<()> {
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

fn registers_wallet_and_displays_descriptor_address(gui: &mut GuiController) -> Result<()> {
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
    let registered = gui.confirm_cli_command(
        "CLI wallet import",
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

    let address = gui.confirm_cli_command(
        "CLI descriptor address",
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

fn sign_message_recovers_the_expected_key(gui: &mut GuiController) -> Result<()> {
    let cli = cli(PREFIXED_TCP).with_args(["--fingerprint", FINGERPRINT]);
    let xpub = Xpub::from_str(cli.run_ok(["xpub", "get", "m/84'/0'/0'"])?.trim())?;
    let message = "BHWI Specter-DIY CLI fixture";
    let output = gui.confirm_cli_command(
        "CLI message signing",
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
        .decode(output.trim())
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

#[test]
fn screen_codec_retains_fragmented_and_coalesced_lines() -> Result<()> {
    let mut codec = ScreenCodec::default();
    codec.push(b"Prom")?;
    assert!(codec.next()?.is_none());
    codec.push(b"pt\r\nMenu\r\n")?;
    assert_eq!(codec.next()?.as_deref(), Some("Prompt"));
    assert_eq!(codec.next()?.as_deref(), Some("Menu"));
    assert!(codec.next()?.is_none());
    Ok(())
}

#[test]
fn specter_cli_scenarios() -> Result<()> {
    let mut gui = GuiController::connect()?;

    prefixed_tcp_lists_and_gets_xpub()?;
    bare_tcp_selector_gets_fingerprint()?;
    list_pretty_and_json_keep_firmware_unavailable()?;
    descriptor_address_requires_the_policy()?;
    registers_wallet_and_displays_descriptor_address(&mut gui)?;
    sign_message_recovers_the_expected_key(&mut gui)?;
    Ok(())
}
