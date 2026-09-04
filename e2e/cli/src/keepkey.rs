use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{ChildStderr, ChildStdin, Command, Output, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use bhwi_cli::hwi::{PIN_MATRIX_DESCRIPTION, SEND_PIN_INSTRUCTION};
use bhwi_e2e_keepkey::debuglink::{
    DEFAULT_MAIN_ADDR, DebugButton, DebugLink, KeepKeyHostInteraction, SYNTHETIC_MNEMONIC,
    lock_device,
};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
    absolute::LockTime,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    psbt::{Input, Output as PsbtOutput, Psbt},
    secp256k1::Secp256k1,
    sighash::SighashCache,
    sign_message::{MessageSignature, signed_msg_hash},
    transaction::Version as TxVersion,
};

use crate::support::{COMMAND_TIMEOUT, Cli, CommandCase, ExpectedOutput, assert_command};

const FINGERPRINT: &str = "95d8f670";
const XPUB_44: &str = "tpubDCknDegFqAdP4V2AhHhs635DPe8N1aTjfKE9m2UFbdej8zmeNbtqDzK59SxnsYSRSx5uS3AujbwgANUiAk4oHmDNUKoGGkWWUY6c48WgjEx";
const XPUB_49: &str = "tpubDDfS76c9NLz6v8CxwsCBi6YFcW463axCZpc3FR26othehmeXowmSBJ6TVPYYqhkekpivwRgkvdHgy8bCp5eHrqu33bGanQQH2qnVbPLUJEh";
const XPUB_84: &str = "tpubDDPHCt8nzaf3HZXAMeUj3grAcDdXmyy6BkUZgMyhCjUDLwpdE4gdzCFH6rG9Ex9PukLURFmGYhbrZAXzP4D464g8wHa2FRz3cbB6Q6QGqno";
const TEST_PIN: &str = "1234";

fn cli() -> Cli {
    Cli::global().with_args([
        "--device-type",
        "keepkey",
        "--device-path",
        DEFAULT_MAIN_ADDR,
    ])
}

fn cli_with_passphrase(passphrase: &str) -> Cli {
    cli().with_args(["--passphrase", passphrase])
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build KeepKey E2E runtime")
}

fn with_decisions<T, F>(button: DebugButton, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Arc<AtomicBool>) -> Result<T> + Send + 'static,
{
    let runtime = runtime()?;
    let debug = runtime.block_on(DebugLink::connect_default())?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let worker = thread::spawn(move || {
        let _ = sender.send(operation(worker_cancelled));
    });
    let received = runtime.block_on(debug.drive(button, receiver));
    if received.is_err() {
        cancelled.store(true, Ordering::Release);
    }
    worker
        .join()
        .map_err(|_| anyhow!("KeepKey CLI worker panicked"))?;
    received?.map_err(|_| anyhow!("KeepKey CLI worker stopped"))?
}

fn run_approved<I, S>(cli: &Cli, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let cli = cli.clone();
    let args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect();
    with_decisions(DebugButton::Yes, move |cancelled| {
        cli.run_ok_cancellable(args, cancelled)
    })
}

fn run_output_approved<I, S>(cli: &Cli, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let cli = cli.clone();
    let args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect();
    with_decisions(DebugButton::Yes, move |cancelled| {
        cli.run_output_cancellable(args, cancelled)
    })
}

#[derive(Clone, Copy)]
enum Wrapper {
    Legacy,
    ShWit,
    Wit,
}

impl Wrapper {
    const ALL: [Self; 3] = [Self::Legacy, Self::ShWit, Self::Wit];

    fn purpose(self) -> u32 {
        match self {
            Self::Legacy => 44,
            Self::ShWit => 49,
            Self::Wit => 84,
        }
    }

    fn xpub(self) -> Xpub {
        Xpub::from_str(match self {
            Self::Legacy => XPUB_44,
            Self::ShWit => XPUB_49,
            Self::Wit => XPUB_84,
        })
        .unwrap()
    }

    fn address_format(self) -> &'static str {
        match self {
            Self::Legacy => "p2pkh",
            Self::ShWit => "p2sh",
            Self::Wit => "p2wpkh",
        }
    }

    fn address(self, child: Xpub) -> Address {
        match self {
            Self::Legacy => Address::p2pkh(PublicKey::new(child.public_key), Network::Testnet),
            Self::ShWit => Address::p2shwpkh(&child.to_pub(), Network::Testnet),
            Self::Wit => Address::p2wpkh(&child.to_pub(), Network::Testnet),
        }
    }
}

fn suffix(change: u32, index: u32) -> DerivationPath {
    DerivationPath::from(vec![
        ChildNumber::from_normal_idx(change).unwrap(),
        ChildNumber::from_normal_idx(index).unwrap(),
    ])
}

#[test]
fn keepkey_device_list() -> Result<()> {
    assert_command(CommandCase {
        name: "KeepKey device list",
        cli: cli(),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(FINGERPRINT),
    })?;

    let json: serde_json::Value = serde_json::from_str(
        &cli()
            .with_args(["--format", "json"])
            .run_ok(["device", "list"])?,
    )?;
    let devices = json
        .as_array()
        .context("device list JSON is not an array")?;
    assert_eq!(devices.len(), 1);
    let device = &devices[0];
    assert_eq!(device["name"], "KeepKey Emulator");
    assert_eq!(device["device_type"], "keepkey");
    assert_eq!(device["path"], DEFAULT_MAIN_ADDR);
    assert_eq!(device["model"], "keepkey_simulator");
    assert_eq!(device["is_emulated"], true);
    assert_eq!(device["fingerprint"], FINGERPRINT);
    assert_eq!(device["label"], "test");
    assert_eq!(device["version"], "7.10.0");
    Ok(())
}

#[test]
fn keepkey_exact_account_xpubs() -> Result<()> {
    let cli = cli();
    for (path, expected) in [
        ("m/44'/1'/0'", XPUB_44),
        ("m/49'/1'/0'", XPUB_49),
        ("m/84'/1'/0'", XPUB_84),
    ] {
        assert_eq!(cli.run_ok(["xpub", "get", path])?, format!("{expected}\n"));
    }
    Ok(())
}

#[test]
fn keepkey_descriptors_and_keypool() -> Result<()> {
    let cli = cli();
    let xpub_86 = cli.run_ok(["xpub", "get", "m/86'/1'/0'"])?;
    let xpub_86 = xpub_86.trim();
    let descriptors = cli.run_ok(["descriptor", "pubkeys", "--account", "0"])?;
    let expected = [
        format!("pkh([{FINGERPRINT}/44'/1'/0']{XPUB_44}/0/*)"),
        format!("wpkh([{FINGERPRINT}/84'/1'/0']{XPUB_84}/0/*)"),
        format!("sh(wpkh([{FINGERPRINT}/49'/1'/0']{XPUB_49}/0/*))"),
        format!("tr([{FINGERPRINT}/86'/1'/0']{xpub_86}/0/*)"),
        format!("pkh([{FINGERPRINT}/44'/1'/0']{XPUB_44}/1/*)"),
        format!("wpkh([{FINGERPRINT}/84'/1'/0']{XPUB_84}/1/*)"),
        format!("sh(wpkh([{FINGERPRINT}/49'/1'/0']{XPUB_49}/1/*))"),
        format!("tr([{FINGERPRINT}/86'/1'/0']{xpub_86}/1/*)"),
    ]
    .join("\n");
    assert_eq!(descriptors, format!("{expected}\n"));

    let keypool = cli.run_ok([
        "descriptor",
        "keypool",
        "--path",
        "m/84'/1'/0'",
        "--start",
        "0",
        "--end",
        "4",
    ])?;
    assert_eq!(
        keypool,
        format!(
            "wpkh([{FINGERPRINT}/84'/1'/0']{XPUB_84}/0/*) range=0-4 internal=false keypool=true\n"
        )
    );
    Ok(())
}

#[test]
fn keepkey_legacy_wrapped_and_native_addresses() -> Result<()> {
    let secp = Secp256k1::verification_only();
    let cli = cli();
    let child_path = suffix(0, 0);
    for wrapper in Wrapper::ALL {
        let path = format!("m/{}'/1'/0'/0/0", wrapper.purpose());
        let child = wrapper.xpub().derive_pub(&secp, &child_path)?;
        let output = run_approved(
            &cli,
            [
                "address",
                "get",
                "--from-path",
                &path,
                "--address-format",
                wrapper.address_format(),
                "--display",
            ],
        )?;
        assert_eq!(output.trim(), wrapper.address(child).to_string());
    }
    Ok(())
}

fn previous_tx(value: u64, script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }],
    }
}

fn native_psbt() -> (Psbt, PublicKey) {
    let secp = Secp256k1::verification_only();
    let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
    let account: DerivationPath = "m/84'/1'/0'".parse().unwrap();
    let xpub = Xpub::from_str(XPUB_84).unwrap();
    let receive_path = suffix(0, 0);
    let change_path = suffix(1, 0);
    let receive = xpub.derive_pub(&secp, &receive_path).unwrap();
    let change = xpub.derive_pub(&secp, &change_path).unwrap();
    let receive_script = Address::p2wpkh(&receive.to_pub(), Network::Testnet).script_pubkey();
    let previous = previous_tx(50_000, receive_script.clone());
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: previous.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: Address::p2wpkh(&change.to_pub(), Network::Testnet).script_pubkey(),
        }],
    })
    .unwrap();
    psbt.inputs[0] = Input {
        non_witness_utxo: Some(previous),
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: receive_script,
        }),
        bip32_derivation: [(
            receive.public_key,
            (fingerprint, account.extend(receive_path)),
        )]
        .into(),
        ..Default::default()
    };
    psbt.outputs[0] = PsbtOutput {
        bip32_derivation: [(
            change.public_key,
            (fingerprint, account.extend(change_path)),
        )]
        .into(),
        ..Default::default()
    };
    (psbt, PublicKey::new(receive.public_key))
}

fn owned_taproot_psbt(account_xpub: &Xpub) -> Psbt {
    let secp = Secp256k1::verification_only();
    let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
    let key = account_xpub
        .derive_pub(&secp, &suffix(0, 0))
        .unwrap()
        .public_key
        .x_only_public_key()
        .0;
    let script = ScriptBuf::new_p2tr(&secp, key, None);
    let previous = previous_tx(50_000, script.clone());
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: previous.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: script.clone(),
        }],
    })
    .unwrap();
    psbt.inputs[0] = Input {
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script,
        }),
        tap_internal_key: Some(key),
        tap_key_origins: [(
            key,
            (
                Vec::new(),
                (fingerprint, "m/86'/1'/0'/0/0".parse().unwrap()),
            ),
        )]
        .into(),
        ..Default::default()
    };
    psbt
}

#[test]
fn taproot_rejection_fixtures_match_their_bip86_origins() -> Result<()> {
    let account_xpub = Xpub::from_str(cli().run_ok(["xpub", "get", "m/86'/1'/0'"])?.trim())?;
    let psbt = owned_taproot_psbt(&account_xpub);
    let secp = Secp256k1::verification_only();
    let child: DerivationPath = "m/0/0".parse()?;
    let full_path: DerivationPath = "m/86'/1'/0'/0/0".parse()?;
    let expected_key = account_xpub
        .derive_pub(&secp, &child)?
        .public_key
        .x_only_public_key()
        .0;
    let input = &psbt.inputs[0];

    assert_eq!(input.tap_internal_key, Some(expected_key));
    assert_eq!(input.tap_key_origins.len(), 1);
    let (leaf_hashes, origin) = input
        .tap_key_origins
        .get(&expected_key)
        .context("Taproot fixture is missing its BIP86 key origin")?;
    assert!(leaf_hashes.is_empty());
    assert_eq!(origin, &(Fingerprint::from_str(FINGERPRINT)?, full_path));

    let expected_script = ScriptBuf::new_p2tr(&secp, expected_key, None);
    assert_eq!(
        input
            .witness_utxo
            .as_ref()
            .context("Taproot fixture is missing its witness UTXO")?
            .script_pubkey,
        expected_script
    );
    assert_eq!(psbt.unsigned_tx.output[0].script_pubkey, expected_script);
    Ok(())
}

struct TempPsbt(PathBuf);

impl TempPsbt {
    fn new(psbt: &Psbt) -> Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before Unix epoch")?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("bhwi-keepkey-{}-{nonce}.psbt", std::process::id()));
        fs::write(&path, psbt.to_string()).context("write temporary KeepKey PSBT")?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPsbt {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn verify_psbt_signature(original: &Psbt, signed: &Psbt, key: &PublicKey) -> Result<()> {
    let mut normalized = signed.clone();
    let signature = normalized
        .inputs
        .get_mut(0)
        .context("signed PSBT has no input 0")?
        .partial_sigs
        .remove(key)
        .context("signed PSBT has no KeepKey signature")?;
    let mut cache = SighashCache::new(&normalized.unsigned_tx);
    let (message, sighash_type) = normalized.sighash_ecdsa(0, &mut cache)?;
    assert_eq!(signature.sighash_type, sighash_type);
    Secp256k1::verification_only().verify_ecdsa(&message, &signature.signature, &key.inner)?;
    if &normalized != original {
        bail!("signed PSBT changed data other than the expected partial signature");
    }
    Ok(())
}

#[test]
fn psbt_verifier_rejects_non_signature_mutation() -> Result<()> {
    let (original, _) = native_psbt();
    let mut signed = original.clone();
    let secp = Secp256k1::new();
    let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[1; 32])?;
    let key = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &secret_key,
    ));
    let mut cache = SighashCache::new(&signed.unsigned_tx);
    let (message, sighash_type) = signed.sighash_ecdsa(0, &mut cache)?;
    signed.inputs[0].partial_sigs.insert(
        key,
        bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&message, &secret_key),
            sighash_type,
        },
    );
    signed.outputs[0].redeem_script = Some(ScriptBuf::new());

    assert!(verify_psbt_signature(&original, &signed, &key).is_err());
    Ok(())
}

#[test]
fn keepkey_psbt_signature_is_cryptographically_valid() -> Result<()> {
    let (original, key) = native_psbt();
    let file = TempPsbt::new(&original)?;
    let path = file
        .path()
        .to_str()
        .context("temporary PSBT path is not UTF-8")?;
    let output = run_approved(&cli(), ["sign-psbt", "--psbt", path])?;
    let signed = Psbt::from_str(output.trim()).context("parse signed KeepKey PSBT")?;
    verify_psbt_signature(&original, &signed, &key)
}

#[test]
fn keepkey_message_signature_recovers_the_derived_key() -> Result<()> {
    let message = "hello";
    let output = run_approved(
        &cli(),
        [
            "sign-message",
            "--message",
            message,
            "--path",
            "m/44'/1'/0'/0/0",
        ],
    )?;
    let payload = BASE64_STANDARD
        .decode(output.trim())
        .context("KeepKey message signature is not base64")?;
    let signature = MessageSignature::from_slice(&payload)
        .context("KeepKey message signature is not recoverable")?;
    let secp = Secp256k1::verification_only();
    let expected = PublicKey::new(
        Xpub::from_str(XPUB_44)?
            .derive_pub(&secp, &suffix(0, 0))?
            .public_key,
    );
    assert_eq!(
        signature.recover_pubkey(&secp, signed_msg_hash(message))?,
        expected
    );
    Ok(())
}

fn assert_failure<I, S>(cli: &Cli, args: I, expected: &str, sensitive_values: &[&str]) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let output = cli.run_output(args)?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "failed command did not exit with code 1"
    );
    assert!(output.stdout.is_empty(), "failed command wrote stdout");
    let stderr = String::from_utf8(output.stderr)?;
    for sensitive in sensitive_values {
        assert!(
            !stderr.contains(*sensitive),
            "failed command leaked a sensitive value to stderr"
        );
    }

    let first = format!("Error: {expected}");
    if stderr != format!("{first}\n") {
        let body = stderr
            .strip_suffix('\n')
            .expect("failure stderr must end with one newline");
        let lines: Vec<_> = body.split('\n').collect();
        assert_eq!(lines.first().copied(), Some(first.as_str()));
        assert_eq!(lines.get(1).copied(), Some(""));
        assert_eq!(lines.get(2).copied(), Some("Caused by:"));
        assert!(lines.len() >= 4, "anyhow cause block has no causes");

        let mut previous = expected;
        for (index, line) in lines[3..].iter().enumerate() {
            let prefix = format!("    {index}: ");
            let cause = line
                .strip_prefix(&prefix)
                .unwrap_or_else(|| panic!("unexpected anyhow cause line: {line}"));
            assert!(!cause.is_empty(), "anyhow cause text is empty");
            assert!(
                cause.len() < previous.len() && previous.ends_with(cause),
                "anyhow cause is not a strict suffix of its parent: {cause}"
            );
            previous = cause;
        }
    }
    Ok(())
}

#[test]
fn keepkey_unsupported_paths_are_exact() -> Result<()> {
    let cli = cli();
    assert_failure(
        &cli,
        [
            "address",
            "get",
            "--from-path",
            "m/86'/1'/0'/0/0",
            "--address-format",
            "p2tr",
            "--display",
        ],
        "hwi device error: interpreter error: unsupported display address: KeepKey does not support Taproot address display",
        &[],
    )?;

    let xpub_86 = Xpub::from_str(cli.run_ok(["xpub", "get", "m/86'/1'/0'"])?.trim())?;
    let taproot = owned_taproot_psbt(&xpub_86);
    let taproot_secret = taproot.to_string();
    let file = TempPsbt::new(&taproot)?;
    assert_failure(
        &cli,
        [
            "sign-psbt",
            "--psbt",
            file.path()
                .to_str()
                .context("temporary PSBT path is not UTF-8")?,
        ],
        "hwi device error: interpreter error: missing command info: KeepKey does not support Taproot inputs",
        &[taproot_secret.as_str()],
    )?;
    assert_failure(
        &cli,
        ["address", "get", "--from-descriptor", "not-registered"],
        "hwi device error: interpreter error: unsupported display address: descriptor address display is not yet supported",
        &[],
    )?;

    let secp = Secp256k1::new();
    let account: DerivationPath = "m/48'/1'/0'/0'".parse()?;
    let cosigner_root = Xpriv::new_master(Network::Testnet, &[9u8; 32])?;
    let cosigner_fingerprint = cosigner_root.fingerprint(&secp);
    let cosigner_xpub = Xpub::from_priv(&secp, &cosigner_root.derive_priv(&secp, &account)?);
    let device_xpub = cli.run_ok(["xpub", "get", "m/48'/1'/0'/0'"])?;
    for descriptor in [
        format!(
            "wsh(sortedmulti(2,[{FINGERPRINT}/48'/1'/0'/0']{}/0/*,[{cosigner_fingerprint}/48'/1'/0'/0']{cosigner_xpub}/0/*))",
            device_xpub.trim()
        ),
        format!(
            "wsh(multi(2,[{FINGERPRINT}/48'/1'/0'/0']{}/0/*,[{cosigner_fingerprint}/48'/1'/0'/0']{cosigner_xpub}/0/*))",
            device_xpub.trim()
        ),
    ] {
        assert_failure(
            &cli,
            [
                "register-wallet",
                "--name",
                "keepkey-unsupported",
                "--descriptor",
                &descriptor,
            ],
            "hwi device error: interpreter error: missing command info: register_wallet is not supported",
            &[],
        )?;
    }
    assert_failure(
        &cli,
        ["device", "backup"],
        "hwi device error: interpreter error: missing command info: The Keepkey does not support creating a backup via software",
        &[],
    )
}

struct InteractiveOutput {
    stdout: String,
    pin_kinds: Vec<bhwi::common::PinMatrixRequestKind>,
    recovery_requests: usize,
}

fn request_from_prompt(line: &str) -> Result<Option<bhwi::common::HostRequest>> {
    use bhwi::common::{HostRequest, PinMatrixRequestKind};

    let request = match line {
        "Enter current PIN positions:" => Some(HostRequest::PinMatrix {
            kind: PinMatrixRequestKind::Current,
        }),
        "Enter new PIN positions:" => Some(HostRequest::PinMatrix {
            kind: PinMatrixRequestKind::NewFirst,
        }),
        "Re-enter new PIN positions:" => Some(HostRequest::PinMatrix {
            kind: PinMatrixRequestKind::NewSecond,
        }),
        _ => None,
    };
    if request.is_some() || PIN_MATRIX_DESCRIPTION.lines().any(|known| known == line) {
        return Ok(request);
    }

    const PREFIX: &str = "Recovery word ";
    const MIDDLE: &str = ", character ";
    const SUFFIX: &str = " (letter/space/backspace/done):";
    if let Some(value) = line
        .strip_prefix(PREFIX)
        .and_then(|line| line.strip_suffix(SUFFIX))
    {
        let (word, character) = value
            .split_once(MIDDLE)
            .context("invalid KeepKey recovery prompt")?;
        return Ok(Some(HostRequest::RecoveryCharacter {
            word_position: word
                .parse()
                .context("invalid KeepKey recovery word position")?,
            character_position: character
                .parse()
                .context("invalid KeepKey recovery character position")?,
        }));
    }
    bail!("unexpected KeepKey host prompt")
}

#[test]
fn keepkey_prompt_markers_are_exact() -> Result<()> {
    use bhwi::common::{HostRequest, PinMatrixRequestKind};

    assert_eq!(
        request_from_prompt("Enter new PIN positions:")?,
        Some(HostRequest::PinMatrix {
            kind: PinMatrixRequestKind::NewFirst,
        })
    );
    assert_eq!(
        request_from_prompt("Recovery word 4, character 2 (letter/space/backspace/done):")?,
        Some(HostRequest::RecoveryCharacter {
            word_position: 4,
            character_position: 2,
        })
    );
    assert!(request_from_prompt(PIN_MATRIX_DESCRIPTION.lines().next().unwrap())?.is_none());
    assert!(request_from_prompt("unrecognized prompt").is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn silent_interactive_child_is_killed_and_reaped() {
    use std::{
        env,
        path::Path,
        process::{self, Command},
    };

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let pid_file = env::temp_dir().join(format!(
        "bhwi-e2e-interactive-timeout-{}-{nonce}.pid",
        process::id()
    ));
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("printf '%s' \"$$\" > \"$1\"; exec sleep 30")
        .arg("bhwi-interactive-timeout-test")
        .arg(&pid_file);
    let error = run_interactive_process(
        command,
        Arc::new(AtomicBool::new(false)),
        Duration::from_millis(100),
        |mut stderr, _stdin| {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes)?;
            Ok(())
        },
    )
    .expect_err("silent interactive command should time out");
    assert!(error.to_string().contains("timed out"));

    let pid = fs::read_to_string(&pid_file).expect("timed-out child should record its pid");
    fs::remove_file(pid_file).expect("remove child pid file");
    assert!(
        !Path::new("/proc").join(pid.trim()).exists(),
        "timed-out interactive child was not reaped"
    );
}

fn run_interactive_process<T, F>(
    mut command: Command,
    cancelled: Arc<AtomicBool>,
    timeout: Duration,
    prompt: F,
) -> Result<(Vec<u8>, T)>
where
    T: Send + 'static,
    F: FnOnce(ChildStderr, ChildStdin) -> Result<T> + Send + 'static,
{
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Stop {
        Exited,
        TimedOut,
        Cancelled,
        WaitFailed,
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn interactive KeepKey CLI")?;
    let stdin = child.stdin.take().expect("stdin was piped");
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let prompt_cancelled = Arc::clone(&cancelled);
    let prompt_worker = thread::spawn(move || {
        let result = prompt(stderr, stdin);
        if result.is_err() {
            prompt_cancelled.store(true, Ordering::Release);
        }
        result
    });
    let stdout_worker = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });

    let started = Instant::now();
    let mut status = None;
    let mut wait_error = None;
    let stop = loop {
        if cancelled.load(Ordering::Acquire) {
            break Stop::Cancelled;
        }
        match child.try_wait() {
            Ok(Some(exit_status)) => {
                status = Some(exit_status);
                break Stop::Exited;
            }
            Ok(None) => {}
            Err(error) => {
                wait_error = Some(error);
                break Stop::WaitFailed;
            }
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break Stop::TimedOut;
        }
        thread::sleep(Duration::from_millis(25).min(remaining));
    };

    let reap_error = if stop != Stop::Exited {
        cancelled.store(true, Ordering::Release);
        let _ = child.kill();
        child.wait().err()
    } else {
        None
    };

    let stdout = stdout_worker.join();
    let prompt = prompt_worker.join();
    let stdout = stdout
        .map_err(|_| anyhow!("interactive KeepKey CLI stdout reader panicked"))?
        .context("read interactive KeepKey CLI stdout")?;
    let prompt =
        prompt.map_err(|_| anyhow!("interactive KeepKey CLI prompt worker panicked"))??;

    if let Some(error) = reap_error {
        return Err(error).context("kill and reap interactive KeepKey CLI");
    }
    if let Some(error) = wait_error {
        return Err(error).context("poll interactive KeepKey CLI");
    }
    match stop {
        Stop::TimedOut => bail!("interactive KeepKey CLI timed out after {timeout:?}"),
        Stop::Cancelled => bail!("interactive KeepKey CLI cancelled"),
        Stop::Exited => {}
        Stop::WaitFailed => unreachable!("wait error handled above"),
    }
    if !status
        .context("interactive KeepKey CLI exited without a status")?
        .success()
    {
        bail!("interactive KeepKey CLI failed")
    }
    Ok((stdout, prompt))
}

fn interactive_child(
    cli: Cli,
    args: Vec<String>,
    cancelled: Arc<AtomicBool>,
) -> Result<InteractiveOutput> {
    let runtime = runtime()?;
    let mut interaction = runtime.block_on(KeepKeyHostInteraction::connect_default(
        TEST_PIN,
        SYNTHETIC_MNEMONIC,
    ))?;
    let command = cli.command(args)?;
    let (bytes, (pin_kinds, recovery_requests)) = run_interactive_process(
        command,
        cancelled,
        COMMAND_TIMEOUT,
        move |stderr, mut stdin| {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            let mut pin_kinds = Vec::new();
            let mut recovery_requests = 0;
            loop {
                line.clear();
                if reader.read_line(&mut line)? == 0 {
                    return Ok((pin_kinds, recovery_requests));
                }
                let line = line.trim_end_matches(['\r', '\n']);
                let Some(request) = request_from_prompt(line)? else {
                    continue;
                };
                match &request {
                    bhwi::common::HostRequest::PinMatrix { kind } => pin_kinds.push(*kind),
                    bhwi::common::HostRequest::RecoveryCharacter { .. } => {
                        recovery_requests += 1;
                    }
                }
                let response = runtime
                    .block_on(interaction.response_line(&request))
                    .map_err(|_| anyhow!("failed to answer KeepKey host prompt"))?;
                stdin
                    .write_all(response.as_bytes())
                    .context("write KeepKey host response")?;
                stdin.flush().context("flush KeepKey host response")?;
            }
        },
    )?;
    Ok(InteractiveOutput {
        stdout: String::from_utf8(bytes).context("KeepKey CLI stdout is not UTF-8")?,
        pin_kinds,
        recovery_requests,
    })
}

fn run_interactive_approved<I, S>(cli: &Cli, args: I) -> Result<InteractiveOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let cli = cli.clone();
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect();
    with_decisions(DebugButton::Yes, move |cancelled| {
        interactive_child(cli, args, cancelled)
    })
}

fn expected_pin_stderr() -> String {
    format!("{SEND_PIN_INSTRUCTION}\n{PIN_MATRIX_DESCRIPTION}\n")
}

fn assert_success_output(output: Output, stderr: &str) -> Result<String> {
    assert!(output.status.success(), "KeepKey CLI command failed");
    assert_eq!(String::from_utf8(output.stderr)?, stderr);
    Ok(String::from_utf8(output.stdout)?)
}

fn debug_pin_positions() -> Result<String> {
    runtime()?.block_on(async {
        DebugLink::connect_default()
            .await?
            .pin_positions(TEST_PIN)
            .await
            .map_err(anyhow::Error::from)
    })
}

fn raw_lock() -> Result<()> {
    runtime()?.block_on(lock_device(DEFAULT_MAIN_ADDR))?;
    Ok(())
}

fn finish_pending_toggle(cli: &Cli) -> Result<()> {
    let output = run_output_approved(cli, ["device", "toggle-passphrase"])?;
    assert!(assert_success_output(output, &expected_pin_stderr())?.is_empty());
    let positions = debug_pin_positions()?;
    assert!(cli.run_ok(["device", "send-pin", &positions])?.is_empty());
    Ok(())
}

#[test]
#[ignore = "requires a fresh KeepKey emulator image"]
fn keepkey_management_lifecycle() -> Result<()> {
    use bhwi::common::PinMatrixRequestKind;

    let cli = cli();
    let setup = run_interactive_approved(&cli, ["device", "setup", "--label", "BHWI KeepKey CLI"])?;
    assert!(setup.stdout.is_empty());
    assert_eq!(
        setup.pin_kinds.as_slice(),
        &[
            PinMatrixRequestKind::NewFirst,
            PinMatrixRequestKind::NewSecond
        ]
    );
    let listed: serde_json::Value = serde_json::from_str(
        &cli.clone()
            .with_args(["--format", "json"])
            .run_ok(["device", "list"])?,
    )?;
    assert_eq!(listed[0]["label"], "BHWI KeepKey CLI");

    assert!(run_approved(&cli, ["device", "wipe"])?.is_empty());
    assert_eq!(
        cli.run_ok(["device", "list"])?,
        format!("{DEFAULT_MAIN_ADDR}\n")
    );
    let restore = run_interactive_approved(
        &cli,
        [
            "device",
            "restore",
            "--label",
            "BHWI KeepKey CLI Restored",
            "--word-count",
            "12",
        ],
    )?;
    assert!(restore.stdout.is_empty());
    assert_eq!(
        restore.pin_kinds.as_slice(),
        &[
            PinMatrixRequestKind::NewFirst,
            PinMatrixRequestKind::NewSecond
        ]
    );
    assert!(restore.recovery_requests >= 12);
    let listed: serde_json::Value = serde_json::from_str(
        &cli.clone()
            .with_args(["--format", "json"])
            .run_ok(["device", "list"])?,
    )?;
    assert_eq!(listed[0]["fingerprint"], FINGERPRINT);
    assert_eq!(listed[0]["label"], "BHWI KeepKey CLI Restored");

    raw_lock()?;
    let output = cli.run_output(["device", "prompt-pin"])?;
    assert!(assert_success_output(output, &expected_pin_stderr())?.is_empty());
    let positions = debug_pin_positions()?;
    assert!(cli.run_ok(["device", "send-pin", &positions])?.is_empty());
    assert_eq!(cli.run_ok(["device", "list"])?.trim(), FINGERPRINT);

    raw_lock()?;
    finish_pending_toggle(&cli)?;
    let empty = run_approved(&cli_with_passphrase(""), ["device", "list"])?;
    let first = run_approved(
        &cli_with_passphrase("fixture-passphrase-one"),
        ["device", "list"],
    )?;
    let second = run_approved(
        &cli_with_passphrase("fixture-passphrase-two"),
        ["device", "list"],
    )?;
    assert_eq!(empty.trim(), FINGERPRINT);
    assert_ne!(first.trim(), empty.trim());
    assert_ne!(second.trim(), empty.trim());
    assert_ne!(first.trim(), second.trim());
    let long_passphrase = "x".repeat(51);
    assert_failure(
        &cli_with_passphrase(&long_passphrase),
        ["device", "list"],
        "hwi device error: interpreter error: invalid input: Passphrase too long",
        &[long_passphrase.as_str()],
    )?;

    raw_lock()?;
    finish_pending_toggle(&cli)?;
    assert_eq!(
        cli_with_passphrase("ignored-when-disabled")
            .run_ok(["device", "list"])?
            .trim(),
        FINGERPRINT
    );

    raw_lock()?;
    let output = cli.run_output(["device", "prompt-pin"])?;
    assert!(assert_success_output(output, &expected_pin_stderr())?.is_empty());
    let rejected_pin = "1111";
    assert_failure(
        &cli,
        ["device", "send-pin", rejected_pin],
        "device rejected the PIN",
        &[rejected_pin],
    )?;

    raw_lock()?;
    let fresh_cli = self::cli();
    let output = fresh_cli.run_output(["device", "prompt-pin"])?;
    assert!(assert_success_output(output, &expected_pin_stderr())?.is_empty());
    let positions = debug_pin_positions()?;
    assert!(
        fresh_cli
            .run_ok(["device", "send-pin", &positions])?
            .is_empty()
    );
    let listed: serde_json::Value = serde_json::from_str(
        &fresh_cli
            .with_args(["--format", "json"])
            .run_ok(["device", "list"])?,
    )?;
    assert_eq!(listed[0]["fingerprint"], FINGERPRINT);
    let needs_pin_sent = listed[0].get("needs_pin_sent");
    assert!(needs_pin_sent.is_none() || needs_pin_sent == Some(&serde_json::Value::Bool(false)));
    Ok(())
}
