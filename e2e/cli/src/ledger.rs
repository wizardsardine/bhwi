use std::{
    env, fs,
    path::PathBuf,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use bitcoin::{
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    address::Address,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    psbt::{Input, Output as PsbtOutput, Psbt},
    secp256k1::Secp256k1,
    transaction::Version as TxVersion,
};

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

const LEDGER_FINGERPRINT: &str = "f5acc2fd";
const LEDGER_XPUB_44: &str = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";
const LEDGER_ADDRESS_84_0: &str = "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk";
const LEDGER_SIGN_MESSAGE_HELLO: &str =
    "IL3u9GLAzgG5BdtSBqUe0Fo2Zx0UlKwSsYx2TbuVX0VULFgZYRBQCW0W7QOlsB/JgGwWNhl3eYYjXtdfyR7pM+Y=";

#[test]
fn ledger_device_list() -> Result<()> {
    assert_command(CommandCase {
        name: "device list",
        cli: Cli::global(),
        args: &["device", "list"],
        expected: ExpectedOutput::Exact(LEDGER_FINGERPRINT),
    })
}

#[test]
fn ledger_xpub_get() -> Result<()> {
    assert_command(CommandCase {
        name: "xpub get m/44'/1'/0'",
        cli: Cli::for_device(LEDGER_FINGERPRINT),
        args: &["xpub", "get", "m/44'/1'/0'"],
        expected: ExpectedOutput::Exact(LEDGER_XPUB_44),
    })
}

#[test]
fn ledger_descriptor_pubkeys() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor pubkeys account 0",
        cli: Cli::for_device(LEDGER_FINGERPRINT),
        args: &["descriptor", "pubkeys", "--account", "0"],
        expected: ExpectedOutput::DescriptorPubkeys {
            fingerprint: LEDGER_FINGERPRINT,
            account: 0,
        },
    })
}

#[test]
fn ledger_keypool_get() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor keypool m/84'/1'/0' 0-4",
        cli: Cli::for_device(LEDGER_FINGERPRINT),
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
            fingerprint: LEDGER_FINGERPRINT,
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
fn ledger_address_by_path() -> Result<()> {
    assert_command(CommandCase {
        name: "address get from path",
        cli: Cli::for_device(LEDGER_FINGERPRINT),
        args: &["address", "get", "--from-path", "m/84'/1'/0'/0/0"],
        expected: ExpectedOutput::Exact(LEDGER_ADDRESS_84_0),
    })
}

#[test]
fn ledger_sign_message() -> Result<()> {
    set_ledger_automation(&automation(include_str!(
        "../../ledger/automations/sign_message.json"
    )))?;
    assert_command(CommandCase {
        name: "sign message hello",
        cli: Cli::for_device(LEDGER_FINGERPRINT),
        args: &[
            "sign-message",
            "--message",
            "hello",
            "--path",
            "m/44'/1'/0'/0",
        ],
        expected: ExpectedOutput::Exact(LEDGER_SIGN_MESSAGE_HELLO),
    })
}

#[test]
fn ledger_register_wallet_and_descriptor_address() -> Result<()> {
    let policy = wallet_policy()?;
    set_ledger_automation(&automation(include_str!(
        "../../ledger/automations/register_wallet_accept.json"
    )))?;
    let hmac = Cli::for_device(LEDGER_FINGERPRINT).run_ok([
        "register-wallet",
        "--name",
        "clitestwallet",
        "--descriptor",
        &policy,
    ])?;
    let hmac = hmac.trim();
    assert_eq!(hmac.len(), 64);
    hex::decode(hmac)?;

    assert_command(CommandCase {
        name: "address get from registered descriptor",
        cli: Cli::for_device(LEDGER_FINGERPRINT),
        args: &[
            "address",
            "get",
            "--from-descriptor",
            "clitestwallet",
            "--wallet-descriptor",
            &policy,
            "--hmac",
            hmac,
        ],
        expected: ExpectedOutput::Exact(LEDGER_ADDRESS_84_0),
    })
}

#[test]
fn ledger_sign_psbt() -> Result<()> {
    let policy = wallet_policy()?;
    set_ledger_automation(&automation(include_str!(
        "../../ledger/automations/register_wallet_accept.json"
    )))?;
    let hmac = Cli::for_device(LEDGER_FINGERPRINT).run_ok([
        "register-wallet",
        "--name",
        "clipsbttest",
        "--descriptor",
        &policy,
    ])?;
    let hmac = hmac.trim().to_string();
    let psbt = ledger_psbt()?;
    let psbt_file = temp_file("ledger-sign-psbt", psbt.to_string())?;

    set_ledger_automation(&automation(include_str!(
        "../../ledger/automations/sign_psbt.json"
    )))?;
    let signed = Cli::for_device(LEDGER_FINGERPRINT).run_ok([
        "sign-psbt",
        "--psbt",
        psbt_file.to_str().context("utf-8 temp path")?,
        "--name",
        "clipsbttest",
        "--descriptor",
        &policy,
        "--hmac",
        &hmac,
    ])?;
    fs::remove_file(psbt_file)?;

    let signed = Psbt::from_str(signed.trim())?;
    assert_eq!(signed.inputs.len(), 1);
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
    Ok(())
}

fn wallet_policy() -> Result<String> {
    let xpub = Cli::for_device(LEDGER_FINGERPRINT).run_ok(["xpub", "get", "m/84'/1'/0'"])?;
    Ok(format!(
        "wpkh([{LEDGER_FINGERPRINT}/84'/1'/0']{}/<0;1>/*)",
        xpub.trim()
    ))
}

fn set_ledger_automation(automation: &serde_json::Value) -> Result<()> {
    reqwest::blocking::Client::new()
        .post("http://localhost:5000/automation")
        .json(automation)
        .send()?
        .error_for_status()?;
    Ok(())
}

fn automation(json: &str) -> serde_json::Value {
    serde_json::from_str(json).expect("valid automation json")
}

fn temp_file(name: &str, contents: impl AsRef<[u8]>) -> Result<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let path = env::temp_dir().join(format!("bhwi-e2e-cli-{name}-{unique}"));
    fs::write(&path, contents)?;
    Ok(path)
}

fn ledger_psbt() -> Result<Psbt> {
    let fingerprint = Fingerprint::from_str(LEDGER_FINGERPRINT)?;
    let xpub = Xpub::from_str(
        Cli::for_device(LEDGER_FINGERPRINT)
            .run_ok(["xpub", "get", "m/84'/1'/0'"])?
            .trim(),
    )?;
    let secp = Secp256k1::verification_only();
    let input_path: DerivationPath = "m/84'/1'/0'/0/0".parse()?;
    let change_path: DerivationPath = "m/84'/1'/0'/1/0".parse()?;
    let input_child_path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(0)?,
        ChildNumber::from_normal_idx(0)?,
    ]);
    let change_child_path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(1)?,
        ChildNumber::from_normal_idx(0)?,
    ]);
    let input_xpub = xpub.derive_pub(&secp, &input_child_path)?;
    let change_xpub = xpub.derive_pub(&secp, &change_child_path)?;
    let input_pubkey = PublicKey::new(input_xpub.public_key);
    let change_pubkey = PublicKey::new(change_xpub.public_key);
    let input_script = Address::p2wpkh(&input_xpub.to_pub(), Network::Testnet).script_pubkey();
    let change_script = Address::p2wpkh(&change_xpub.to_pub(), Network::Testnet).script_pubkey();
    let prev_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: input_script.clone(),
        }],
    };
    let unsigned_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: change_script,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    psbt.inputs[0] = Input {
        non_witness_utxo: Some(prev_tx),
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: input_script,
        }),
        bip32_derivation: [(input_pubkey.inner, (fingerprint, input_path))].into(),
        ..Default::default()
    };
    psbt.outputs[0] = PsbtOutput {
        bip32_derivation: [(change_pubkey.inner, (fingerprint, change_path))].into(),
        ..Default::default()
    };
    Ok(psbt)
}
