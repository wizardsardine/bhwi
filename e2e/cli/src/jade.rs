use anyhow::Result;
use bitcoin::{
    Address, Network, PublicKey,
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    blockdata::{opcodes, script::Builder},
    secp256k1::Secp256k1,
};
use std::str::FromStr;

use crate::support::{Cli, CommandCase, ExpectedOutput, assert_command};

const JADE_FINGERPRINT: &str = "e3ebcc79";
const JADE_ADDRESS_84_0: &str = "tb1q9t9pgtdsyf6r8ks7gnxvj99sea4d3nmjl0tnzu";
const JADE_ADDRESS_49_0: &str = "2MsFo9x4kZMVumePtLZvjh9Hn9A98bS3MF6";
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
fn jade_address_get_by_path() -> Result<()> {
    assert_command(CommandCase {
        name: "address get m/84'/1'/0'/0/0",
        cli: Cli::for_device(JADE_FINGERPRINT),
        args: &["address", "get", "--from-path", "m/84'/1'/0'/0/0"],
        expected: ExpectedOutput::Exact(JADE_ADDRESS_84_0),
    })
}

#[test]
fn jade_nested_segwit_address_get_by_path() -> Result<()> {
    assert_command(CommandCase {
        name: "address get m/49'/1'/0'/0/0",
        cli: Cli::for_device(JADE_FINGERPRINT),
        args: &[
            "address",
            "get",
            "--from-path",
            "m/49'/1'/0'/0/0",
            "--address-format",
            "p2sh",
        ],
        expected: ExpectedOutput::Exact(JADE_ADDRESS_49_0),
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
fn jade_keypool_get() -> Result<()> {
    assert_command(CommandCase {
        name: "descriptor keypool m/84'/1'/0' 0-4",
        cli: Cli::for_device(JADE_FINGERPRINT),
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
            fingerprint: JADE_FINGERPRINT,
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
fn jade_register_wallet_and_descriptor_address() -> Result<()> {
    let cli = Cli::for_device(JADE_FINGERPRINT);
    let account_path: DerivationPath = "m/48'/1'/0'/2'".parse()?;
    let device_xpub = Xpub::from_str(cli.run_ok(["xpub", "get", "m/48'/1'/0'/2'"])?.trim())?;
    let secp = Secp256k1::new();
    let cosigner_master = Xpriv::new_master(Network::Testnet, &[7u8; 32])?;
    let cosigner_fingerprint = cosigner_master.fingerprint(&secp);
    let cosigner_xpriv = cosigner_master.derive_priv(&secp, &account_path)?;
    let cosigner_xpub = Xpub::from_priv(&secp, &cosigner_xpriv);
    let descriptor = format!(
        "wsh(sortedmulti(2,[{JADE_FINGERPRINT}/{account_path}]{device_xpub}/<0;1>/*,[{cosigner_fingerprint}/{account_path}]{cosigner_xpub}/<0;1>/*))"
    );

    let output = cli.run_ok([
        "register-wallet",
        "--name",
        "jade-cli",
        "--descriptor",
        &descriptor,
    ])?;
    assert!(output.is_empty());

    let address = cli.run_ok(["address", "get", "--from-descriptor", "jade-cli"])?;
    assert_eq!(
        address.trim(),
        multisig_address(&secp, device_xpub, cosigner_xpub)
    );
    Ok(())
}

fn multisig_address(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    first: Xpub,
    second: Xpub,
) -> String {
    let path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(0).unwrap(),
    ]);
    let mut keys = [
        first.derive_pub(secp, &path).unwrap().public_key,
        second.derive_pub(secp, &path).unwrap().public_key,
    ];
    keys.sort_by_key(|key| key.serialize());
    let script = Builder::new()
        .push_int(2)
        .push_key(&PublicKey::new(keys[0]))
        .push_key(&PublicKey::new(keys[1]))
        .push_int(2)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    Address::p2wsh(&script, Network::Testnet).to_string()
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
