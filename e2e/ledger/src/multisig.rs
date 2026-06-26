//! Multi-key (multisig and miniscript) descriptor e2e tests against Speculos.
//!
//! These mirror the single-sig coverage in `lib.rs` but exercise wallet
//! policies with more than one key, across wsh (segwit v0) and tr (taproot).
//! Only the Ledger key is a real signer; co-signers are derived from fixed
//! seeds (the device never owns them), so signing yields exactly one
//! signature — the device's. This follows async-hwi's Speculos test approach.

use std::str::FromStr;

use bhwi::bitcoin::NetworkKind;
use bhwi::bitcoin::{
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    psbt::{Input, Psbt},
    secp256k1::{All, Secp256k1},
    transaction::Version as TxVersion,
};
use bhwi::ledger::{LedgerWalletPolicy, Version};
use bhwi_async::{DeviceContext, DisplayAddress, HWI};
use miniscript::descriptor::{
    DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, WalletPolicy,
};
use miniscript::psbt::{PsbtInputExt, PsbtOutputExt};

use crate::tests::{SpeculosDevice, SpeculosReqwestClient, init};

/// Account-level derivation path for BIP-48 native segwit / taproot multisig.
const MULTISIG_ACCOUNT_PATH: &str = "m/48'/1'/0'/2'";

/// BIP-341 NUMS point `H`, used as an unspendable taproot internal key so a
/// taproot multisig can only be spent through its script path.
const NUMS_POINT: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Value of the single input the test PSBTs spend (must equal the witness UTXO).
const INPUT_VALUE: Amount = Amount::from_sat(50_000);
/// Value sent to the change output (input minus fee).
const CHANGE_VALUE: Amount = Amount::from_sat(49_000);

/// Loads a Speculos automation ruleset from its JSON.
async fn load_automation(client: &SpeculosReqwestClient, json: &str) {
    let rules: serde_json::Value = serde_json::from_str(json).expect("valid automation json");
    client.set_automation(&rules).await.unwrap();
}

/// A descriptor key: enough to render its descriptor fragment and (for the
/// device) recompute its derived public key for signature assertions.
struct Key {
    fingerprint: Fingerprint,
    account_path: DerivationPath,
    xpub: Xpub,
}

impl Key {
    /// The Speculos device key, read live from the emulator.
    async fn device(dev: &mut SpeculosDevice, path: &str) -> Key {
        let account_path = DerivationPath::from_str(path).unwrap();
        Key {
            fingerprint: dev.get_master_fingerprint().await.unwrap(),
            xpub: dev
                .get_extended_pubkey(account_path.clone(), false)
                .await
                .unwrap(),
            account_path,
        }
    }

    /// A co-signer key derived from a fixed seed; the device never owns it.
    fn cosigner(secp: &Secp256k1<All>, seed: u8, path: &str) -> Key {
        let master = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap();
        let account_path = DerivationPath::from_str(path).unwrap();
        let xpriv = master.derive_priv(secp, &account_path).unwrap();
        Key {
            fingerprint: master.fingerprint(secp),
            xpub: Xpub::from_priv(secp, &xpriv),
            account_path,
        }
    }

    /// An unspendable taproot internal key built from the NUMS point. It has an
    /// origin fingerprint but no derivation path, matching how liana renders it.
    fn unspendable() -> Key {
        let nums = PublicKey::from_str(NUMS_POINT).unwrap();
        Key {
            fingerprint: Fingerprint::from([0u8; 4]),
            account_path: DerivationPath::master(),
            xpub: Xpub {
                network: NetworkKind::Test,
                depth: 0,
                parent_fingerprint: Fingerprint::from([0u8; 4]),
                child_number: ChildNumber::from_normal_idx(0).unwrap(),
                public_key: nums.inner,
                chain_code: ChainCode::from([0u8; 32]),
            },
        }
    }

    /// Descriptor key expression with key-origin and `/<0;1>/*` multipath.
    fn descriptor_key(&self) -> String {
        // rust-bitcoin's `DerivationPath` Display omits the leading `m`; the
        // master path renders empty. Render the origin without it either way.
        let path = self.account_path.to_string();
        let origin = path.trim_start_matches('m').trim_start_matches('/');
        if origin.is_empty() {
            format!("[{}]{}/<0;1>/*", self.fingerprint, self.xpub)
        } else {
            format!("[{}/{}]{}/<0;1>/*", self.fingerprint, origin, self.xpub)
        }
    }

    /// Receive-branch public key at index 0, used to assert the device signed.
    fn receive_pubkey(&self, secp: &Secp256k1<All>) -> PublicKey {
        let child = self
            .xpub
            .derive_pub(
                secp,
                &[
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(0).unwrap(),
                ],
            )
            .unwrap();
        PublicKey::new(child.public_key)
    }
}

/// Registers `policy` on the device, asserts a 32-byte HMAC is returned, and
/// returns the Ledger signing context for the registered wallet.
async fn register(
    dev: &mut SpeculosDevice,
    client: &SpeculosReqwestClient,
    name: &str,
    policy: &str,
) -> DeviceContext {
    load_automation(
        client,
        include_str!("../automations/register_wallet_accept.json"),
    )
    .await;
    let hmac = dev.register_wallet(name, policy).await.unwrap();
    assert_eq!(hmac.len(), 32);
    DeviceContext::Ledger {
        wallet_policy: LedgerWalletPolicy::new(
            name.to_string(),
            Version::V2,
            WalletPolicy::from_str(policy).unwrap(),
        ),
        wallet_hmac: Some(hmac),
    }
}

/// Splits a multipath descriptor into definite receive (branch 0) and change
/// (branch 1) descriptors at index 0.
fn definite_branches(
    descriptor: &str,
) -> (
    Descriptor<DefiniteDescriptorKey>,
    Descriptor<DefiniteDescriptorKey>,
) {
    let desc = Descriptor::<DescriptorPublicKey>::from_str(descriptor).unwrap();
    let mut branches = desc.into_single_descriptors().unwrap().into_iter();
    let receive = branches.next().expect("receive branch");
    let change = branches.next().expect("change branch");
    (
        receive.derive_at_index(0).unwrap(),
        change.derive_at_index(0).unwrap(),
    )
}

/// Builds a single-input PSBT spending a receive output back to a change output.
/// `update_with_descriptor_unchecked` fills the witness / taproot fields and
/// per-key BIP-32 derivations so the device can recognize and sign its key.
fn build_psbt(
    secp: &Secp256k1<All>,
    receive: &Descriptor<DefiniteDescriptorKey>,
    change: &Descriptor<DefiniteDescriptorKey>,
) -> Psbt {
    let input_script = receive.derived_descriptor(secp).script_pubkey();
    let change_script = change.derived_descriptor(secp).script_pubkey();

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
            value: INPUT_VALUE,
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
            value: CHANGE_VALUE,
            script_pubkey: change_script,
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: INPUT_VALUE,
        script_pubkey: input_script,
    });
    psbt.inputs[0].non_witness_utxo = Some(prev_tx);
    psbt.inputs[0]
        .update_with_descriptor_unchecked(receive)
        .unwrap();
    psbt.outputs[0]
        .update_with_descriptor_unchecked(change)
        .unwrap();
    psbt
}

/// Asserts the signed input carries exactly one signature and it is the
/// device's (ecdsa `partial_sigs` for wsh, schnorr `tap_script_sigs` for the
/// taproot script path).
fn assert_device_signed_once(input: &Input, device: PublicKey) {
    let total = input.partial_sigs.len()
        + input.tap_script_sigs.len()
        + usize::from(input.tap_key_sig.is_some());
    assert_eq!(total, 1, "expected exactly one signature");

    let device_xonly = device.inner.x_only_public_key().0;
    let signed = input.partial_sigs.contains_key(&device)
        || input
            .tap_script_sigs
            .keys()
            .any(|(xonly, _)| *xonly == device_xonly);
    assert!(signed, "device key signature missing");
}

/// Reads the device key, builds the descriptor via `build`, then runs the full
/// register + display-address + sign flow over a single device connection.
/// `build` receives the secp context and the device key (always `keys[0]`).
async fn run_flow(name: &str, build: impl FnOnce(&Secp256k1<All>, &Key) -> String) {
    let secp = Secp256k1::new();
    let (mut dev, client) = init().await;
    let device = Key::device(&mut dev, MULTISIG_ACCOUNT_PATH).await;
    let descriptor = build(&secp, &device);

    let ctx = register(&mut dev, &client, name, &descriptor).await;
    let (receive, change) = definite_branches(&descriptor);

    // Display address by registered descriptor must match the locally derived
    // receive address at index 0.
    let expected_address = receive
        .derived_descriptor(&secp)
        .address(Network::Testnet)
        .unwrap()
        .to_string();
    load_automation(
        &client,
        include_str!("../automations/register_wallet_accept.json"),
    )
    .await;
    let address = dev
        .display_address(
            DisplayAddress::ByDescriptor {
                index: 0,
                change: false,
                display: true,
                descriptor_name: name.to_string(),
            },
            Some(ctx.clone()),
        )
        .await
        .expect("display multisig address");
    assert_eq!(address, expected_address);

    let psbt = build_psbt(&secp, &receive, &change);
    load_automation(&client, include_str!("../automations/sign_psbt.json")).await;
    let signed = dev
        .sign_tx(psbt, Some(ctx))
        .await
        .expect("sign multisig psbt");
    assert_eq!(signed.inputs.len(), 1);
    assert_device_signed_once(&signed.inputs[0], device.receive_pubkey(&secp));
}

#[tokio::test]
async fn wsh_sortedmulti_2of2() {
    run_flow("multi2of2", |secp, device| {
        let cosigner = Key::cosigner(secp, 0xa5, MULTISIG_ACCOUNT_PATH);
        format!(
            "wsh(sortedmulti(2,{},{}))",
            device.descriptor_key(),
            cosigner.descriptor_key()
        )
    })
    .await;
}

#[tokio::test]
async fn wsh_sortedmulti_2of3() {
    run_flow("multi2of3", |secp, device| {
        let cosigner_a = Key::cosigner(secp, 0xa5, MULTISIG_ACCOUNT_PATH);
        let cosigner_b = Key::cosigner(secp, 0x5a, "m/48'/1'/1'/2'");
        format!(
            "wsh(sortedmulti(2,{},{},{}))",
            device.descriptor_key(),
            cosigner_a.descriptor_key(),
            cosigner_b.descriptor_key()
        )
    })
    .await;
}

#[tokio::test]
async fn wsh_recovery_miniscript() {
    // Liana-style inheritance: device key spends immediately; recovery key
    // spends after a relative timelock. The device owns the always-available
    // primary path, so no timelock is required to produce its signature.
    run_flow("recovery", |secp, device| {
        let recovery = Key::cosigner(secp, 0xc3, MULTISIG_ACCOUNT_PATH);
        format!(
            "wsh(or_d(pk({}),and_v(v:pkh({}),older(10))))",
            device.descriptor_key(),
            recovery.descriptor_key()
        )
    })
    .await;
}

#[tokio::test]
async fn tr_multi_a_2of2() {
    // Taproot 2-of-2 multisig with an unspendable NUMS internal key, so the
    // only spend path is the `multi_a` tapscript. The device signs that leaf,
    // producing a single taproot script signature.
    run_flow("trmulti2of2", |secp, device| {
        let cosigner = Key::cosigner(secp, 0x7e, MULTISIG_ACCOUNT_PATH);
        format!(
            "tr({},multi_a(2,{},{}))",
            Key::unspendable().descriptor_key(),
            device.descriptor_key(),
            cosigner.descriptor_key()
        )
    })
    .await;
}
