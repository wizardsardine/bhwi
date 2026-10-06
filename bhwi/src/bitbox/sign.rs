//! Bitcoin transaction sign types + PSBT lowering.
//!
//! Ported from bitbox-api-rs (`src/btc.rs`, lines 78-575),
//! Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
//! Version 2.0 — see BITBOX_LICENSE at the repository root.
//!
//! Represents a bitcoin transaction in the shape the BitBox02 firmware expects,
//! computed once from the input `Psbt` and then driven through the multi-round
//! `BtcSign*` state machine on the device.

use std::collections::BTreeMap;

use bitcoin::{
    Script,
    bip32::DerivationPath,
    blockdata::{opcodes, script::Instruction},
};

use super::api::make_script_config_simple;
use super::error::BitBoxError;
use super::proto as pb;

/// The leading run of hardened elements of a derivation path (the account-level prefix).
fn hardened_prefix(path: &DerivationPath) -> DerivationPath {
    path.into_iter()
        .take_while(|c| c.is_hardened())
        .cloned()
        .collect()
}

/// An input of a previous transaction requested during signing.
#[derive(Clone, Debug, PartialEq)]
pub struct PrevTxInput {
    /// Previous transaction identifier in Bitcoin's internal byte order.
    pub prev_out_hash: Vec<u8>,
    /// Output index within the previous transaction.
    pub prev_out_index: u32,
    /// Raw input script bytes.
    pub signature_script: Vec<u8>,
    /// Consensus-encoded sequence number.
    pub sequence: u32,
}

impl From<&bitcoin::TxIn> for PrevTxInput {
    fn from(value: &bitcoin::TxIn) -> Self {
        PrevTxInput {
            prev_out_hash: (value.previous_output.txid.as_ref() as &[u8]).to_vec(),
            prev_out_index: value.previous_output.vout,
            signature_script: value.script_sig.as_bytes().to_vec(),
            sequence: value.sequence.to_consensus_u32(),
        }
    }
}

/// An output of a previous transaction requested during signing.
#[derive(Clone, Debug, PartialEq)]
pub struct PrevTxOutput {
    /// Output value in satoshis.
    pub value: u64,
    /// Raw output script bytes.
    pub pubkey_script: Vec<u8>,
}

impl From<&bitcoin::TxOut> for PrevTxOutput {
    fn from(value: &bitcoin::TxOut) -> Self {
        PrevTxOutput {
            value: value.value.to_sat(),
            pubkey_script: value.script_pubkey.as_bytes().to_vec(),
        }
    }
}

/// A previous transaction in the format used by the BitBox02 signing protocol.
#[derive(Clone, Debug, PartialEq)]
pub struct PrevTx {
    /// Consensus transaction version represented as an unsigned integer.
    pub version: u32,
    /// Previous transaction inputs.
    pub inputs: Vec<PrevTxInput>,
    /// Previous transaction outputs.
    pub outputs: Vec<PrevTxOutput>,
    /// Consensus-encoded absolute lock time.
    pub locktime: u32,
}

impl From<&bitcoin::Transaction> for PrevTx {
    fn from(value: &bitcoin::Transaction) -> Self {
        PrevTx {
            version: value.version.0 as _,
            inputs: value.input.iter().map(PrevTxInput::from).collect(),
            outputs: value.output.iter().map(PrevTxOutput::from).collect(),
            locktime: value.lock_time.to_consensus_u32(),
        }
    }
}

/// A transaction input and its device signing key.
#[derive(Debug, PartialEq)]
pub struct TxInput {
    /// Spent transaction identifier in Bitcoin's internal byte order.
    pub prev_out_hash: Vec<u8>,
    /// Index of the spent output.
    pub prev_out_index: u32,
    /// Value of the spent output in satoshis.
    pub prev_out_value: u64,
    /// Consensus-encoded sequence number.
    pub sequence: u32,
    /// Derivation path of the signing key.
    pub keypath: DerivationPath,
    /// Index into [`Transaction::script_configs`].
    pub script_config_index: u32,
    /// Can be `None` if all transaction inputs are Taproot.
    pub prev_tx: Option<PrevTx>,
}

impl TxInput {
    pub(crate) fn get_prev_tx(&self) -> Result<&PrevTx, BitBoxError> {
        self.prev_tx.as_ref().ok_or(BitBoxError::BtcSign(
            "input's previous transaction required but missing".into(),
        ))
    }
}

/// An output identified as belonging to the device's wallet.
#[derive(Debug, PartialEq)]
pub struct TxInternalOutput {
    /// Derivation path of the output key.
    pub keypath: DerivationPath,
    /// Output value in satoshis.
    pub value: u64,
    /// Index into [`Transaction::script_configs`].
    pub script_config_index: u32,
}

/// A recognized output script's hash, witness program, or OP_RETURN data.
#[derive(Debug, PartialEq)]
pub struct Payload {
    /// Script payload bytes without the script's framing opcodes.
    pub data: Vec<u8>,
    /// Device output type describing the payload.
    pub output_type: pb::BtcOutputType,
}

impl Payload {
    /// Extracts a payload from a supported output script.
    ///
    /// Supports P2PKH, P2SH, P2WPKH, P2WSH, P2TR, and OP_RETURN with exactly
    /// one minimal data push. Other scripts return a signing error.
    pub fn from_pkscript(pkscript: &[u8]) -> Result<Payload, BitBoxError> {
        let script = Script::from_bytes(pkscript);
        if script.is_p2pkh() {
            Ok(Payload {
                data: pkscript[3..23].to_vec(),
                output_type: pb::BtcOutputType::P2pkh,
            })
        } else if script.is_p2sh() {
            Ok(Payload {
                data: pkscript[2..22].to_vec(),
                output_type: pb::BtcOutputType::P2sh,
            })
        } else if script.is_p2wpkh() {
            Ok(Payload {
                data: pkscript[2..].to_vec(),
                output_type: pb::BtcOutputType::P2wpkh,
            })
        } else if script.is_p2wsh() {
            Ok(Payload {
                data: pkscript[2..].to_vec(),
                output_type: pb::BtcOutputType::P2wsh,
            })
        } else if script.is_p2tr() {
            Ok(Payload {
                data: pkscript[2..].to_vec(),
                output_type: pb::BtcOutputType::P2tr,
            })
        } else if matches!(script.as_bytes().first(), Some(&byte) if byte == opcodes::all::OP_RETURN.to_u8())
        {
            let mut instructions = script.instructions_minimal();
            match instructions.next() {
                Some(Ok(Instruction::Op(op))) if op == opcodes::all::OP_RETURN => {}
                _ => return Err(BitBoxError::BtcSign("unrecognized OP_RETURN".into())),
            }

            let payload = match instructions.next() {
                None => {
                    return Err(BitBoxError::BtcSign(
                        "naked OP_RETURN is not supported".into(),
                    ));
                }
                Some(Ok(Instruction::Op(op))) if op == opcodes::all::OP_PUSHBYTES_0 => Vec::new(),
                Some(Ok(Instruction::PushBytes(push))) => push.as_bytes().to_vec(),
                Some(Ok(_)) => {
                    return Err(BitBoxError::BtcSign(
                        "no data push found after OP_RETURN".into(),
                    ));
                }
                Some(Err(_)) => {
                    return Err(BitBoxError::BtcSign(
                        "failed to parse OP_RETURN payload".into(),
                    ));
                }
            };

            match instructions.next() {
                None => Ok(Payload {
                    data: payload,
                    output_type: pb::BtcOutputType::OpReturn,
                }),
                Some(Ok(_)) => Err(BitBoxError::BtcSign(
                    "only one data push supported after OP_RETURN".into(),
                )),
                Some(Err(_)) => Err(BitBoxError::BtcSign(
                    "failed to parse OP_RETURN payload".into(),
                )),
            }
        } else {
            Err(BitBoxError::BtcSign("unrecognized pubkey script".into()))
        }
    }
}

/// An output not identified as belonging to the device's wallet.
#[derive(Debug, PartialEq)]
pub struct TxExternalOutput {
    /// Recognized script payload.
    pub payload: Payload,
    /// Output value in satoshis.
    pub value: u64,
}

impl TryFrom<&bitcoin::TxOut> for TxExternalOutput {
    type Error = BitBoxError;
    fn try_from(value: &bitcoin::TxOut) -> Result<Self, Self::Error> {
        Ok(TxExternalOutput {
            payload: Payload::from_pkscript(value.script_pubkey.as_bytes())?,
            value: value.value.to_sat(),
        })
    }
}

/// A transaction output classified for device signing.
#[derive(Debug, PartialEq)]
pub enum TxOutput {
    /// An output belonging to the device wallet.
    Internal(
        /// Wallet-owned output details.
        TxInternalOutput,
    ),
    /// An output to an external recipient or OP_RETURN.
    External(
        /// External output details.
        TxExternalOutput,
    ),
}

/// A Bitcoin transaction prepared for the BitBox02 signing protocol.
#[derive(Debug, PartialEq)]
pub struct Transaction {
    /// Script configurations referenced by inputs and internal outputs.
    pub script_configs: Vec<pb::BtcScriptConfigWithKeypath>,
    /// Consensus transaction version represented as an unsigned integer.
    pub version: u32,
    /// Inputs to sign.
    pub inputs: Vec<TxInput>,
    /// Outputs classified by ownership.
    pub outputs: Vec<TxOutput>,
    /// Consensus-encoded absolute lock time.
    pub locktime: u32,
}

/// Per-input key info recorded during PSBT lowering. Used at the end of the sign flow
/// to insert the returned signature back into the PSBT under the correct key.
#[derive(Clone, Debug)]
pub enum OurKey {
    /// A SegWit public key and its derivation path.
    Segwit(
        /// Signing public key.
        bitcoin::secp256k1::PublicKey,
        /// Signing key derivation path.
        DerivationPath,
    ),
    /// A Taproot internal key's derivation path.
    TaprootInternal(
        /// Internal key derivation path.
        DerivationPath,
    ),
    /// A Taproot script public key, leaf hash, and derivation path.
    TaprootScript(
        /// Signing x-only public key.
        bitcoin::secp256k1::XOnlyPublicKey,
        /// Leaf whose script is signed.
        bitcoin::taproot::TapLeafHash,
        /// Signing key derivation path.
        DerivationPath,
    ),
}

impl OurKey {
    pub(crate) fn keypath(&self) -> DerivationPath {
        match self {
            OurKey::Segwit(_, kp) => kp.clone(),
            OurKey::TaprootInternal(kp) => kp.clone(),
            OurKey::TaprootScript(_, _, kp) => kp.clone(),
        }
    }
}

trait PsbtOutputInfo {
    fn get_bip32_derivation(
        &self,
    ) -> &BTreeMap<bitcoin::secp256k1::PublicKey, bitcoin::bip32::KeySource>;
    fn get_tap_internal_key(&self) -> Option<&bitcoin::secp256k1::XOnlyPublicKey>;
    fn get_tap_key_origins(
        &self,
    ) -> &BTreeMap<
        bitcoin::secp256k1::XOnlyPublicKey,
        (
            Vec<bitcoin::taproot::TapLeafHash>,
            bitcoin::bip32::KeySource,
        ),
    >;
}

impl PsbtOutputInfo for &bitcoin::psbt::Input {
    fn get_bip32_derivation(
        &self,
    ) -> &BTreeMap<bitcoin::secp256k1::PublicKey, bitcoin::bip32::KeySource> {
        &self.bip32_derivation
    }
    fn get_tap_internal_key(&self) -> Option<&bitcoin::secp256k1::XOnlyPublicKey> {
        self.tap_internal_key.as_ref()
    }
    fn get_tap_key_origins(
        &self,
    ) -> &BTreeMap<
        bitcoin::secp256k1::XOnlyPublicKey,
        (
            Vec<bitcoin::taproot::TapLeafHash>,
            bitcoin::bip32::KeySource,
        ),
    > {
        &self.tap_key_origins
    }
}

impl PsbtOutputInfo for &bitcoin::psbt::Output {
    fn get_bip32_derivation(
        &self,
    ) -> &BTreeMap<bitcoin::secp256k1::PublicKey, bitcoin::bip32::KeySource> {
        &self.bip32_derivation
    }
    fn get_tap_internal_key(&self) -> Option<&bitcoin::secp256k1::XOnlyPublicKey> {
        self.tap_internal_key.as_ref()
    }
    fn get_tap_key_origins(
        &self,
    ) -> &BTreeMap<
        bitcoin::secp256k1::XOnlyPublicKey,
        (
            Vec<bitcoin::taproot::TapLeafHash>,
            bitcoin::bip32::KeySource,
        ),
    > {
        &self.tap_key_origins
    }
}

fn find_our_key<T: PsbtOutputInfo>(
    our_root_fingerprint: &[u8],
    output_info: T,
) -> Result<OurKey, BitBoxError> {
    for (xonly, (leaf_hashes, (fingerprint, derivation_path))) in
        output_info.get_tap_key_origins().iter()
    {
        if &fingerprint[..] == our_root_fingerprint {
            if let Some(tap_internal_key) = output_info.get_tap_internal_key()
                && tap_internal_key == xonly
            {
                if !leaf_hashes.is_empty() {
                    return Err(BitBoxError::BtcSign(
                        "taproot key reused as internal and in leaf script".into(),
                    ));
                }
                return Ok(OurKey::TaprootInternal(derivation_path.clone()));
            }
            if leaf_hashes.len() != 1 {
                return Err(BitBoxError::BtcSign(
                    "taproot key must appear in exactly one leaf hash".into(),
                ));
            }
            return Ok(OurKey::TaprootScript(
                *xonly,
                leaf_hashes[0],
                derivation_path.clone(),
            ));
        }
    }
    for (pubkey, (fingerprint, derivation_path)) in output_info.get_bip32_derivation().iter() {
        if &fingerprint[..] == our_root_fingerprint {
            return Ok(OurKey::Segwit(*pubkey, derivation_path.clone()));
        }
    }
    Err(BitBoxError::BtcSign(
        "could not find our key in an input".into(),
    ))
}

fn script_config_from_utxo(
    output: &bitcoin::TxOut,
    keypath: DerivationPath,
    redeem_script: Option<&bitcoin::ScriptBuf>,
) -> Result<pb::BtcScriptConfigWithKeypath, BitBoxError> {
    let keypath = hardened_prefix(&keypath);
    if output.script_pubkey.is_p2wpkh() {
        return Ok(pb::BtcScriptConfigWithKeypath {
            script_config: Some(make_script_config_simple(
                pb::btc_script_config::SimpleType::P2wpkh,
            )),
            keypath: keypath.to_u32_vec(),
        });
    }
    let redeem_is_p2wpkh = redeem_script.map(|s| s.is_p2wpkh()).unwrap_or(false);
    if output.script_pubkey.is_p2sh() && redeem_is_p2wpkh {
        return Ok(pb::BtcScriptConfigWithKeypath {
            script_config: Some(make_script_config_simple(
                pb::btc_script_config::SimpleType::P2wpkhP2sh,
            )),
            keypath: keypath.to_u32_vec(),
        });
    }
    if output.script_pubkey.is_p2tr() {
        return Ok(pb::BtcScriptConfigWithKeypath {
            script_config: Some(make_script_config_simple(
                pb::btc_script_config::SimpleType::P2tr,
            )),
            keypath: keypath.to_u32_vec(),
        });
    }
    Err(BitBoxError::BtcSign(
        "unrecognized/unsupported output type; multisig/policy must be forced".into(),
    ))
}

impl Transaction {
    /// Lowers a PSBT into a device transaction and aligned per-input signing keys.
    ///
    /// Every input must have a key origin matching `our_root_fingerprint` and
    /// usable UTXO data. Without a forced configuration, only supported
    /// single-key scripts are inferred; policy signing supplies its configuration.
    pub fn from_psbt(
        our_root_fingerprint: &[u8],
        psbt: &bitcoin::psbt::Psbt,
        force_script_config: Option<pb::BtcScriptConfigWithKeypath>,
    ) -> Result<(Self, Vec<OurKey>), BitBoxError> {
        let mut script_configs: Vec<pb::BtcScriptConfigWithKeypath> = Vec::new();
        let mut is_script_config_forced = false;
        if let Some(cfg) = force_script_config {
            script_configs.push(cfg);
            is_script_config_forced = true;
        }

        let mut our_keys: Vec<OurKey> = Vec::new();
        let mut inputs: Vec<TxInput> = Vec::new();

        let mut add_script_config = |script_config: pb::BtcScriptConfigWithKeypath| -> usize {
            match script_configs.iter().position(|el| el == &script_config) {
                Some(pos) => pos,
                None => {
                    script_configs.push(script_config);
                    script_configs.len() - 1
                }
            }
        };

        for (input_index, (tx_input, psbt_input)) in
            psbt.unsigned_tx.input.iter().zip(&psbt.inputs).enumerate()
        {
            let utxo = psbt
                .spend_utxo(input_index)
                .map_err(|e| BitBoxError::Psbt(e.to_string()))?;
            let our_key = find_our_key(our_root_fingerprint, psbt_input)?;
            let script_config_index = if is_script_config_forced {
                0
            } else {
                add_script_config(script_config_from_utxo(
                    utxo,
                    our_key.keypath(),
                    psbt_input.redeem_script.as_ref(),
                )?)
            };

            inputs.push(TxInput {
                prev_out_hash: (tx_input.previous_output.txid.as_ref() as &[u8]).to_vec(),
                prev_out_index: tx_input.previous_output.vout,
                prev_out_value: utxo.value.to_sat(),
                sequence: tx_input.sequence.to_consensus_u32(),
                keypath: our_key.keypath(),
                script_config_index: script_config_index as _,
                prev_tx: psbt_input.non_witness_utxo.as_ref().map(PrevTx::from),
            });
            our_keys.push(our_key);
        }

        let mut outputs: Vec<TxOutput> = Vec::new();
        for (tx_output, psbt_output) in psbt.unsigned_tx.output.iter().zip(&psbt.outputs) {
            let our_key = find_our_key(our_root_fingerprint, psbt_output);
            match our_key {
                Ok(our_key) => {
                    let script_config_index = if is_script_config_forced {
                        0
                    } else {
                        add_script_config(script_config_from_utxo(
                            tx_output,
                            our_key.keypath(),
                            psbt_output.redeem_script.as_ref(),
                        )?)
                    };
                    outputs.push(TxOutput::Internal(TxInternalOutput {
                        keypath: our_key.keypath(),
                        value: tx_output.value.to_sat(),
                        script_config_index: script_config_index as _,
                    }));
                }
                Err(_) => {
                    outputs.push(TxOutput::External(tx_output.try_into()?));
                }
            }
        }

        Ok((
            Transaction {
                script_configs,
                version: psbt.unsigned_tx.version.0 as _,
                inputs,
                outputs,
                locktime: psbt.unsigned_tx.lock_time.to_consensus_u32(),
            },
            our_keys,
        ))
    }
}

pub(crate) fn is_taproot_simple(script_config: &pb::BtcScriptConfigWithKeypath) -> bool {
    matches!(
        script_config.script_config.as_ref(),
        Some(pb::BtcScriptConfig {
            config: Some(pb::btc_script_config::Config::SimpleType(simple_type)),
        }) if *simple_type == pb::btc_script_config::SimpleType::P2tr as i32
    )
}

pub(crate) fn is_taproot_policy(script_config: &pb::BtcScriptConfigWithKeypath) -> bool {
    matches!(
        script_config.script_config.as_ref(),
        Some(pb::BtcScriptConfig {
            config: Some(pb::btc_script_config::Config::Policy(policy)),
        }) if policy.policy.as_str().starts_with("tr(")
    )
}

pub(crate) fn is_schnorr(script_config: &pb::BtcScriptConfigWithKeypath) -> bool {
    is_taproot_simple(script_config) || is_taproot_policy(script_config)
}

/// Inserts device signatures into their aligned PSBT inputs.
///
/// Inputs, signatures, and keys are zipped without checking equal lengths;
/// unmatched entries are ignored. An invalid signature can return an error after
/// earlier inputs have already been modified.
pub fn apply_signatures(
    psbt: &mut bitcoin::psbt::Psbt,
    signatures: &[Vec<u8>],
    our_keys: &[OurKey],
) -> Result<(), BitBoxError> {
    for (psbt_input, (signature, our_key)) in
        psbt.inputs.iter_mut().zip(signatures.iter().zip(our_keys))
    {
        match our_key {
            OurKey::Segwit(pubkey, _) => {
                psbt_input.partial_sigs.insert(
                    bitcoin::PublicKey::new(*pubkey),
                    bitcoin::ecdsa::Signature {
                        signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(signature)
                            .map_err(|_| BitBoxError::InvalidSignature)?,
                        sighash_type: bitcoin::sighash::EcdsaSighashType::All,
                    },
                );
            }
            OurKey::TaprootInternal(_) => {
                psbt_input.tap_key_sig = Some(
                    bitcoin::taproot::Signature::from_slice(signature)
                        .map_err(|_| BitBoxError::InvalidSignature)?,
                );
            }
            OurKey::TaprootScript(xonly, leaf_hash, _) => {
                let sig = bitcoin::taproot::Signature::from_slice(signature)
                    .map_err(|_| BitBoxError::InvalidSignature)?;
                psbt_input.tap_script_sigs.insert((*xonly, *leaf_hash), sig);
            }
        }
    }
    Ok(())
}
