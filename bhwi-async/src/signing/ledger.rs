use std::str::FromStr;

use bhwi::bitcoin::{
    self, Address, CompressedPublicKey, Network, PublicKey, ScriptBuf, TxOut,
    bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource},
    blockdata::{
        opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_16},
        script::{Instruction, PushBytes},
    },
    psbt::{Input, Psbt},
    secp256k1::Secp256k1,
};
use bhwi::common::{DeviceContext, MultisigAddressType, MultisigDisplayAddress};
use bhwi::ledger::{LedgerWalletPolicy, Version};
use bhwi::miniscript::descriptor::{DescriptorPublicKey, WalletPolicy, Wildcard};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LedgerAddressType {
    Tap,
    Wit,
    ShWit,
    Legacy,
}

impl LedgerAddressType {
    fn priority(self) -> u8 {
        match self {
            Self::Tap => 0,
            Self::Wit => 1,
            Self::ShWit => 2,
            Self::Legacy => 3,
        }
    }

    fn purpose(self) -> u32 {
        match self {
            Self::Legacy => 44,
            Self::ShWit => 49,
            Self::Wit => 84,
            Self::Tap => 86,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LedgerSigningPlan {
    Default {
        address_type: LedgerAddressType,
        account_path: DerivationPath,
    },
    Registered {
        address_type: LedgerAddressType,
        name: String,
        policy: String,
    },
}

impl LedgerSigningPlan {
    fn priority(&self) -> u8 {
        match self {
            Self::Default { address_type, .. } | Self::Registered { address_type, .. } => {
                address_type.priority()
            }
        }
    }
}

pub fn ledger_signing_plans(
    psbt: &Psbt,
    fingerprint: Fingerprint,
    network: Network,
) -> Result<Vec<LedgerSigningPlan>, String> {
    let mut plans = Vec::new();

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let Some(utxo) = input_utxo(psbt, input_index)? else {
            continue;
        };
        let owns_input = input_has_fingerprint(input, fingerprint);
        let envelope = match multisig_script(input, &utxo, input_index) {
            Ok(envelope) => envelope,
            Err(err) if owns_input => return Err(err),
            Err(_) => None,
        };

        if let Some((address_type, script)) = envelope.as_ref()
            && let Some((threshold, pubkeys)) = parse_multisig_script(script)?
        {
            let owns_multisig = pubkeys.iter().any(|pubkey| {
                input
                    .bip32_derivation
                    .get(&pubkey.inner)
                    .is_some_and(|(key_fingerprint, _)| *key_fingerprint == fingerprint)
            });
            if owns_multisig {
                let plan = ledger_multisig_plan(
                    psbt,
                    input,
                    input_index,
                    *address_type,
                    threshold,
                    &pubkeys,
                )?;
                if !plans.contains(&plan) {
                    plans.push(plan);
                }
                continue;
            }
        }

        if let Some(plan) = ledger_singlesig_plan(input, &utxo, input_index, fingerprint, network)?
        {
            if !plans.contains(&plan) {
                plans.push(plan);
            }
            continue;
        }

        if owns_input {
            let policy = if utxo.script_pubkey.is_p2tr() {
                "taproot script-path"
            } else if envelope.is_some() {
                "non-sorted-multisig or miniscript"
            } else {
                "non-default"
            };
            return Err(format!(
                "input {input_index}: Ledger HWI signtx cannot infer {policy} wallet policy; use explicit descriptor and HMAC signing"
            ));
        }
    }

    plans.sort_by_key(LedgerSigningPlan::priority);
    Ok(plans)
}

fn ledger_singlesig_plan(
    input: &Input,
    utxo: &TxOut,
    input_index: usize,
    fingerprint: Fingerprint,
    network: Network,
) -> Result<Option<LedgerSigningPlan>, String> {
    let Some(address_type) = singlesig_address_type(input, utxo) else {
        return Ok(None);
    };

    if address_type == LedgerAddressType::Tap {
        let owned: Vec<_> = input
            .tap_key_origins
            .iter()
            .filter(|(_, (_, (key_fingerprint, _)))| *key_fingerprint == fingerprint)
            .collect();
        if owned.is_empty() {
            return Ok(None);
        }
        let Some(internal_key) = input.tap_internal_key else {
            return Err(format!(
                "input {input_index}: Ledger BIP86 input is missing tap_internal_key; use explicit descriptor and HMAC signing for non-default taproot policies"
            ));
        };
        let candidates: Vec<_> = owned
            .into_iter()
            .filter(|(key, (leaf_hashes, _))| **key == internal_key && leaf_hashes.is_empty())
            .collect();
        if candidates.len() != 1 || input.tap_merkle_root.is_some() {
            return Err(format!(
                "input {input_index}: Ledger HWI signtx supports only unambiguous BIP86 key-path inputs; use explicit descriptor and HMAC signing for taproot script paths"
            ));
        }
        let (_, (_, (_, path))) = candidates[0];
        let account_path =
            validate_standard_singlesig_path(path, address_type, network, input_index)?;
        let secp = Secp256k1::verification_only();
        let expected = Address::p2tr(&secp, internal_key, None, network).script_pubkey();
        if expected != utxo.script_pubkey {
            return Err(format!(
                "input {input_index}: BIP86 internal key does not match the prevout script; use explicit descriptor and HMAC signing for non-default taproot policies"
            ));
        }
        return Ok(Some(LedgerSigningPlan::Default {
            address_type,
            account_path,
        }));
    }

    let owned: Vec<_> = input
        .bip32_derivation
        .iter()
        .filter(|(_, (key_fingerprint, _))| *key_fingerprint == fingerprint)
        .collect();
    if owned.is_empty() {
        return Ok(None);
    }
    let candidates: Vec<_> = owned
        .into_iter()
        .filter(|(key, _)| singlesig_key_matches(**key, address_type, input, utxo, network))
        .collect();
    if candidates.len() != 1 {
        return Err(format!(
            "input {input_index}: Ledger single-sig key metadata is missing or ambiguous"
        ));
    }
    let (_, (_, path)) = candidates[0];
    let account_path = validate_standard_singlesig_path(path, address_type, network, input_index)?;
    Ok(Some(LedgerSigningPlan::Default {
        address_type,
        account_path,
    }))
}

fn singlesig_address_type(input: &Input, utxo: &TxOut) -> Option<LedgerAddressType> {
    if utxo.script_pubkey.is_p2pkh() {
        Some(LedgerAddressType::Legacy)
    } else if utxo.script_pubkey.is_p2wpkh() {
        Some(LedgerAddressType::Wit)
    } else if utxo.script_pubkey.is_p2tr() {
        Some(LedgerAddressType::Tap)
    } else if utxo.script_pubkey.is_p2sh()
        && input
            .redeem_script
            .as_ref()
            .is_some_and(|script| script.is_p2wpkh() && script.to_p2sh() == utxo.script_pubkey)
    {
        Some(LedgerAddressType::ShWit)
    } else {
        None
    }
}

fn singlesig_key_matches(
    key: bitcoin::secp256k1::PublicKey,
    address_type: LedgerAddressType,
    input: &Input,
    utxo: &TxOut,
    network: Network,
) -> bool {
    let key = PublicKey::new(key);
    match address_type {
        LedgerAddressType::Legacy => {
            Address::p2pkh(key, network).script_pubkey() == utxo.script_pubkey
        }
        LedgerAddressType::Wit => CompressedPublicKey::try_from(key)
            .is_ok_and(|key| Address::p2wpkh(&key, network).script_pubkey() == utxo.script_pubkey),
        LedgerAddressType::ShWit => CompressedPublicKey::try_from(key).is_ok_and(|key| {
            input.redeem_script.as_ref().is_some_and(|script| {
                Address::p2wpkh(&key, network).script_pubkey() == *script
                    && script.to_p2sh() == utxo.script_pubkey
            })
        }),
        LedgerAddressType::Tap => false,
    }
}

fn validate_standard_singlesig_path(
    path: &DerivationPath,
    address_type: LedgerAddressType,
    network: Network,
    input_index: usize,
) -> Result<DerivationPath, String> {
    let children = path.as_ref();
    if children.len() != 5 {
        return Err(format!(
            "input {input_index}: Ledger default wallet requires an exact five-level derivation path"
        ));
    }
    let purpose = hardened_index(children[0]);
    let coin_type = hardened_index(children[1]);
    let account = hardened_index(children[2]);
    let branch = normal_index(children[3]);
    let index = normal_index(children[4]);
    let expected_coin_type = if network == Network::Bitcoin { 0 } else { 1 };
    if purpose != Some(address_type.purpose())
        || coin_type != Some(expected_coin_type)
        || account.is_none()
        || !matches!(branch, Some(0 | 1))
        || index.is_none()
    {
        return Err(format!(
            "input {input_index}: derivation path {path} is not a standard Ledger {:?} wallet path",
            address_type
        ));
    }
    Ok(DerivationPath::from(children[..3].to_vec()))
}

fn hardened_index(child: ChildNumber) -> Option<u32> {
    match child {
        ChildNumber::Hardened { index } => Some(index),
        ChildNumber::Normal { .. } => None,
    }
}

fn normal_index(child: ChildNumber) -> Option<u32> {
    match child {
        ChildNumber::Normal { index } => Some(index),
        ChildNumber::Hardened { .. } => None,
    }
}

fn ledger_multisig_plan(
    psbt: &Psbt,
    input: &Input,
    input_index: usize,
    address_type: LedgerAddressType,
    threshold: usize,
    pubkeys: &[PublicKey],
) -> Result<LedgerSigningPlan, String> {
    if !pubkeys
        .windows(2)
        .all(|keys| keys[0].inner.serialize() < keys[1].inner.serialize())
    {
        return Err(format!(
            "input {input_index}: Ledger HWI signtx supports only sorted multisig scripts"
        ));
    }

    let mut keys = Vec::with_capacity(pubkeys.len());
    let mut expected_suffix = None;
    for pubkey in pubkeys {
        let key_source = input.bip32_derivation.get(&pubkey.inner).ok_or_else(|| {
            format!("input {input_index}: multisig public key is missing BIP32 derivation metadata")
        })?;
        let resolved = global_xpub_key_expression(psbt, key_source, pubkey, input_index)?;
        match expected_suffix {
            Some(suffix) if suffix != resolved.suffix => {
                return Err(format!(
                    "input {input_index}: multisig keys do not share one receive/change derivation"
                ));
            }
            None => expected_suffix = Some(resolved.suffix),
            Some(_) => {}
        }
        keys.push(format!("{}/<0;1>/*", resolved.expression));
    }
    // sortedmulti semantics do not depend on the key-info order. Canonicalize it so
    // inputs at different indexes reconstruct one stable registered wallet.
    keys.sort();
    let policy = multisig_policy_descriptor(address_type, threshold, &keys, true);
    Ok(LedgerSigningPlan::Registered {
        address_type,
        name: format!("{threshold} of {} Multisig", pubkeys.len()),
        policy,
    })
}

struct ResolvedMultisigKey {
    expression: String,
    suffix: (u32, u32),
}

fn global_xpub_key_expression(
    psbt: &Psbt,
    key_source: &KeySource,
    pubkey: &PublicKey,
    input_index: usize,
) -> Result<ResolvedMultisigKey, String> {
    let (fingerprint, key_path) = key_source;
    let children = key_path.as_ref();
    if children.len() < 2 {
        return Err(format!(
            "input {input_index}: multisig derivation path is too short"
        ));
    }
    let branch = normal_index(children[children.len() - 2]);
    let index = normal_index(children[children.len() - 1]);
    if !matches!(branch, Some(0 | 1)) || index.is_none() {
        return Err(format!(
            "input {input_index}: Ledger multisig derivation must end in /0/index or /1/index"
        ));
    }
    let suffix = (
        branch.expect("branch checked"),
        index.expect("index checked"),
    );
    let xpub_path = DerivationPath::from(children[..children.len() - 2].to_vec());
    let matches: Vec<_> = psbt
        .xpub
        .iter()
        .filter(|(_, (xpub_fingerprint, path))| {
            *xpub_fingerprint == *fingerprint && *path == xpub_path
        })
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "input {input_index}: expected one account-level global xpub for {fingerprint}, found {}",
            matches.len()
        ));
    }
    let (xpub, (_, origin_path)) = matches[0];
    let secp = Secp256k1::verification_only();
    let derived = xpub
        .derive_pub(
            &secp,
            &[
                ChildNumber::from_normal_idx(suffix.0).expect("branch checked"),
                ChildNumber::from_normal_idx(suffix.1).expect("index checked"),
            ],
        )
        .map_err(|err| format!("input {input_index}: failed to derive global xpub: {err}"))?;
    if derived.public_key != pubkey.inner {
        return Err(format!(
            "input {input_index}: global xpub derivation does not match multisig public key"
        ));
    }
    let origin = origin_path.to_string();
    let origin = origin.trim_start_matches('m').trim_start_matches('/');
    let expression = if origin.is_empty() {
        format!("[{fingerprint}]{xpub}")
    } else {
        format!("[{fingerprint}/{origin}]{xpub}")
    };
    Ok(ResolvedMultisigKey { expression, suffix })
}

fn input_has_fingerprint(input: &Input, fingerprint: Fingerprint) -> bool {
    input
        .bip32_derivation
        .values()
        .any(|(key_fingerprint, _)| *key_fingerprint == fingerprint)
        || input
            .tap_key_origins
            .values()
            .any(|(_, (key_fingerprint, _))| *key_fingerprint == fingerprint)
}

fn input_utxo(psbt: &Psbt, input_index: usize) -> Result<Option<TxOut>, String> {
    let input = &psbt.inputs[input_index];
    let txin = &psbt.unsigned_tx.input[input_index];
    let non_witness = if let Some(tx) = &input.non_witness_utxo {
        if tx.compute_txid() != txin.previous_output.txid {
            return Err(format!(
                "input {input_index}: non_witness_utxo transaction id does not match prevout"
            ));
        }
        Some(
            tx.output
                .get(txin.previous_output.vout as usize)
                .cloned()
                .ok_or_else(|| format!("input {input_index}: prevout index is out of range"))?,
        )
    } else {
        None
    };
    if let (Some(witness), Some(non_witness)) = (&input.witness_utxo, &non_witness)
        && witness != non_witness
    {
        return Err(format!(
            "input {input_index}: witness_utxo and non_witness_utxo disagree"
        ));
    }
    Ok(input.witness_utxo.clone().or(non_witness))
}

pub fn extend_account_path_for_policy(path: &DerivationPath) -> DerivationPath {
    let mut children = path.as_ref().to_vec();
    children.push(ChildNumber::from_normal_idx(0).expect("valid receive branch"));
    children.push(ChildNumber::from_normal_idx(0).expect("valid address index"));
    DerivationPath::from(children)
}

fn multisig_script(
    input: &Input,
    utxo: &TxOut,
    input_index: usize,
) -> Result<Option<(LedgerAddressType, ScriptBuf)>, String> {
    if utxo.script_pubkey.is_p2wsh() {
        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or_else(|| format!("input {input_index}: P2WSH input is missing witness_script"))?;
        if witness_script.to_p2wsh() != utxo.script_pubkey {
            return Err(format!(
                "input {input_index}: witness_script does not match P2WSH prevout"
            ));
        }
        return Ok(Some((LedgerAddressType::Wit, witness_script.clone())));
    }
    if !utxo.script_pubkey.is_p2sh() {
        return Ok(None);
    }
    let redeem_script = input
        .redeem_script
        .as_ref()
        .ok_or_else(|| format!("input {input_index}: P2SH input is missing redeem_script"))?;
    if redeem_script.to_p2sh() != utxo.script_pubkey {
        return Err(format!(
            "input {input_index}: redeem_script does not match P2SH prevout"
        ));
    }
    if redeem_script.is_p2wsh() {
        let witness_script = input.witness_script.as_ref().ok_or_else(|| {
            format!("input {input_index}: nested P2WSH input is missing witness_script")
        })?;
        if witness_script.to_p2wsh() != *redeem_script {
            return Err(format!(
                "input {input_index}: witness_script does not match nested P2WSH redeem_script"
            ));
        }
        Ok(Some((LedgerAddressType::ShWit, witness_script.clone())))
    } else {
        Ok(Some((LedgerAddressType::Legacy, redeem_script.clone())))
    }
}

fn parse_multisig_script(script: &ScriptBuf) -> Result<Option<(usize, Vec<PublicKey>)>, String> {
    let mut instructions = script.instructions();
    let Some(first) = instructions.next() else {
        return Ok(None);
    };
    let threshold = match first.map_err(|err| err.to_string())? {
        Instruction::Op(op) => pushnum(op).filter(|n| *n <= 16),
        Instruction::PushBytes(_) => None,
    };
    let Some(threshold) = threshold else {
        return Ok(None);
    };

    let mut pubkeys = Vec::new();
    let signer_count = loop {
        let Some(instruction) = instructions.next() else {
            return Ok(None);
        };
        match instruction.map_err(|err| err.to_string())? {
            Instruction::PushBytes(bytes) if bytes.len() == 33 => {
                let public_key = PublicKey::from_slice(push_bytes_as_bytes(bytes))
                    .map_err(|err| err.to_string())?;
                pubkeys.push(public_key);
            }
            Instruction::Op(op) => {
                break pushnum(op);
            }
            Instruction::PushBytes(_) => return Ok(None),
        }
    };

    let Some(signer_count) = signer_count else {
        return Ok(None);
    };
    let Some(last) = instructions.next() else {
        return Ok(None);
    };
    if last.map_err(|err| err.to_string())? != Instruction::Op(OP_CHECKMULTISIG)
        || instructions.next().is_some()
        || signer_count != pubkeys.len()
        || threshold == 0
        || threshold > signer_count
    {
        return Ok(None);
    }
    Ok(Some((threshold, pubkeys)))
}

fn multisig_policy_descriptor(
    address_type: LedgerAddressType,
    threshold: usize,
    keys: &[String],
    sorted: bool,
) -> String {
    let operator = if sorted { "sortedmulti" } else { "multi" };
    let body = format!("{operator}({threshold},{})", keys.join(","));
    match address_type {
        LedgerAddressType::Legacy => format!("sh({body})"),
        LedgerAddressType::ShWit => format!("sh(wsh({body}))"),
        LedgerAddressType::Wit => format!("wsh({body})"),
        LedgerAddressType::Tap => unreachable!("taproot is not classic multisig"),
    }
}

fn pushnum(op: bitcoin::blockdata::opcodes::Opcode) -> Option<usize> {
    if op == OP_PUSHNUM_1 {
        return Some(1);
    }
    if op.to_u8() >= OP_PUSHNUM_1.to_u8() && op.to_u8() <= OP_PUSHNUM_16.to_u8() {
        return Some((op.to_u8() - OP_PUSHNUM_1.to_u8() + 1) as usize);
    }
    None
}

fn push_bytes_as_bytes(bytes: &PushBytes) -> &[u8] {
    bytes.as_bytes()
}

const MULTISIG_BRANCH_RULE: &str =
    "Ledger Bitcoin app requires derivation paths ending with /0/* or /1/* for multisig";
const MULTISIG_KEY_COUNT_RULE: &str = "Invalid threshold or number of keys";
const MULTISIG_ORIGIN_RULE: &str =
    "Ledger multisig display requires extended public keys with origin information";

#[derive(Debug)]
pub struct LedgerMultisigDisplayPlan {
    pub name: String,
    pub policy_text: String,
    pub policy: WalletPolicy,
    pub change: bool,
    pub address_index: u32,
}

pub fn ledger_multisig_display_plan(
    multisig: MultisigDisplayAddress,
) -> Result<LedgerMultisigDisplayPlan, String> {
    let key_count = multisig.keys.len();
    if multisig.threshold == 0
        || key_count == 0
        || key_count > 16
        || usize::from(multisig.threshold) > key_count
    {
        return Err(MULTISIG_KEY_COUNT_RULE.to_owned());
    }

    let mut suffixes = Vec::with_capacity(key_count);
    let mut keys = Vec::with_capacity(key_count);
    let mut origin_too_long = false;
    for key in &multisig.keys {
        let xpub = match key {
            DescriptorPublicKey::XPub(xpub) => xpub,
            DescriptorPublicKey::Single(_) => return Err(MULTISIG_ORIGIN_RULE.to_owned()),
            DescriptorPublicKey::MultiXPub(_) => return Err(MULTISIG_BRANCH_RULE.to_owned()),
        };
        let Some((_, origin_path)) = &xpub.origin else {
            return Err(MULTISIG_ORIGIN_RULE.to_owned());
        };
        let suffix = xpub.derivation_path.as_ref();
        if xpub.wildcard != Wildcard::None || suffix.len() != 2 {
            return Err(MULTISIG_BRANCH_RULE.to_owned());
        }
        let Some(branch) = normal_index(suffix[0]) else {
            return Err(MULTISIG_BRANCH_RULE.to_owned());
        };
        let Some(index) = normal_index(suffix[1]) else {
            return Err(MULTISIG_BRANCH_RULE.to_owned());
        };
        if branch > 1 || index > 0x7fff_ffff {
            return Err(MULTISIG_BRANCH_RULE.to_owned());
        }
        suffixes.push((branch, index));
        origin_too_long |= origin_path.as_ref().len() > 4;
        keys.push(format!("{}/<0;1>/*", bhwi::policy::format_key_info(key)));
    }
    let Some((branch, address_index)) = suffixes.first().copied() else {
        return Err(MULTISIG_KEY_COUNT_RULE.to_owned());
    };
    if suffixes
        .iter()
        .any(|suffix| *suffix != (branch, address_index))
    {
        return Err(
            "Ledger Bitcoin app requires all derivation paths to end with /0/*, or all with /1/* for multisig"
                .to_owned(),
        );
    }
    if origin_too_long {
        return Err(
            "Ledger Bitcoin app requires extended keys with derivation length at most 4".to_owned(),
        );
    }

    let address_type = match multisig.address_type {
        MultisigAddressType::Legacy => LedgerAddressType::Legacy,
        MultisigAddressType::ShWit => LedgerAddressType::ShWit,
        MultisigAddressType::Wit => LedgerAddressType::Wit,
    };

    let policy_text = multisig_policy_descriptor(
        address_type,
        usize::from(multisig.threshold),
        &keys,
        multisig.sorted,
    );
    let policy = WalletPolicy::from_str(&policy_text).map_err(|err| err.to_string())?;

    Ok(LedgerMultisigDisplayPlan {
        name: format!("{} of {key_count} Multisig", multisig.threshold),
        policy_text,
        policy,
        change: branch == 1,
        address_index,
    })
}

/// No `hmac` means a default policy, which needs no registration.
pub fn registered_context(
    name: String,
    policy: WalletPolicy,
    hmac: Option<[u8; 32]>,
) -> DeviceContext {
    DeviceContext::Ledger {
        wallet_policy: LedgerWalletPolicy::new(name, Version::V2, policy),
        wallet_hmac: hmac,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bhwi::bitcoin::{
        Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime,
        bip32::{Xpriv, Xpub},
        blockdata::script::Builder,
        transaction::Version as TxVersion,
    };

    use super::*;

    #[test]
    fn ledger_signing_plans_cover_all_default_wallets() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let pubkey = sample_child_pubkey(0);
        for (address_type, path, input) in [
            (
                LedgerAddressType::Legacy,
                "m/44'/1'/0'/0/0",
                Input {
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: Address::p2pkh(pubkey, Network::Testnet).script_pubkey(),
                    }),
                    ..Default::default()
                },
            ),
            (LedgerAddressType::ShWit, "m/49'/1'/0'/0/0", {
                let redeem_script = Address::p2wpkh(
                    &CompressedPublicKey::try_from(pubkey).unwrap(),
                    Network::Testnet,
                )
                .script_pubkey();
                Input {
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: redeem_script.to_p2sh(),
                    }),
                    redeem_script: Some(redeem_script),
                    ..Default::default()
                }
            }),
            (
                LedgerAddressType::Wit,
                "m/84'/1'/0'/0/0",
                Input {
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: Address::p2wpkh(
                            &CompressedPublicKey::try_from(pubkey).unwrap(),
                            Network::Testnet,
                        )
                        .script_pubkey(),
                    }),
                    ..Default::default()
                },
            ),
        ] {
            let path = DerivationPath::from_str(path).unwrap();
            let mut input = input;
            input
                .bip32_derivation
                .insert(pubkey.inner, (fingerprint, path));
            assert_eq!(
                ledger_signing_plans(&psbt_with_input(input), fingerprint, Network::Testnet)
                    .unwrap(),
                vec![LedgerSigningPlan::Default {
                    address_type,
                    account_path: DerivationPath::from_str(&format!(
                        "m/{}'/1'/0'",
                        address_type.purpose()
                    ))
                    .unwrap(),
                }]
            );
        }

        let internal_key = pubkey.inner.x_only_public_key().0;
        let path = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
        let psbt = psbt_with_input(Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Address::p2tr(
                    &Secp256k1::verification_only(),
                    internal_key,
                    None,
                    Network::Testnet,
                )
                .script_pubkey(),
            }),
            tap_internal_key: Some(internal_key),
            tap_key_origins: [(internal_key, (Vec::new(), (fingerprint, path)))].into(),
            ..Default::default()
        });
        assert_eq!(
            ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap(),
            vec![LedgerSigningPlan::Default {
                address_type: LedgerAddressType::Tap,
                account_path: DerivationPath::from_str("m/86'/1'/0'").unwrap(),
            }]
        );
    }

    #[test]
    fn ledger_signing_plans_support_multiple_singlesig_accounts() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let pubkey_a = sample_child_pubkey(0);
        let pubkey_b = sample_child_pubkey(1);
        let psbt = psbt_with_inputs(vec![
            Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Address::p2wpkh(
                        &CompressedPublicKey::try_from(pubkey_a).unwrap(),
                        Network::Testnet,
                    )
                    .script_pubkey(),
                }),
                bip32_derivation: [(
                    pubkey_a.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                    ),
                )]
                .into(),
                ..Default::default()
            },
            Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Address::p2wpkh(
                        &CompressedPublicKey::try_from(pubkey_b).unwrap(),
                        Network::Testnet,
                    )
                    .script_pubkey(),
                }),
                bip32_derivation: [(
                    pubkey_b.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/84'/1'/1'/0/0").unwrap(),
                    ),
                )]
                .into(),
                ..Default::default()
            },
        ]);

        let plans = ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap();
        assert_eq!(plans.len(), 2);
        assert!(plans.iter().all(|plan| matches!(
            plan,
            LedgerSigningPlan::Default {
                address_type: LedgerAddressType::Wit,
                ..
            }
        )));
    }

    #[test]
    fn ledger_signing_plans_support_mixed_default_and_registered_policies() {
        let (multisig, fingerprint) = sample_multisig_psbt(LedgerAddressType::Wit, true);
        let pubkey = sample_child_pubkey(0);
        let singlesig = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Address::p2wpkh(
                    &CompressedPublicKey::try_from(pubkey).unwrap(),
                    Network::Testnet,
                )
                .script_pubkey(),
            }),
            bip32_derivation: [(
                pubkey.inner,
                (
                    fingerprint,
                    DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                ),
            )]
            .into(),
            ..Default::default()
        };
        let mut psbt = psbt_with_inputs(vec![singlesig, multisig.inputs[0].clone()]);
        psbt.xpub = multisig.xpub;

        let plans = ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap();
        assert_eq!(plans.len(), 2);
        assert!(matches!(plans[0], LedgerSigningPlan::Default { .. }));
        assert!(matches!(plans[1], LedgerSigningPlan::Registered { .. }));
    }

    #[test]
    fn ledger_multisig_plans_cover_all_hwi_wrappers() {
        for address_type in [
            LedgerAddressType::Legacy,
            LedgerAddressType::ShWit,
            LedgerAddressType::Wit,
        ] {
            let (psbt, fingerprint) = sample_multisig_psbt(address_type, true);
            let plans = ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap();
            let LedgerSigningPlan::Registered { policy, name, .. } = &plans[0] else {
                panic!("registered policy");
            };
            assert_eq!(name, "2 of 2 Multisig");
            assert_eq!(policy.matches("/<0;1>/*").count(), 2);
            match address_type {
                LedgerAddressType::Legacy => assert!(policy.starts_with("sh(sortedmulti(2,")),
                LedgerAddressType::ShWit => {
                    assert!(policy.starts_with("sh(wsh(sortedmulti(2,"))
                }
                LedgerAddressType::Wit => assert!(policy.starts_with("wsh(sortedmulti(2,")),
                LedgerAddressType::Tap => unreachable!(),
            }
        }
    }

    #[test]
    fn ledger_multisig_plan_rejects_missing_global_xpub() {
        let (mut psbt, fingerprint) = sample_multisig_psbt(LedgerAddressType::Wit, true);
        psbt.xpub.clear();

        let err =
            ledger_signing_plans(&psbt, fingerprint, Network::Testnet).expect_err("missing xpub");
        assert!(err.contains("expected one account-level global xpub"));
    }

    #[test]
    fn ledger_multisig_plan_rejects_unsorted_script() {
        let (psbt, fingerprint) = sample_multisig_psbt(LedgerAddressType::Wit, false);

        let err = ledger_signing_plans(&psbt, fingerprint, Network::Testnet)
            .expect_err("unsorted multisig");
        assert!(err.contains("supports only sorted multisig"));
    }

    fn sample_child_pubkey(index: u32) -> PublicKey {
        let secp = Secp256k1::verification_only();
        let xpub = sample_xpub()
            .derive_pub(
                &secp,
                &[
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(index).unwrap(),
                ],
            )
            .expect("derive pubkey");
        PublicKey::new(xpub.public_key)
    }

    fn multisig_script_buf(threshold: i64, pubkeys: &[PublicKey]) -> ScriptBuf {
        let mut builder = Builder::new().push_int(threshold);
        for pubkey in pubkeys {
            builder = builder.push_slice(pubkey.inner.serialize());
        }
        builder
            .push_int(pubkeys.len() as i64)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    fn sample_multisig_psbt(address_type: LedgerAddressType, sorted: bool) -> (Psbt, Fingerprint) {
        let secp = Secp256k1::new();
        let account_path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
        let suffix = [
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ];
        let mut sources = Vec::new();
        for seed in [1_u8, 2] {
            let master = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap();
            let fingerprint = master.fingerprint(&secp);
            let account = master.derive_priv(&secp, &account_path).unwrap();
            let xpub = Xpub::from_priv(&secp, &account);
            let child = xpub.derive_pub(&secp, &suffix).unwrap();
            sources.push((fingerprint, xpub, PublicKey::new(child.public_key)));
        }
        sources.sort_by_key(|(_, _, pubkey)| pubkey.inner.serialize());
        if !sorted {
            sources.reverse();
        }
        let pubkeys: Vec<_> = sources.iter().map(|(_, _, pubkey)| *pubkey).collect();
        let script = multisig_script_buf(2, &pubkeys);
        let mut input = Input {
            bip32_derivation: sources
                .iter()
                .map(|(fingerprint, _, pubkey)| {
                    let mut path = account_path.as_ref().to_vec();
                    path.extend_from_slice(&suffix);
                    (pubkey.inner, (*fingerprint, DerivationPath::from(path)))
                })
                .collect(),
            ..Default::default()
        };
        let script_pubkey = match address_type {
            LedgerAddressType::Legacy => {
                input.redeem_script = Some(script.clone());
                script.to_p2sh()
            }
            LedgerAddressType::ShWit => {
                let redeem_script = script.to_p2wsh();
                input.redeem_script = Some(redeem_script.clone());
                input.witness_script = Some(script);
                redeem_script.to_p2sh()
            }
            LedgerAddressType::Wit => {
                input.witness_script = Some(script.clone());
                script.to_p2wsh()
            }
            LedgerAddressType::Tap => unreachable!(),
        };
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        });
        let mut psbt = psbt_with_input(input);
        for (fingerprint, xpub, _) in &sources {
            psbt.xpub
                .insert(*xpub, (*fingerprint, account_path.clone()));
        }
        (psbt, sources[0].0)
    }

    fn psbt_with_input(input: Input) -> Psbt {
        psbt_with_inputs(vec![input])
    }

    fn psbt_with_inputs(inputs: Vec<Input>) -> Psbt {
        let unsigned_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|_| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("psbt");
        psbt.inputs = inputs;
        psbt
    }

    fn sample_xpub() -> Xpub {
        Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT")
            .expect("sample xpub")
    }
}
