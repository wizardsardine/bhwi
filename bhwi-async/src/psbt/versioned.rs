use std::collections::HashSet;

use bhwi::bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    consensus::encode::{VarInt, deserialize_partial, serialize},
    hashes::Hash as _,
    psbt::{self, Psbt},
    transaction::Version,
};

const MAGIC: &[u8] = b"psbt\xff";

const GLOBAL_UNSIGNED_TX: u64 = 0x00;
const GLOBAL_XPUB: u64 = 0x01;
const GLOBAL_TX_VERSION: u64 = 0x02;
const GLOBAL_FALLBACK_LOCKTIME: u64 = 0x03;
const GLOBAL_INPUT_COUNT: u64 = 0x04;
const GLOBAL_OUTPUT_COUNT: u64 = 0x05;
const GLOBAL_TX_MODIFIABLE: u64 = 0x06;
const GLOBAL_VERSION: u64 = 0xfb;
const IN_PREVIOUS_TXID: u64 = 0x0e;
const IN_OUTPUT_INDEX: u64 = 0x0f;
const IN_SEQUENCE: u64 = 0x10;
const IN_REQUIRED_TIME_LOCKTIME: u64 = 0x11;
const IN_REQUIRED_HEIGHT_LOCKTIME: u64 = 0x12;
const OUT_BIP32_DERIVATION: u64 = 0x02;
const OUT_AMOUNT: u64 = 0x03;
const OUT_SCRIPT: u64 = 0x04;

const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// A version 0 or 2 PSBT, signed as version 0 and written back in its original version.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionedPsbt {
    psbt: Psbt,
    v2: Option<V2Fields>,
}

#[derive(Debug, Clone, PartialEq)]
struct V2Fields {
    fallback_lock_time: Option<u32>,
    tx_modifiable: Option<u8>,
    inputs: Vec<V2Input>,
}

#[derive(Debug, Clone, PartialEq)]
struct V2Input {
    has_sequence: bool,
    required_time: Option<u32>,
    required_height: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum VersionedPsbtError {
    #[error("invalid PSBT: {0}")]
    Psbt(#[from] psbt::Error),
    #[error("invalid PSBT: {0}")]
    Invalid(String),
    #[error("the PSBT signed by the device spends a different transaction")]
    TransactionChanged,
}

fn invalid(message: impl Into<String>) -> VersionedPsbtError {
    VersionedPsbtError::Invalid(message.into())
}

impl VersionedPsbt {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, VersionedPsbtError> {
        let mut reader = Reader::new(bytes)?;
        let global = reader.map()?;
        let psbt = match psbt_version(&global)? {
            0 => Self::from_v0(bytes)?,
            2 => Self::from_v2(global, reader)?,
            version => return Err(invalid(format!("PSBT version {version} is not supported"))),
        };
        check_previous_outputs(&psbt.psbt)?;
        Ok(psbt)
    }

    pub fn serialize(&self) -> Vec<u8> {
        match &self.v2 {
            None => self.psbt.serialize(),
            Some(v2) => serialize_v2(&self.psbt, v2),
        }
    }

    pub fn as_psbt_v0(&self) -> &Psbt {
        &self.psbt
    }

    pub fn version(&self) -> u32 {
        if self.v2.is_some() {
            2
        } else {
            self.psbt.version
        }
    }

    pub fn restore_version(
        &self,
        signed_psbt_from_device: Psbt,
    ) -> Result<Self, VersionedPsbtError> {
        let Some(v2) = &self.v2 else {
            return Ok(Self {
                psbt: signed_psbt_from_device,
                v2: None,
            });
        };
        if signed_psbt_from_device.unsigned_tx != self.psbt.unsigned_tx
            || signed_psbt_from_device.inputs.len() != v2.inputs.len()
            || signed_psbt_from_device.outputs.len() != self.psbt.unsigned_tx.output.len()
        {
            return Err(VersionedPsbtError::TransactionChanged);
        }
        Ok(Self {
            psbt: signed_psbt_from_device,
            v2: Some(v2.clone()),
        })
    }

    fn from_v0(bytes: &[u8]) -> Result<Self, VersionedPsbtError> {
        let psbt = Psbt::deserialize(bytes)?;
        let v2_only =
            |key: &psbt::raw::Key, types: &[u64]| types.contains(&u64::from(key.type_value));
        let global = [
            GLOBAL_TX_VERSION,
            GLOBAL_FALLBACK_LOCKTIME,
            GLOBAL_INPUT_COUNT,
            GLOBAL_OUTPUT_COUNT,
            GLOBAL_TX_MODIFIABLE,
        ];
        let input = [
            IN_PREVIOUS_TXID,
            IN_OUTPUT_INDEX,
            IN_SEQUENCE,
            IN_REQUIRED_TIME_LOCKTIME,
            IN_REQUIRED_HEIGHT_LOCKTIME,
        ];
        let output = [OUT_AMOUNT, OUT_SCRIPT];
        if psbt.unknown.keys().any(|key| v2_only(key, &global))
            || psbt
                .inputs
                .iter()
                .any(|i| i.unknown.keys().any(|key| v2_only(key, &input)))
            || psbt
                .outputs
                .iter()
                .any(|o| o.unknown.keys().any(|key| v2_only(key, &output)))
        {
            return Err(invalid("a version 0 PSBT contains a PSBTv2 field"));
        }
        Ok(Self { psbt, v2: None })
    }

    fn from_v2(global: Vec<Pair>, mut reader: Reader<'_>) -> Result<Self, VersionedPsbtError> {
        let mut tx_version = None;
        let mut fallback_lock_time = None;
        let mut input_count = None;
        let mut output_count = None;
        let mut tx_modifiable = None;
        let mut global_rest = Vec::new();
        for pair in global {
            match pair.key_type {
                GLOBAL_UNSIGNED_TX => {
                    return Err(invalid("PSBTv2 must not contain PSBT_GLOBAL_UNSIGNED_TX"));
                }
                GLOBAL_TX_VERSION => {
                    tx_version = Some(i32::from_le_bytes(pair.fixed("PSBT_GLOBAL_TX_VERSION")?));
                }
                GLOBAL_FALLBACK_LOCKTIME => {
                    fallback_lock_time = Some(u32::from_le_bytes(
                        pair.fixed("PSBT_GLOBAL_FALLBACK_LOCKTIME")?,
                    ));
                }
                GLOBAL_INPUT_COUNT => input_count = Some(pair.count("PSBT_GLOBAL_INPUT_COUNT")?),
                GLOBAL_OUTPUT_COUNT => output_count = Some(pair.count("PSBT_GLOBAL_OUTPUT_COUNT")?),
                GLOBAL_TX_MODIFIABLE => {
                    tx_modifiable = Some(pair.fixed::<1>("PSBT_GLOBAL_TX_MODIFIABLE")?[0]);
                }
                GLOBAL_VERSION => pair.no_key_data("PSBT_GLOBAL_VERSION")?,
                _ => global_rest.push(pair),
            }
        }
        let tx_version = tx_version.ok_or_else(|| missing("PSBT_GLOBAL_TX_VERSION"))?;
        let input_count = input_count.ok_or_else(|| missing("PSBT_GLOBAL_INPUT_COUNT"))?;
        let output_count = output_count.ok_or_else(|| missing("PSBT_GLOBAL_OUTPUT_COUNT"))?;

        let mut tx_inputs = Vec::new();
        let mut v2_inputs = Vec::new();
        let mut input_rest = Vec::new();
        for _ in 0..input_count {
            let (txin, v2_input, rest) = read_input(reader.map()?)?;
            tx_inputs.push(txin);
            v2_inputs.push(v2_input);
            input_rest.push(rest);
        }
        let mut tx_outputs = Vec::new();
        let mut output_rest = Vec::new();
        for _ in 0..output_count {
            let (txout, rest) = read_output(reader.map()?)?;
            tx_outputs.push(txout);
            output_rest.push(rest);
        }
        if !reader.is_empty() {
            return Err(invalid("data follows the last PSBT map"));
        }

        let unsigned_tx = Transaction {
            version: Version(tx_version),
            lock_time: LockTime::from_consensus(lock_time(fallback_lock_time, &v2_inputs)?),
            input: tx_inputs,
            output: tx_outputs,
        };
        let mut v0 = MAGIC.to_vec();
        let mut unsigned_tx_bytes = serialize(&unsigned_tx.version);
        unsigned_tx_bytes.extend(serialize(&unsigned_tx.input));
        unsigned_tx_bytes.extend(serialize(&unsigned_tx.output));
        unsigned_tx_bytes.extend(serialize(&unsigned_tx.lock_time));
        write_pairs(&mut v0, &[Pair::new(GLOBAL_UNSIGNED_TX, unsigned_tx_bytes)]);
        write_map(&mut v0, &global_rest);
        for rest in input_rest.iter().chain(&output_rest) {
            write_map(&mut v0, rest);
        }
        Ok(Self {
            psbt: Psbt::deserialize(&v0)?,
            v2: Some(V2Fields {
                fallback_lock_time,
                tx_modifiable,
                inputs: v2_inputs,
            }),
        })
    }
}

fn missing(field: &str) -> VersionedPsbtError {
    invalid(format!("PSBTv2 is missing {field}"))
}

fn check_previous_outputs(psbt: &Psbt) -> Result<(), VersionedPsbtError> {
    for (index, (txin, input)) in psbt.unsigned_tx.input.iter().zip(&psbt.inputs).enumerate() {
        let Some(previous_tx) = &input.non_witness_utxo else {
            continue;
        };
        let prevout = txin.previous_output;
        if previous_tx.compute_txid() != prevout.txid {
            return Err(invalid(format!(
                "input {index}: non_witness_utxo does not match the prevout txid"
            )));
        }
        let Some(previous_output) = previous_tx.output.get(prevout.vout as usize) else {
            return Err(invalid(format!(
                "input {index}: non_witness_utxo has no output {}",
                prevout.vout
            )));
        };
        if input
            .witness_utxo
            .as_ref()
            .is_some_and(|witness_utxo| witness_utxo != previous_output)
        {
            return Err(invalid(format!(
                "input {index}: witness_utxo and non_witness_utxo disagree"
            )));
        }
    }
    Ok(())
}

fn psbt_version(global: &[Pair]) -> Result<u32, VersionedPsbtError> {
    match global.iter().find(|pair| pair.key_type == GLOBAL_VERSION) {
        Some(pair) => Ok(u32::from_le_bytes(pair.fixed("PSBT_GLOBAL_VERSION")?)),
        None => Ok(0),
    }
}

fn read_input(pairs: Vec<Pair>) -> Result<(TxIn, V2Input, Vec<Pair>), VersionedPsbtError> {
    let mut txid = None;
    let mut vout = None;
    let mut sequence = None;
    let mut required_time = None;
    let mut required_height = None;
    let mut rest = Vec::new();
    for pair in pairs {
        match pair.key_type {
            IN_PREVIOUS_TXID => {
                txid = Some(Txid::from_byte_array(pair.fixed("PSBT_IN_PREVIOUS_TXID")?));
            }
            IN_OUTPUT_INDEX => vout = Some(u32::from_le_bytes(pair.fixed("PSBT_IN_OUTPUT_INDEX")?)),
            IN_SEQUENCE => sequence = Some(u32::from_le_bytes(pair.fixed("PSBT_IN_SEQUENCE")?)),
            IN_REQUIRED_TIME_LOCKTIME => {
                let time = u32::from_le_bytes(pair.fixed("PSBT_IN_REQUIRED_TIME_LOCKTIME")?);
                if time < LOCKTIME_THRESHOLD {
                    return Err(invalid("PSBT_IN_REQUIRED_TIME_LOCKTIME is below 500000000"));
                }
                required_time = Some(time);
            }
            IN_REQUIRED_HEIGHT_LOCKTIME => {
                let height = u32::from_le_bytes(pair.fixed("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME")?);
                if height == 0 || height >= LOCKTIME_THRESHOLD {
                    return Err(invalid(
                        "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME is not between 1 and 499999999",
                    ));
                }
                required_height = Some(height);
            }
            _ => rest.push(pair),
        }
    }
    let txin = TxIn {
        previous_output: OutPoint {
            txid: txid.ok_or_else(|| missing("PSBT_IN_PREVIOUS_TXID"))?,
            vout: vout.ok_or_else(|| missing("PSBT_IN_OUTPUT_INDEX"))?,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(sequence.unwrap_or(u32::MAX)),
        witness: Witness::new(),
    };
    let v2_input = V2Input {
        has_sequence: sequence.is_some(),
        required_time,
        required_height,
    };
    Ok((txin, v2_input, rest))
}

fn read_output(pairs: Vec<Pair>) -> Result<(TxOut, Vec<Pair>), VersionedPsbtError> {
    let mut amount = None;
    let mut script = None;
    let mut rest = Vec::new();
    for pair in pairs {
        match pair.key_type {
            OUT_AMOUNT => {
                let sats = i64::from_le_bytes(pair.fixed("PSBT_OUT_AMOUNT")?);
                let sats =
                    u64::try_from(sats).map_err(|_| invalid("PSBT_OUT_AMOUNT is negative"))?;
                amount = Some(Amount::from_sat(sats));
            }
            OUT_SCRIPT => {
                pair.no_key_data("PSBT_OUT_SCRIPT")?;
                script = Some(ScriptBuf::from_bytes(pair.value));
            }
            _ => rest.push(pair),
        }
    }
    let txout = TxOut {
        value: amount.ok_or_else(|| missing("PSBT_OUT_AMOUNT"))?,
        script_pubkey: script.ok_or_else(|| missing("PSBT_OUT_SCRIPT"))?,
    };
    Ok((txout, rest))
}

/// BIP 370 "Determining Lock Time".
fn lock_time(fallback: Option<u32>, inputs: &[V2Input]) -> Result<u32, VersionedPsbtError> {
    if inputs
        .iter()
        .all(|i| i.required_time.is_none() && i.required_height.is_none())
    {
        return Ok(fallback.unwrap_or(0));
    }
    let height_for_all = inputs
        .iter()
        .all(|i| i.required_height.is_some() || i.required_time.is_none());
    let time_for_all = inputs
        .iter()
        .all(|i| i.required_time.is_some() || i.required_height.is_none());
    let max =
        |field: fn(&V2Input) -> Option<u32>| inputs.iter().filter_map(field).max().unwrap_or(0);
    if height_for_all {
        Ok(max(|i| i.required_height))
    } else if time_for_all {
        Ok(max(|i| i.required_time))
    } else {
        Err(invalid(
            "PSBTv2 inputs require both a time and a height lock time",
        ))
    }
}

fn serialize_v2(psbt: &Psbt, v2: &V2Fields) -> Vec<u8> {
    let v0 = psbt.serialize();
    let mut reader = Reader::new(&v0).expect("rust-bitcoin writes the PSBT magic");
    let mut maps =
        std::iter::from_fn(|| Some(reader.map().expect("rust-bitcoin writes valid maps")));
    let tx = &psbt.unsigned_tx;

    // Places each v2 field where Python HWI writes it, so `hwi` output matches it byte for byte.
    let global = maps.next().expect("a PSBT has a global map");
    let (xpubs, global_rest): (Vec<_>, Vec<_>) = global
        .into_iter()
        .filter(|pair| pair.key_type != GLOBAL_UNSIGNED_TX)
        .partition(|pair| pair.key_type == GLOBAL_XPUB);
    let mut fields = vec![Pair::new(
        GLOBAL_TX_VERSION,
        tx.version.0.to_le_bytes().to_vec(),
    )];
    if let Some(fallback) = v2.fallback_lock_time {
        fields.push(Pair::new(
            GLOBAL_FALLBACK_LOCKTIME,
            fallback.to_le_bytes().to_vec(),
        ));
    }
    fields.push(Pair::new(
        GLOBAL_INPUT_COUNT,
        serialize(&VarInt(tx.input.len() as u64)),
    ));
    fields.push(Pair::new(
        GLOBAL_OUTPUT_COUNT,
        serialize(&VarInt(tx.output.len() as u64)),
    ));
    if let Some(flags) = v2.tx_modifiable {
        fields.push(Pair::new(GLOBAL_TX_MODIFIABLE, vec![flags]));
    }
    fields.push(Pair::new(GLOBAL_VERSION, 2u32.to_le_bytes().to_vec()));

    let mut out = MAGIC.to_vec();
    write_pairs(&mut out, &xpubs);
    write_pairs(&mut out, &fields);
    write_map(&mut out, &global_rest);

    for (txin, v2_input) in tx.input.iter().zip(&v2.inputs) {
        let pairs = maps.next().expect("a PSBT has one map per input");
        let split = pairs
            .iter()
            .position(|pair| !rust_bitcoin_input_field(pair.key_type));
        let (head, tail) = pairs.split_at(split.unwrap_or(pairs.len()));
        let mut fields = vec![
            Pair::new(IN_PREVIOUS_TXID, serialize(&txin.previous_output.txid)),
            Pair::new(
                IN_OUTPUT_INDEX,
                txin.previous_output.vout.to_le_bytes().to_vec(),
            ),
        ];
        if v2_input.has_sequence {
            fields.push(Pair::new(
                IN_SEQUENCE,
                txin.sequence.0.to_le_bytes().to_vec(),
            ));
        }
        if let Some(time) = v2_input.required_time {
            fields.push(Pair::new(
                IN_REQUIRED_TIME_LOCKTIME,
                time.to_le_bytes().to_vec(),
            ));
        }
        if let Some(height) = v2_input.required_height {
            fields.push(Pair::new(
                IN_REQUIRED_HEIGHT_LOCKTIME,
                height.to_le_bytes().to_vec(),
            ));
        }
        write_pairs(&mut out, head);
        write_pairs(&mut out, &fields);
        write_map(&mut out, tail);
    }

    for txout in &tx.output {
        let pairs = maps.next().expect("a PSBT has one map per output");
        let split = pairs
            .iter()
            .position(|pair| pair.key_type > OUT_BIP32_DERIVATION);
        let (head, tail) = pairs.split_at(split.unwrap_or(pairs.len()));
        let fields = [
            Pair::new(OUT_AMOUNT, serialize(&txout.value)),
            Pair::new(OUT_SCRIPT, txout.script_pubkey.to_bytes()),
        ];
        write_pairs(&mut out, head);
        write_pairs(&mut out, &fields);
        write_map(&mut out, tail);
    }
    out
}

fn rust_bitcoin_input_field(key_type: u64) -> bool {
    matches!(key_type, 0x00..=0x08 | 0x0a..=0x0d | 0x13..=0x18)
}

struct Pair {
    key_type: u64,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Pair {
    fn new(key_type: u64, value: Vec<u8>) -> Self {
        Self {
            key_type,
            key: serialize(&VarInt(key_type)),
            value,
        }
    }

    fn no_key_data(&self, field: &str) -> Result<(), VersionedPsbtError> {
        if self.key.len() == serialize(&VarInt(self.key_type)).len() {
            Ok(())
        } else {
            Err(invalid(format!("{field} has key data")))
        }
    }

    fn fixed<const N: usize>(&self, field: &str) -> Result<[u8; N], VersionedPsbtError> {
        self.no_key_data(field)?;
        self.value
            .as_slice()
            .try_into()
            .map_err(|_| invalid(format!("{field} is not {N} bytes")))
    }

    fn count(&self, field: &str) -> Result<u64, VersionedPsbtError> {
        self.no_key_data(field)?;
        match deserialize_partial::<VarInt>(&self.value) {
            Ok((count, read)) if read == self.value.len() => Ok(count.0),
            _ => Err(invalid(format!("{field} is not a compact size"))),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, VersionedPsbtError> {
        bytes
            .strip_prefix(MAGIC)
            .map(|bytes| Self { bytes })
            .ok_or_else(|| invalid("missing the PSBT magic bytes"))
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn compact_size(&mut self) -> Result<u64, VersionedPsbtError> {
        let (value, read) = deserialize_partial::<VarInt>(self.bytes)
            .map_err(|_| invalid("truncated or non-canonical compact size"))?;
        self.bytes = &self.bytes[read..];
        Ok(value.0)
    }

    fn take(&mut self, len: u64) -> Result<Vec<u8>, VersionedPsbtError> {
        let len = usize::try_from(len)
            .ok()
            .filter(|len| *len <= self.bytes.len())
            .ok_or_else(|| invalid("a PSBT map ends early"))?;
        let (taken, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(taken.to_vec())
    }

    fn map(&mut self) -> Result<Vec<Pair>, VersionedPsbtError> {
        let mut pairs: Vec<Pair> = Vec::new();
        let mut keys = HashSet::new();
        loop {
            let key_len = self.compact_size()?;
            if key_len == 0 {
                return Ok(pairs);
            }
            let key = self.take(key_len)?;
            let (key_type, _) = deserialize_partial::<VarInt>(&key)
                .map_err(|_| invalid("a PSBT key has no valid type"))?;
            let value_len = self.compact_size()?;
            let value = self.take(value_len)?;
            if !keys.insert(key.clone()) {
                return Err(invalid(format!(
                    "duplicate PSBT key of type {:#04x}",
                    key_type.0
                )));
            }
            pairs.push(Pair {
                key_type: key_type.0,
                key,
                value,
            });
        }
    }
}

fn write_pairs(out: &mut Vec<u8>, pairs: &[Pair]) {
    for pair in pairs {
        out.extend(serialize(&VarInt(pair.key.len() as u64)));
        out.extend(&pair.key);
        out.extend(serialize(&VarInt(pair.value.len() as u64)));
        out.extend(&pair.value);
    }
}

fn write_map(out: &mut Vec<u8>, pairs: &[Pair]) {
    write_pairs(out, pairs);
    out.push(0x00);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhwi::bitcoin::{
        EcdsaSighashType, PublicKey, ecdsa,
        secp256k1::{Message, Secp256k1, SecretKey},
    };
    use bitcoin::base64::prelude::{BASE64_STANDARD, Engine as _};
    use serde_json::Value;

    fn cases() -> Vec<Value> {
        let vectors: Value = serde_json::from_str(include_str!("bip370.json")).unwrap();
        vectors["cases"].as_array().unwrap().clone()
    }

    fn bytes(psbt: &Value) -> Vec<u8> {
        BASE64_STANDARD
            .decode(psbt["base64"].as_str().unwrap().trim())
            .unwrap()
    }

    fn vector(description: &str) -> VersionedPsbt {
        let case = cases()
            .into_iter()
            .find(|case| case["description"] == description)
            .unwrap();
        VersionedPsbt::deserialize(&bytes(&case["task"]["deserialize"]["psbt"])).unwrap()
    }

    fn new_v2(psbt: Psbt) -> VersionedPsbt {
        let input = V2Input {
            has_sequence: true,
            required_time: None,
            required_height: None,
        };
        let v2 = V2Fields {
            fallback_lock_time: Some(psbt.unsigned_tx.lock_time.to_consensus_u32()),
            tx_modifiable: None,
            inputs: vec![input; psbt.inputs.len()],
        };
        VersionedPsbt { psbt, v2: Some(v2) }
    }

    #[test]
    fn bip370_vectors() {
        for case in cases() {
            let description = case["description"].as_str().unwrap();
            let (task, body) = case["task"].as_object().unwrap().iter().next().unwrap();
            let parse = |psbt: &Value| VersionedPsbt::deserialize(&bytes(psbt));
            match task.as_str() {
                "deserialize" => {
                    let psbt =
                        parse(&body["psbt"]).unwrap_or_else(|e| panic!("{description}: {e}"));
                    assert_eq!(psbt.serialize(), bytes(&body["psbt"]), "{description}");
                }
                "fail_deserialize" | "fail_determine_lock_time" => {
                    assert!(parse(&body["psbt"]).is_err(), "{description}");
                }
                "determine_lock_time" => {
                    for psbt in body["psbts"].as_array().unwrap() {
                        let psbt = parse(psbt).unwrap_or_else(|e| panic!("{description}: {e}"));
                        let lock_time = psbt.as_psbt_v0().unsigned_tx.lock_time.to_consensus_u32();
                        assert_eq!(lock_time, body["expected_lock_time"], "{description}");
                    }
                }
                task => panic!("{description}: unknown task {task}"),
            }
        }
    }

    #[test]
    fn a_version_0_psbt_stays_version_0() {
        let v2 = vector("Valid: 1 input, 2 output updated PSBTv2.");
        let v0_bytes = v2.as_psbt_v0().serialize();
        let v0 = VersionedPsbt::deserialize(&v0_bytes).unwrap();
        assert_eq!((v2.version(), v0.version()), (2, 0));
        assert_eq!(v0.serialize(), v0_bytes);

        let rewritten = VersionedPsbt::deserialize(&new_v2(v0.as_psbt_v0().clone()).serialize());
        assert_eq!(rewritten.unwrap().as_psbt_v0(), v0.as_psbt_v0());
    }

    #[test]
    fn a_new_signature_is_written_back_as_v2() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let key = PublicKey::new(secret.public_key(&secp));
        let signature = secp.sign_ecdsa(&Message::from_digest([2; 32]), &secret);
        let psbt_to_sign = vector(
            "Valid: 1 input, 2 output updated PSBTv2, with both Inputs Modifiable Flag (bit 0) and Outputs Modifiable Flag (bit 1) of PSBT_GLOBAL_TX_MODIFIABLE set",
        );
        let mut signed_psbt_from_device = psbt_to_sign.as_psbt_v0().clone();
        signed_psbt_from_device.inputs[0].partial_sigs.insert(
            key,
            ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
        let signed_psbt = psbt_to_sign
            .restore_version(signed_psbt_from_device)
            .unwrap();
        let reread = VersionedPsbt::deserialize(&signed_psbt.serialize()).unwrap();
        assert_eq!(reread.version(), 2);
        assert!(
            reread.as_psbt_v0().inputs[0]
                .partial_sigs
                .contains_key(&key)
        );
        assert_eq!(reread.v2.unwrap().tx_modifiable, Some(0x03));
    }

    #[test]
    fn a_signed_psbt_for_another_transaction_is_refused() {
        let psbt_to_sign = vector("Valid: 1 input, 2 output updated PSBTv2.");
        let mut signed_psbt_from_device = psbt_to_sign.as_psbt_v0().clone();
        signed_psbt_from_device.unsigned_tx.lock_time = LockTime::from_consensus(1);
        assert!(matches!(
            psbt_to_sign.restore_version(signed_psbt_from_device),
            Err(VersionedPsbtError::TransactionChanged)
        ));
    }

    #[test]
    fn inconsistent_previous_outputs_are_refused() {
        let secp = Secp256k1::new();
        let key = PublicKey::new(SecretKey::from_slice(&[1; 32]).unwrap().public_key(&secp));
        let script_pubkey = ScriptBuf::new_p2pkh(&key.pubkey_hash());
        let output = |sats: u64| TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: script_pubkey.clone(),
        };
        let previous_tx = |sats: u64| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![output(sats)],
        };
        let real_previous_tx = previous_tx(10_000_000_000);
        let psbt = |vout: u32, non_witness_utxo: Transaction, witness_utxo: Option<TxOut>| {
            let unsigned_tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: real_previous_tx.compute_txid(),
                        vout,
                    },
                    ..TxIn::default()
                }],
                output: vec![output(90_000_000)],
            };
            let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
            psbt.inputs[0].non_witness_utxo = Some(non_witness_utxo);
            psbt.inputs[0].witness_utxo = witness_utxo;
            psbt
        };
        let cases = [
            (
                psbt(0, real_previous_tx.clone(), Some(output(10_000_000_000))),
                None,
            ),
            (
                psbt(0, real_previous_tx.clone(), Some(output(100_000_000))),
                Some("witness_utxo and non_witness_utxo disagree"),
            ),
            (
                psbt(0, previous_tx(100_000_000), None),
                Some("non_witness_utxo does not match the prevout txid"),
            ),
            (
                psbt(1, real_previous_tx.clone(), None),
                Some("non_witness_utxo has no output 1"),
            ),
        ];
        for (psbt, refusal) in cases {
            for bytes in [psbt.serialize(), new_v2(psbt.clone()).serialize()] {
                let result = VersionedPsbt::deserialize(&bytes);
                match refusal {
                    None => {
                        result.unwrap();
                    }
                    Some(refusal) => assert!(
                        result.unwrap_err().to_string().contains(refusal),
                        "{refusal}"
                    ),
                }
            }
        }
    }
}
