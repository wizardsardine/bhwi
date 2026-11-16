use std::collections::BTreeMap;

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, VarInt, Witness, absolute,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    consensus::{Decodable, deserialize, serialize},
    psbt::Psbt,
    transaction,
};

type Map = BTreeMap<Vec<u8>, Vec<u8>>;
type Result<T, E = String> = std::result::Result<T, E>;

pub(super) struct SigningPsbt {
    pub(super) backend: Psbt,
    original: Option<Vec<Map>>,
}

fn compact(bytes: &mut &[u8]) -> Result<usize> {
    let value = VarInt::consensus_decode(bytes)
        .map_err(|e| e.to_string())?
        .0;
    usize::try_from(value).map_err(|_| "PSBT length overflow".into())
}

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if len > bytes.len() {
        return Err("Truncated PSBT field".into());
    }
    let (value, rest) = bytes.split_at(len);
    *bytes = rest;
    Ok(value)
}

fn read_pair<'a>(bytes: &mut &'a [u8]) -> Result<Option<(&'a [u8], &'a [u8])>> {
    let len = compact(bytes)?;
    if len == 0 {
        return Ok(None);
    }
    let key = take(bytes, len)?;
    let mut key_bytes = key;
    let key_type = compact(&mut key_bytes)?;
    if key_type == 0xfc {
        let identifier_len = compact(&mut key_bytes)?;
        take(&mut key_bytes, identifier_len)?;
        compact(&mut key_bytes)?;
    }
    let len = compact(bytes)?;
    Ok(Some((key, take(bytes, len)?)))
}

fn read_map(bytes: &mut &[u8]) -> Result<Map> {
    let mut map = Map::new();
    while let Some((key, value)) = read_pair(bytes)? {
        if map.insert(key.to_vec(), value.to_vec()).is_some() {
            return Err("Duplicate PSBT key".into());
        }
    }
    Ok(map)
}

fn encode(maps: &[Map]) -> Vec<u8> {
    let mut bytes = b"psbt\xff".to_vec();
    for map in maps {
        for (key, value) in map {
            bytes.extend(serialize(&VarInt(key.len() as u64)));
            bytes.extend(key);
            bytes.extend(serialize(&VarInt(value.len() as u64)));
            bytes.extend(value);
        }
        bytes.push(0);
    }
    bytes
}

fn field(map: &Map, key: u8) -> Result<&[u8]> {
    map.get([key].as_slice())
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Missing PSBT field {key:#x}"))
}

fn number(map: &Map, key: u8) -> Result<u32> {
    deserialize(field(map, key)?).map_err(|e| e.to_string())
}

fn optional_number(map: &Map, key: u8) -> Result<Option<u32>> {
    map.get([key].as_slice())
        .map(|_| number(map, key))
        .transpose()
}

fn count(map: &Map, key: u8) -> Result<usize> {
    let mut bytes = field(map, key)?;
    let count = compact(&mut bytes)?;
    if !bytes.is_empty() {
        return Err("Trailing PSBT count data".into());
    }
    Ok(count)
}

fn validate_keys(map: &Map, fields: &[u8], version: u32) -> Result<()> {
    for key in map.keys() {
        if fields.contains(&key[0]) && (version == 0 || key.len() != 1) {
            return Err("PSBT version-specific field or invalid key data".into());
        }
    }
    Ok(())
}

impl SigningPsbt {
    pub(super) fn parse(text: &str) -> Result<Self> {
        let data = BASE64_STANDARD.decode(text).map_err(|e| e.to_string())?;
        let payload = data.strip_prefix(b"psbt\xff").ok_or("Invalid PSBT magic")?;
        let mut bytes = payload;
        let mut version = 0;
        while let Some((key, value)) = read_pair(&mut bytes)? {
            if matches!(key[0], 0 | 0xfb) && key.len() != 1 {
                return Err("Invalid global PSBT key data".into());
            }
            if key == [0xfb] {
                version = deserialize::<u32>(value).map_err(|e| e.to_string())?;
            }
        }
        if version == 0 {
            let backend = Psbt::deserialize(&data).map_err(|e| e.to_string())?;
            let excluded = |map: &BTreeMap<bitcoin::psbt::raw::Key, Vec<u8>>, fields: &[u8]| {
                map.keys().any(|key| fields.contains(&key.type_value))
            };
            if excluded(&backend.unknown, &[2, 3, 4, 5, 6])
                || backend
                    .inputs
                    .iter()
                    .any(|input| excluded(&input.unknown, &[0x0e, 0x0f, 0x10, 0x11, 0x12]))
                || backend
                    .outputs
                    .iter()
                    .any(|output| excluded(&output.unknown, &[3, 4]))
            {
                return Err("PSBT version-specific field".into());
            }
            for _ in 0..backend.inputs.len() + backend.outputs.len() {
                while read_pair(&mut bytes)?.is_some() {}
            }
            if !bytes.is_empty() {
                return Err("Trailing PSBT data".into());
            }
            return Ok(Self {
                backend,
                original: None,
            });
        }
        if version != 2 {
            return Err("Unsupported PSBT version".into());
        }
        let mut bytes = payload;
        let global = read_map(&mut bytes)?;
        validate_keys(&global, &[2, 3, 4, 5, 6], version)?;
        if global.contains_key([0].as_slice()) {
            return Err("PSBTv2 must exclude unsigned transaction".into());
        }
        let (input_count, output_count) = (count(&global, 4)?, count(&global, 5)?);
        if input_count
            .checked_add(output_count)
            .ok_or("PSBT count overflow")?
            > bytes.len()
        {
            return Err("Truncated PSBT maps".into());
        }
        let mut maps = vec![global];
        for _ in 0..input_count {
            let map = read_map(&mut bytes)?;
            validate_keys(&map, &[0x0e, 0x0f, 0x10, 0x11, 0x12], version)?;
            maps.push(map);
        }
        for _ in 0..output_count {
            let map = read_map(&mut bytes)?;
            validate_keys(&map, &[3, 4], version)?;
            maps.push(map);
        }
        if !bytes.is_empty() {
            return Err("Trailing PSBT data".into());
        }
        if let Some(flags) = maps[0].get([6].as_slice())
            && flags.len() != 1
        {
            return Err("Invalid transaction modifiable flags".into());
        }
        let fallback = optional_number(&maps[0], 3)?.unwrap_or(0);
        let mut height = Some(0);
        let mut time = Some(0);
        let mut required_locktime = false;
        let mut inputs = Vec::with_capacity(input_count);
        for map in &maps[1..1 + input_count] {
            let required_height = optional_number(map, 0x12)?;
            let required_time = optional_number(map, 0x11)?;
            if required_height.is_some_and(|n| n == 0 || n >= 500_000_000)
                || required_time.is_some_and(|n| n < 500_000_000)
            {
                return Err("Invalid required locktime".into());
            }
            if required_height.is_some() || required_time.is_some() {
                required_locktime = true;
                height = height.zip(required_height).map(|(a, b)| a.max(b));
                time = time.zip(required_time).map(|(a, b)| a.max(b));
            }
            inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: deserialize(field(map, 0x0e)?).map_err(|e| e.to_string())?,
                    vout: number(map, 0x0f)?,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(optional_number(map, 0x10)?.unwrap_or(u32::MAX)),
                witness: Witness::new(),
            });
        }
        let locktime = if required_locktime {
            height.or(time).ok_or("Incompatible required locktimes")?
        } else {
            fallback
        };
        let mut outputs = Vec::with_capacity(output_count);
        for map in &maps[1 + input_count..] {
            let amount: i64 = deserialize(field(map, 3)?).map_err(|e| e.to_string())?;
            let amount = u64::try_from(amount).map_err(|_| "Negative output amount")?;
            outputs.push(TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::from_bytes(field(map, 4)?.to_vec()),
            });
        }
        let tx = Transaction {
            version: transaction::Version(number(&maps[0], 2)? as i32),
            lock_time: absolute::LockTime::from_consensus(locktime),
            input: inputs,
            output: outputs,
        };
        let mut converted = maps.clone();
        converted[0].retain(|key, _| !matches!(key[0], 2..=6 | 0xfb));
        let mut unsigned = serialize(&tx.version);
        unsigned.extend(serialize(&tx.input));
        unsigned.extend(serialize(&tx.output));
        unsigned.extend(serialize(&tx.lock_time));
        converted[0].insert(vec![0], unsigned);
        for map in &mut converted[1..1 + input_count] {
            map.retain(|key, _| !matches!(key[0], 0x0e..=0x12));
        }
        for map in &mut converted[1 + input_count..] {
            map.retain(|key, _| !matches!(key[0], 3 | 4));
        }
        let backend = Psbt::deserialize(&encode(&converted)).map_err(|e| e.to_string())?;
        Ok(Self {
            backend,
            original: Some(maps),
        })
    }

    pub(super) fn finish(&self, signed: &Psbt) -> Result<String> {
        let Some(original) = &self.original else {
            return Ok(signed.to_string());
        };
        if signed.unsigned_tx != self.backend.unsigned_tx
            || signed.inputs.len() != self.backend.inputs.len()
        {
            return Err("Signer changed the unsigned transaction".into());
        }
        let mut maps = original.clone();
        let serialized = signed.serialize();
        let mut bytes = &serialized[5..];
        read_map(&mut bytes)?;
        let mut flags = maps[0].get([6].as_slice()).map(|v| v[0]);
        for map in maps.iter_mut().skip(1).take(signed.inputs.len()) {
            let result = read_map(&mut bytes)?;
            for (key, value) in result {
                if !matches!(key[0], 2 | 7 | 8 | 0x13 | 0x14) || map.contains_key(&key) {
                    continue;
                }
                let sighash = match key[0] {
                    2 => value.last().copied(),
                    0x13 | 0x14 => Some(if value.len() == 64 {
                        0
                    } else {
                        *value.last().ok_or("Empty signature")?
                    }),
                    _ => None,
                };
                if let Some(sighash) = sighash {
                    let current = flags.get_or_insert(0);
                    if sighash & 0x80 == 0 {
                        *current &= !1;
                    }
                    if sighash & 3 != 2 {
                        *current &= !2;
                    }
                    if sighash & 3 == 3 {
                        *current |= 4;
                    }
                }
                map.insert(key, value);
            }
        }
        if let Some(flags) = flags
            && (flags != 0 || maps[0].contains_key([6].as_slice()))
        {
            maps[0].insert(vec![6], vec![flags]);
        }
        Ok(BASE64_STANDARD.encode(encode(&maps)))
    }
}

#[cfg(test)]
mod tests;
