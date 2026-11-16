use super::*;

fn fixture(inputs: usize) -> Vec<Map> {
    let mut maps = vec![Map::from([
        (vec![2], 2u32.to_le_bytes().to_vec()),
        (vec![4], serialize(&VarInt(inputs as u64))),
        (vec![5], vec![1]),
        (vec![0xfb], 2u32.to_le_bytes().to_vec()),
    ])];
    for index in 0..inputs {
        maps.push(Map::from([
            (vec![0x0e], vec![index as u8 + 1; 32]),
            (vec![0x0f], (index as u32).to_le_bytes().to_vec()),
        ]));
    }
    maps.push(Map::from([
        (vec![3], 42i64.to_le_bytes().to_vec()),
        (vec![4], vec![0x51]),
    ]));
    maps
}

fn text(maps: &[Map]) -> String {
    BASE64_STANDARD.encode(encode(maps))
}

fn parse(maps: &[Map]) -> SigningPsbt {
    SigningPsbt::parse(&text(maps)).unwrap()
}

fn decode(text: &str) -> Vec<Map> {
    let data = BASE64_STANDARD.decode(text).unwrap();
    let mut bytes = &data[5..];
    let mut maps = Vec::new();
    while !bytes.is_empty() {
        maps.push(read_map(&mut bytes).unwrap());
    }
    maps
}

fn backend_maps(psbt: &Psbt) -> Vec<Map> {
    decode(&psbt.to_string())
}

fn signed_with(psbt: &Psbt, entries: &[(Vec<u8>, Vec<u8>)]) -> Psbt {
    let mut maps = backend_maps(psbt);
    maps[1].extend(entries.iter().cloned());
    Psbt::deserialize(&encode(&maps)).unwrap()
}

fn public_key() -> Vec<u8> {
    bitcoin::PublicKey::from_slice(&[
        2, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ])
    .unwrap()
    .to_bytes()
}

fn signature(kind: u8, sighash: u8) -> (Vec<u8>, Vec<u8>) {
    let mut key = vec![kind];
    let value = if kind == 2 {
        key.extend(public_key());
        vec![0x30, 6, 2, 1, 1, 2, 1, 1, sighash]
    } else {
        if kind == 0x14 {
            key.extend(&public_key()[1..]);
            key.extend([0; 32]);
        }
        let mut value = vec![1; 64];
        if sighash != 0 {
            value.push(sighash);
        }
        value
    };
    (key, value)
}

#[test]
fn required_and_optional_fields_and_metadata_survive_roundtrip() {
    let mut maps = fixture(1);
    maps[0].insert(vec![3], 123u32.to_le_bytes().to_vec());
    maps[0].insert(vec![6], vec![0xff]);
    maps[1].insert(vec![0x10], 0xffff_fffeu32.to_le_bytes().to_vec());
    maps[1].insert(vec![0x11], 500_000_001u32.to_le_bytes().to_vec());
    maps[1].insert(vec![0x12], 10u32.to_le_bytes().to_vec());
    maps[1].insert(
        vec![1],
        serialize(&TxOut {
            value: Amount::from_sat(100),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }),
    );
    maps[1].insert(vec![3], 1u32.to_le_bytes().to_vec());
    maps[1].insert(vec![4], vec![0x51]);
    maps[1].insert(vec![5], vec![0x51]);
    let mut derivation = vec![6];
    derivation.extend(public_key());
    maps[1].insert(derivation, vec![0; 8]);
    maps[1].insert(vec![0x17], public_key()[1..].to_vec());
    maps[2].insert(vec![0], vec![0x51]);
    maps[2].insert(vec![1], vec![0x51]);
    for map in &mut maps {
        map.insert(vec![0x50, 0xaa], vec![0, 1, 0xff]);
        map.insert(vec![0xfc, 1, b'x', 7, 9], vec![3, 2, 1]);
    }
    let parsed = parse(&maps);
    assert_eq!(parsed.backend.unsigned_tx.version.0, 2);
    assert_eq!(parsed.backend.unsigned_tx.lock_time.to_consensus_u32(), 10);
    assert_eq!(parsed.backend.unsigned_tx.input[0].sequence.0, 0xffff_fffe);
    assert_eq!(parsed.backend.unsigned_tx.output[0].value.to_sat(), 42);
    assert_eq!(decode(&parsed.finish(&parsed.backend).unwrap()), maps);
    let entry = signature(2, 1);
    let signed = signed_with(&parsed.backend, std::slice::from_ref(&entry));
    let mut expected = maps;
    expected[0].insert(vec![6], vec![0xfc]);
    expected[1].insert(entry.0, entry.1);
    assert_eq!(decode(&parsed.finish(&signed).unwrap()), expected);
}

#[test]
fn unsigned_psbt_stays_unchanged_with_optional_flags_absent_or_present() {
    for flags in [None, Some(0), Some(3), Some(0xff)] {
        let mut maps = fixture(1);
        if let Some(flags) = flags {
            maps[0].insert(vec![6], vec![flags]);
        }
        let parsed = parse(&maps);
        assert_eq!(decode(&parsed.finish(&parsed.backend).unwrap()), maps);
        assert_eq!(parsed.backend.unsigned_tx.input[0].sequence, Sequence::MAX);
        assert_eq!(
            parsed.backend.unsigned_tx.lock_time,
            absolute::LockTime::ZERO
        );
    }
}

#[test]
fn signatures_update_modifiable_bits_and_preserve_signature_encodings() {
    for kind in [2, 0x13, 0x14] {
        for (sighash, flags) in [
            (1, 0xfc),
            (2, 0xfe),
            (3, 0xfc),
            (0x81, 0xfd),
            (0x82, 0xff),
            (0x83, 0xfd),
        ] {
            let mut maps = fixture(1);
            maps[0].insert(vec![6], vec![0xff]);
            let parsed = parse(&maps);
            let entry = signature(kind, sighash);
            let signed = signed_with(&parsed.backend, std::slice::from_ref(&entry));
            maps[0].insert(vec![6], vec![flags]);
            maps[1].insert(entry.0, entry.1);
            assert_eq!(
                decode(&parsed.finish(&signed).unwrap()),
                maps,
                "kind={kind} sighash={sighash}"
            );
        }
    }
    for kind in [0x13, 0x14] {
        let maps = fixture(1);
        let parsed = parse(&maps);
        let entry = signature(kind, 0);
        let signed = signed_with(&parsed.backend, std::slice::from_ref(&entry));
        let result = decode(&parsed.finish(&signed).unwrap());
        assert_eq!(result[0].get(&vec![6]), None);
        assert_eq!(result[1].get(&entry.0), Some(&entry.1));
    }
}

#[test]
fn newly_added_signatures_restrict_but_never_reenable_modification() {
    let entries = [signature(2, 1), signature(0x13, 0x82), signature(0x14, 3)];
    let mut maps = fixture(1);
    maps[0].insert(vec![6], vec![3]);
    let parsed = parse(&maps);
    let signed = signed_with(&parsed.backend, &entries);
    let result = decode(&parsed.finish(&signed).unwrap());
    assert_eq!(result[0].get(&vec![6]), Some(&vec![4]));
    for (key, value) in entries {
        assert_eq!(result[1].get(&key), Some(&value));
    }
    let mut existing = fixture(1);
    existing[0].insert(vec![6], vec![3]);
    let entry = signature(2, 1);
    existing[1].insert(entry.0, entry.1);
    let parsed = parse(&existing);
    assert_eq!(decode(&parsed.finish(&parsed.backend).unwrap()), existing);
}

#[test]
fn conflicting_existing_signatures_preserve_exact_values_and_modifiable_flags() {
    for kind in [2, 0x13, 0x14] {
        for flags in [None, Some(0xff)] {
            let mut maps = fixture(1);
            if let Some(flags) = flags {
                maps[0].insert(vec![6], vec![flags]);
            }
            let existing = signature(kind, 3);
            maps[1].insert(existing.0.clone(), existing.1.clone());
            let parsed = parse(&maps);
            let mut replacement = existing.clone();
            if kind == 2 {
                replacement.1[7] = 2;
            } else {
                replacement.1[0] = 2;
            }
            assert_ne!(existing.1, replacement.1);
            let signed = signed_with(&parsed.backend, &[replacement]);
            assert_eq!(
                decode(&parsed.finish(&signed).unwrap()),
                maps,
                "kind={kind} flags={flags:?}"
            );
        }
    }
}

#[test]
fn locktime_defaults_maximum_compatibility_and_height_tiebreak() {
    let cases = [
        (None, vec![(None, None)], Some(0)),
        (Some(600_000_000), vec![(None, None)], Some(600_000_000)),
        (Some(7), vec![(Some(10), None), (None, None)], Some(10)),
        (
            Some(u32::MAX),
            vec![(Some(10), None), (Some(20), None)],
            Some(20),
        ),
        (
            None,
            vec![(None, Some(500_000_000)), (None, Some(u32::MAX))],
            Some(u32::MAX),
        ),
        (
            None,
            vec![(Some(10), Some(500_000_001)), (Some(20), Some(500_000_000))],
            Some(20),
        ),
        (
            None,
            vec![(Some(10), None), (Some(20), Some(500_000_000))],
            Some(20),
        ),
        (
            None,
            vec![(Some(10), Some(500_000_001)), (None, Some(500_000_000))],
            Some(500_000_001),
        ),
        (
            None,
            vec![(None, None), (None, Some(500_000_000))],
            Some(500_000_000),
        ),
        (
            Some(10),
            vec![(Some(10), None), (None, Some(500_000_000))],
            None,
        ),
    ];
    for (fallback, locks, expected) in cases {
        let mut maps = fixture(locks.len());
        if let Some(fallback) = fallback {
            maps[0].insert(vec![3], u32::to_le_bytes(fallback).to_vec());
        }
        for (index, (height, time)) in locks.into_iter().enumerate() {
            for (key, value) in [(0x12, height), (0x11, time)] {
                if let Some(value) = value {
                    maps[index + 1].insert(vec![key], u32::to_le_bytes(value).to_vec());
                }
            }
        }
        match expected {
            Some(expected) => assert_eq!(
                parse(&maps)
                    .backend
                    .unsigned_tx
                    .lock_time
                    .to_consensus_u32(),
                expected
            ),
            None => assert!(SigningPsbt::parse(&text(&maps)).is_err()),
        }
    }
}

#[test]
fn missing_required_fields_and_invalid_fixed_width_values_are_rejected() {
    for (index, key) in [
        (0, 2),
        (0, 4),
        (0, 5),
        (0, 0xfb),
        (1, 0x0e),
        (1, 0x0f),
        (2, 3),
        (2, 4),
    ] {
        let mut maps = fixture(1);
        maps[index].remove(&vec![key]);
        assert!(
            SigningPsbt::parse(&text(&maps)).is_err(),
            "missing {index}:{key}"
        );
    }
    for (index, key, width) in [
        (0, 2, 4),
        (0, 3, 4),
        (0, 6, 1),
        (0, 0xfb, 4),
        (1, 0x0e, 32),
        (1, 0x0f, 4),
        (1, 0x10, 4),
        (1, 0x11, 4),
        (1, 0x12, 4),
        (2, 3, 8),
    ] {
        for length in [0, width - 1, width + 1] {
            let mut maps = fixture(1);
            maps[index].insert(vec![key], vec![0; length]);
            assert!(
                SigningPsbt::parse(&text(&maps)).is_err(),
                "width {index}:{key}:{length}"
            );
        }
    }
    for (key, value) in [(0x11, 499_999_999u32), (0x12, 0), (0x12, 500_000_000)] {
        let mut maps = fixture(1);
        maps[1].insert(vec![key], value.to_le_bytes().to_vec());
        assert!(SigningPsbt::parse(&text(&maps)).is_err());
    }
    let mut maps = fixture(1);
    maps[2].insert(vec![3], (-1i64).to_le_bytes().to_vec());
    assert!(SigningPsbt::parse(&text(&maps)).is_err());
}

#[test]
fn key_data_counts_versions_and_unsigned_transaction_exclusion_are_checked() {
    for (index, key) in [
        (0, 2),
        (0, 3),
        (0, 4),
        (0, 5),
        (0, 6),
        (0, 0xfb),
        (1, 0x0e),
        (1, 0x0f),
        (1, 0x10),
        (1, 0x11),
        (1, 0x12),
        (2, 3),
        (2, 4),
    ] {
        let mut maps = fixture(1);
        maps[index].insert(vec![key, 0], vec![0; 4]);
        assert!(
            SigningPsbt::parse(&text(&maps)).is_err(),
            "key data {index}:{key}"
        );
    }
    for key in [4, 5] {
        for value in [
            vec![],
            vec![0],
            vec![2],
            vec![1, 0],
            vec![0xfd, 1, 0],
            vec![0xfe, 1, 0, 0, 0],
            vec![0xff; 9],
        ] {
            let mut maps = fixture(1);
            maps[0].insert(vec![key], value);
            assert!(SigningPsbt::parse(&text(&maps)).is_err());
        }
    }
    for version in [1u32, 3, u32::MAX] {
        let mut maps = fixture(1);
        maps[0].insert(vec![0xfb], version.to_le_bytes().to_vec());
        assert!(SigningPsbt::parse(&text(&maps)).is_err());
    }
    let mut maps = fixture(1);
    let unsigned_tx = serialize(&parse(&maps).backend.unsigned_tx);
    maps[0].insert(vec![0], unsigned_tx);
    assert!(SigningPsbt::parse(&text(&maps)).is_err());
}

#[test]
fn malformed_duplicate_noncanonical_and_truncated_encodings_are_rejected() {
    let data = encode(&fixture(1));
    for length in 0..data.len() {
        assert!(
            SigningPsbt::parse(&BASE64_STANDARD.encode(&data[..length])).is_err(),
            "prefix {length}"
        );
    }
    assert!(SigningPsbt::parse("not base64!").is_err());
    let mut bad_magic = data.clone();
    bad_magic[4] = 0;
    assert!(SigningPsbt::parse(&BASE64_STANDARD.encode(bad_magic)).is_err());
    for suffix in [vec![0], vec![1, 2, 3]] {
        let mut trailing = data.clone();
        trailing.extend(suffix);
        assert!(SigningPsbt::parse(&BASE64_STANDARD.encode(trailing)).is_err());
    }
    for replacement in [
        vec![0xfd, 1, 0],
        vec![0xfe, 1, 0, 0, 0],
        vec![0xff, 1, 0, 0, 0, 0, 0, 0, 0],
    ] {
        let mut noncanonical = data.clone();
        noncanonical.splice(5..6, replacement);
        assert!(SigningPsbt::parse(&BASE64_STANDARD.encode(noncanonical)).is_err());
    }
    let mut value_length = data.clone();
    value_length.splice(7..8, [0xfd, 4, 0]);
    assert!(SigningPsbt::parse(&BASE64_STANDARD.encode(value_length)).is_err());
    for entry in [
        vec![1, 2, 4, 2, 0, 0, 0],
        vec![1, 0xfd, 0],
        vec![3, 0xfd, 1, 0, 0],
    ] {
        let mut malformed = data.clone();
        malformed.splice(5..5, entry);
        assert!(SigningPsbt::parse(&BASE64_STANDARD.encode(malformed)).is_err());
    }
}

#[test]
fn v0_roundtrips_signatures_and_excludes_every_v2_only_field() {
    let backend = parse(&fixture(1)).backend;
    let parsed = SigningPsbt::parse(&backend.to_string()).unwrap();
    assert_eq!(parsed.backend, backend);
    assert_eq!(parsed.finish(&backend).unwrap(), backend.to_string());
    let signed = signed_with(&backend, &[signature(2, 1)]);
    assert_eq!(parsed.finish(&signed).unwrap(), signed.to_string());
    for (index, keys) in [
        (0, vec![2, 3, 4, 5, 6]),
        (1, vec![0x0e, 0x0f, 0x10, 0x11, 0x12]),
        (2, vec![3, 4]),
    ] {
        for key in keys {
            let mut maps = backend_maps(&backend);
            maps[index].insert(vec![key], vec![0; 4]);
            assert!(
                SigningPsbt::parse(&text(&maps)).is_err(),
                "v0 exclusion {index}:{key}"
            );
        }
    }
    let mut maps = backend_maps(&backend);
    maps[0].insert(vec![0xfb], vec![0; 4]);
    assert_eq!(parse(&maps).backend.unsigned_tx, backend.unsigned_tx);
}

#[test]
fn finish_rejects_signer_changes_to_unsigned_transaction() {
    let parsed = parse(&fixture(1));
    let mut changed = parsed.backend.clone();
    changed.unsigned_tx.output[0].value = Amount::from_sat(43);
    assert!(parsed.finish(&changed).is_err());
    let mut changed = parsed.backend.clone();
    changed.inputs.clear();
    assert!(parsed.finish(&changed).is_err());
}

#[test]
fn published_bip370_valid_vectors_roundtrip_without_metadata_loss() {
    let vectors = [
        (
            "1 input, 2 output PSBTv2, required fields only.",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2.",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA",
        ),
        (
            "1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE.",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE, and all locktime fields",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8BEQSMjcRiARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with Inputs Modifiable Flag (bit 0) of PSBT_GLOBAL_TX_MODIFIABLE set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEBAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with Outputs Modifiable Flag (bit 1) of PSBT_GLOBAL_TX_MODIFIABLE set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with Has SIGHASH_SINGLE Flag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEEAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with an undefined flag (bit 3) of PSBT_GLOBAL_TX_MODIFIABLE set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEIAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with both Inputs Modifiable Flag (bit 0) and Outputs Modifiable Flag (bit 1) of PSBT_GLOBAL_TX_MODIFIABLE set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEDAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with both Inputs Modifiable Flag (bit 0) and Has SIGHASH_SINGLE Flag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEFAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with both Outputs Modifiable Flag (bit 1) and Has SIGHASH_SINGLE FLag (bit 2) of PSBT_GLOBAL_TX_MODIFIABLE set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEGAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with all defined PSBT_GLOBAL_TX_MODIFIABLE flags set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgEHAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with all possible PSBT_GLOBAL_TX_MODIFIABLE flags set",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIBBgH/AfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "1 input, 2 output updated PSBTv2, with all PSBTv2 fields",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAQYBBwH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BDiALCtkhQZwchxlzXXLcc5+eqeBjjR/kwe7w+ZRAhIFfyAEPBAAAAAABEAT+////AREEjI3EYgESBBAnAAAAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAABBBYAFMQw9kxHVtoxDb0aCFVy7ymZJicsACICAuNvv/U91TQHDPj9OWYUaA81epuF23NAvxz6dF0q17NAGPadhz5UAACAAQAAgAAAAIABAAAAZAAAAAEDCIu96wsAAAAAAQQWABRN0ZOslkpWrBueHMqEVP4vR0+FEwA=",
        ),
    ];
    for (case, value) in vectors {
        let parsed = SigningPsbt::parse(value).unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_eq!(
            decode(&parsed.finish(&parsed.backend).unwrap()),
            decode(value),
            "{case}"
        );
    }
}

#[test]
fn published_bip370_invalid_vectors_are_rejected() {
    let vectors = [
        (
            "PSBTv0 but with PSBT_GLOBAL_VERSION set to 2.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_GLOBAL_TX_VERSION.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAECBAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_GLOBAL_FALLBACK_LOCKTIME.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEDBAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_GLOBAL_INPUT_COUNT.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEEAQIAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_GLOBAL_OUTPUT_COUNT.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEFAQIAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_GLOBAL_TX_MODIFIABLE.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEGAQAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_IN_PREVIOUS_TXID.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAACICA27+LCVWIZhlU7qdZcPdxkFlyhQ24FqjWkxusCRRz3ltGPadhz5UAACAAQAAgAAAAIABAAAAYgAAAAA=",
        ),
        (
            "PSBTv0 but with PSBT_IN_OUTPUT_INDEX.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_IN_SEQUENCE.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonARAE/////wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_IN_REQUIRED_TIME_LOCKTIME.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAREEjI3EYgAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv0 but with PSBT_OUT_AMOUNT.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAACICA27+LCVWIZhlU7qdZcPdxkFlyhQ24FqjWkxusCRRz3ltGPadhz5UAACAAQAAgAAAAIABAAAAYgAAAAA=",
        ),
        (
            "PSBTv0 but with PSBT_OUT_SCRIPT.",
            "cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEEFgAUoH2sirbKlC03nteV+DW6ccnMaIUAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==",
        ),
        (
            "PSBTv2 but with PSBT_GLOBAL_UNSIGNED_TX.",
            "cHNidP8BAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQIEAgAAAAEDBAAAAAABBAEBAQUBAgEGAQcB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wERBIyNxGIBEgQQJwAAACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA",
        ),
        (
            "PSBTv2 missing PSBT_GLOBAL_INPUT_COUNT.",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "PSBTv2 missing PSBT_GLOBAL_OUTPUT_COUNT.",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "PSBTv2 missing PSBT_GLOBAL_TX_VERSION.",
            "cHNidP8BBAEBAQUBAgH7BAIAAAAAAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA",
        ),
        (
            "PSBTv2 missing PSBT_IN_PREVIOUS_TXID.",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEPBAAAAAABEAT+////ACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA",
        ),
        (
            "PSBTv2 missing PSBT_IN_OUTPUT_INDEX.",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "PSBTv2 missing PSBT_OUT_AMOUNT.",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8AIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA",
        ),
        (
            "PSBTv2 missing PSBT_OUT_SCRIPT.",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8AIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAAAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "PSBTv2 with PSBT_IN_REQUIRED_TIME_LOCKTIME less than 500000000.",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAAREE/2TNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME greater than or equal to 500000000.",
            "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARIEAGXNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            "PSBTv2 with PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 0.",
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAQYBBwH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BDiALCtkhQZwchxlzXXLcc5+eqeBjjR/kwe7w+ZRAhIFfyAEPBAAAAAABEAT+////AREEjI3EYgESBAAAAAAAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAABBBYAFMQw9kxHVtoxDb0aCFVy7ymZJicsACICAuNvv/U91TQHDPj9OWYUaA81epuF23NAvxz6dF0q17NAGPadhz5UAACAAQAAgAAAAIABAAAAZAAAAAEDCIu96wsAAAAAAQQWABRN0ZOslkpWrBueHMqEVP4vR0+FEwA=",
        ),
    ];
    for (case, value) in vectors {
        assert!(SigningPsbt::parse(value).is_err(), "{case}");
    }
}

#[test]
fn published_bip370_locktime_vectors() {
    let vectors = [
        (
            Some(0),
            "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
        ),
        (
            Some(0),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAAAAQ4gOhs7PIN9ZInqejHY5sfdUDwAG+8+BpWOdXSAjWjKeKUBDwQAAAAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=",
        ),
        (
            Some(10000),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA",
        ),
        (
            Some(10000),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAESBCgjAAAAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA==",
        ),
        (
            Some(10000),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIBEgQoIwAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=",
        ),
        (
            Some(10000),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiARIEKCMAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA",
        ),
        (
            Some(1657048460),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIBEgQoIwAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=",
        ),
        (
            Some(1657048460),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=",
        ),
        (
            Some(1657048460),
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAAAAQ4gOhs7PIN9ZInqejHY5sfdUDwAG+8+BpWOdXSAjWjKeKUBDwQAAAAAAREEjI3EYgABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA",
        ),
        (
            None,
            "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA==",
        ),
    ];
    for (expected, value) in vectors {
        match expected {
            Some(expected) => assert_eq!(
                SigningPsbt::parse(value)
                    .unwrap()
                    .backend
                    .unsigned_tx
                    .lock_time
                    .to_consensus_u32(),
                expected
            ),
            None => assert!(SigningPsbt::parse(value).is_err()),
        }
    }
}

#[test]
fn finalization_fields_are_merged_without_dropping_required_v2_fields() {
    let mut maps = fixture(1);
    maps[1].insert(vec![0x10], 0xffff_fffeu32.to_le_bytes().to_vec());
    maps[1].insert(vec![0x12], 10u32.to_le_bytes().to_vec());
    let parsed = parse(&maps);
    let entries = [
        (vec![7], vec![0x51]),
        (vec![8], serialize(&Witness::from_slice(&[vec![1, 2]]))),
    ];
    let signed = signed_with(&parsed.backend, &entries);
    for (key, value) in entries {
        maps[1].insert(key, value);
    }
    assert_eq!(decode(&parsed.finish(&signed).unwrap()), maps);
}

#[test]
fn conflicting_existing_finalization_fields_preserve_exact_values() {
    let mut maps = fixture(1);
    maps[0].insert(vec![6], vec![0xff]);
    maps[1].insert(vec![7], vec![0x51]);
    maps[1].insert(vec![8], serialize(&Witness::from_slice(&[vec![1, 2]])));
    let parsed = parse(&maps);
    let signed = signed_with(
        &parsed.backend,
        &[
            (vec![7], vec![0x52]),
            (vec![8], serialize(&Witness::from_slice(&[vec![3, 4]]))),
        ],
    );
    assert_eq!(decode(&parsed.finish(&signed).unwrap()), maps);
}

#[test]
fn creator_psbt_with_zero_inputs_and_outputs_roundtrips() {
    let mut maps = fixture(0);
    maps.pop();
    maps[0].insert(vec![5], vec![0]);
    let parsed = parse(&maps);
    assert!(parsed.backend.unsigned_tx.input.is_empty());
    assert!(parsed.backend.unsigned_tx.output.is_empty());
    assert_eq!(decode(&parsed.finish(&parsed.backend).unwrap()), maps);
}

#[test]
fn absent_modifiable_flags_are_added_only_when_single_requires_pairing() {
    for kind in [2, 0x13, 0x14] {
        for sighash in [1, 2, 3, 0x81, 0x82, 0x83] {
            let parsed = parse(&fixture(1));
            let signed = signed_with(&parsed.backend, &[signature(kind, sighash)]);
            let result = decode(&parsed.finish(&signed).unwrap());
            let expected = if sighash & 3 == 3 {
                Some(vec![4])
            } else {
                None
            };
            assert_eq!(result[0].get(&vec![6]), expected.as_ref());
        }
    }
}

#[test]
fn proprietary_identifier_and_subtype_encodings_are_validated_in_every_scope() {
    for scope in 0..3 {
        for key in [
            vec![0xfc],
            vec![0xfc, 0],
            vec![0xfc, 0, 0xfd],
            vec![0xfc, 0, 0xfd, 1, 0],
            vec![0xfc, 0xfd],
            vec![0xfc, 0xfd, 1, 0, b'x', 0],
            vec![0xfc, 2, b'x'],
            vec![0xfc, 2, b'x', b'y'],
        ] {
            let mut maps = fixture(1);
            maps[scope].insert(key.clone(), vec![1]);
            assert!(
                SigningPsbt::parse(&text(&maps)).is_err(),
                "scope={scope} key={key:?}"
            );
        }
        let mut maps = fixture(1);
        maps[scope].insert(vec![0xfc, 0, 0xfd, 0xfd, 0], vec![1, 2, 3]);
        let parsed = parse(&maps);
        assert_eq!(decode(&parsed.finish(&parsed.backend).unwrap()), maps);
        let entry = signature(2, 1);
        let signed = signed_with(&parsed.backend, std::slice::from_ref(&entry));
        maps[1].insert(entry.0, entry.1);
        assert_eq!(decode(&parsed.finish(&signed).unwrap()), maps);
    }
}
