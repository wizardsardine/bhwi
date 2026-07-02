// Ported from bitbox-api-rs (`src/antiklepto.rs`),
// Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
// Version 2.0 — see BITBOX_LICENSE at the repository root.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};
use std::io::Write;

use super::error::BitBoxError;

fn tagged_sha256(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    let tag_hash = sha256::Hash::hash(tag);

    engine.write_all(tag_hash.as_ref()).unwrap();
    engine.write_all(tag_hash.as_ref()).unwrap();
    engine.write_all(msg).unwrap();

    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn gen_host_nonce() -> Result<[u8; 32], BitBoxError> {
    let mut result = [0u8; 32];
    getrandom::getrandom(&mut result)
        .map_err(|_| BitBoxError::AntiKlepto("failed generating antiklepto host nonce".into()))?;
    Ok(result)
}

pub fn host_commit(host_nonce: &[u8]) -> [u8; 32] {
    tagged_sha256(b"s2c/ecdsa/data", host_nonce)
}

/// Verify that `host_nonce` was used to tweak the nonce during signature generation:
/// `k' = k + H(clientCommitment, hostNonce)`, i.e.
/// `k'*G = signerCommitment + H(signerCommitment, hostNonce)*G`.
pub fn verify_ecdsa(
    host_nonce: &[u8],
    signer_commitment: &[u8],
    signature: &[u8],
) -> Result<(), BitBoxError> {
    let secp = Secp256k1::new();
    let signer_commitment_pubkey = PublicKey::from_slice(signer_commitment)
        .map_err(|_| BitBoxError::AntiKlepto("failed to parse signer commitment".into()))?;

    let mut data = signer_commitment_pubkey.serialize().to_vec();
    data.extend_from_slice(host_nonce);

    let tweak = tagged_sha256(b"s2c/ecdsa/point", &data);

    let tweaked_point = signer_commitment_pubkey
        .add_exp_tweak(
            &secp,
            &Scalar::from_be_bytes(tweak)
                .map_err(|_| BitBoxError::AntiKlepto("tweak is an invalid scalar".into()))?,
        )
        .map_err(|_| BitBoxError::AntiKlepto("failed to tweak key".into()))?;

    let x_coordinate = &tweaked_point.serialize()[1..33];
    let signature_r = &signature[..32];
    if x_coordinate != signature_r {
        return Err(BitBoxError::AntiKlepto(
            "host nonce not present in signature".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hex::FromHex;

    #[test]
    fn test_tagged_sha256() {
        let expected_hash: [u8; 32] =
            FromHex::from_hex("025ee06f5a2db377bd9d7040bae8f6e0ab49784f9c68a1380fba5465d8a99928")
                .unwrap();
        assert_eq!(expected_hash, tagged_sha256(b"test tag", b"test message"));
    }

    #[test]
    fn test_host_commit() {
        let host_nonce: [u8; 32] =
            FromHex::from_hex("e8011345fe4851538c30c1fc1a215395e8063fcf6fbdcf8fab9a42e466a74f4a")
                .unwrap();
        let expected_hash: [u8; 32] =
            FromHex::from_hex("70a8934f41a1679b4c715c3e6db17f785b67da4e398107a0a00c828980a4be2f")
                .unwrap();

        assert_eq!(expected_hash, host_commit(&host_nonce));
    }

    #[test]
    fn test_verify_ecdsa() {
        let unhex = |s| <Vec<u8>>::from_hex(s).unwrap();
        // Fixture recorded from a live protocol run (source: bitbox-api-rs test).
        let host_nonce = unhex("8b4c26aa2695a34bdbc34235f6c91be14b93037a063b13f7c814101359561092");
        let signer_commitment =
            unhex("0236ff92fe02c08d0d04851e0ce1516104085215f05a178307de60ea53e207f971");
        let signature = unhex(
            "7fd66b48ffea2fe048869880bbb3a1819e262af14980e8885df1e5765750cb8f47e01eca356377870356d54853573a955076228e5044cd3dd3a049abe70d5585",
        );
        assert!(verify_ecdsa(&host_nonce, &signer_commitment, &signature).is_ok());

        let mut tweaked = host_nonce.clone();
        tweaked[0] ^= 0x01;
        assert!(verify_ecdsa(&tweaked, &signer_commitment, &signature).is_err());
    }
}
