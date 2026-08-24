use anyhow::{Context, Result, bail};
use bitcoin::{
    Psbt, PublicKey, ScriptBuf,
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::SighashCache,
    sign_message::{MessageSignature, signed_msg_hash},
};

pub fn verify_message_signature(pubkey: &PublicKey, message: &str, payload: &[u8]) -> Result<()> {
    let signature = MessageSignature::from_slice(payload)
        .context("signmessage payload was not a 65-byte recoverable signature")?;
    let secp = Secp256k1::verification_only();
    let recovered = signature
        .recover_pubkey(&secp, signed_msg_hash(message))
        .context("signmessage payload did not recover a public key")?;
    if recovered.inner != pubkey.inner {
        bail!("signmessage payload recovered a public key the device did not sign with");
    }
    Ok(())
}

pub fn verify_psbt_signature(psbt: &Psbt, input_index: usize, pubkey: &PublicKey) -> Result<()> {
    let input = psbt
        .inputs
        .get(input_index)
        .with_context(|| format!("psbt has no input {input_index}"))?;
    let signature = input
        .partial_sigs
        .get(pubkey)
        .with_context(|| format!("psbt input {input_index} carries no signature for the key"))?;

    let expected_sighash_type = input.ecdsa_hash_ty().with_context(|| {
        format!("psbt input {input_index} declared a non-standard sighash type")
    })?;
    if signature.sighash_type != expected_sighash_type {
        bail!(
            "psbt input {input_index} signature used sighash type {:?} but the input requires {:?}",
            signature.sighash_type,
            expected_sighash_type
        );
    }

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = if let Some(witness_script) = input.witness_script.as_ref() {
        let value = input
            .witness_utxo
            .as_ref()
            .with_context(|| {
                format!("psbt input {input_index} has a witness script but no witness utxo")
            })?
            .value;
        cache
            .p2wsh_signature_hash(input_index, witness_script, value, signature.sighash_type)
            .with_context(|| format!("failed to compute p2wsh sighash for input {input_index}"))?
            .to_byte_array()
    } else if let Some(utxo) = input
        .witness_utxo
        .as_ref()
        .filter(|utxo| utxo.script_pubkey.is_p2wpkh())
    {
        // The script code is derived from the scriptPubKey internally.
        cache
            .p2wpkh_signature_hash(
                input_index,
                &utxo.script_pubkey,
                utxo.value,
                signature.sighash_type,
            )
            .with_context(|| format!("failed to compute p2wpkh sighash for input {input_index}"))?
            .to_byte_array()
    } else {
        let script_pubkey = legacy_spent_script(psbt, input_index)?;
        cache
            .legacy_signature_hash(input_index, script_pubkey, signature.sighash_type.to_u32())
            .with_context(|| format!("failed to compute legacy sighash for input {input_index}"))?
            .to_byte_array()
    };

    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(sighash),
            &signature.signature,
            &pubkey.inner,
        )
        .with_context(|| format!("psbt input {input_index} signature did not verify"))
}

pub fn verify_all_psbt_signatures(psbt: &Psbt, expected: &PublicKey) -> Result<()> {
    let mut verified = 0;
    for (index, input) in psbt.inputs.iter().enumerate() {
        if input.partial_sigs.contains_key(expected) {
            verify_psbt_signature(psbt, index, expected)?;
            verified += 1;
        }
    }
    if verified == 0 {
        bail!("psbt carried no signature for the expected key on any input");
    }
    Ok(())
}

pub fn strip_signatures(psbt: &mut Psbt) {
    for input in psbt.inputs.iter_mut() {
        input.partial_sigs.clear();
        input.tap_key_sig = None;
        input.tap_script_sigs.clear();
        input.final_script_sig = None;
        input.final_script_witness = None;
    }
}

pub fn assert_psbt_parity(reference: &Psbt, candidate: &Psbt) -> Result<()> {
    let mut stripped_reference = reference.clone();
    let mut stripped_candidate = candidate.clone();
    strip_signatures(&mut stripped_reference);
    strip_signatures(&mut stripped_candidate);
    if stripped_reference != stripped_candidate {
        bail!("reference and candidate psbts differ outside their signature values");
    }

    for (index, (reference_input, candidate_input)) in reference
        .inputs
        .iter()
        .zip(candidate.inputs.iter())
        .enumerate()
    {
        if !reference_input
            .partial_sigs
            .keys()
            .eq(candidate_input.partial_sigs.keys())
        {
            bail!("reference and candidate psbt input {index} signed with different keys");
        }
        if !reference_input
            .tap_script_sigs
            .keys()
            .eq(candidate_input.tap_script_sigs.keys())
        {
            bail!(
                "reference and candidate psbt input {index} carry different taproot script signature keys"
            );
        }
        if reference_input.tap_key_sig.is_some() != candidate_input.tap_key_sig.is_some() {
            bail!(
                "reference and candidate psbt input {index} disagree on the taproot key signature"
            );
        }
    }

    Ok(())
}

fn legacy_spent_script(psbt: &Psbt, input_index: usize) -> Result<&ScriptBuf> {
    let vout = psbt
        .unsigned_tx
        .input
        .get(input_index)
        .with_context(|| format!("unsigned transaction has no input {input_index}"))?
        .previous_output
        .vout as usize;
    let utxo = psbt.inputs[input_index]
        .non_witness_utxo
        .as_ref()
        .with_context(|| {
            format!("psbt input {input_index} has no utxo to derive a sighash from")
        })?;
    utxo.output
        .get(vout)
        .map(|output| &output.script_pubkey)
        .with_context(|| format!("psbt input {input_index} non-witness utxo has no output {vout}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Amount, NetworkKind, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::LockTime,
        bip32::Xpriv,
        ecdsa,
        secp256k1::{SecretKey, ecdsa::Signature as SecpSignature},
        sighash::EcdsaSighashType,
        transaction::Version,
    };

    const MESSAGE: &str = "hello world";

    fn key(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).expect("master key");
        let private_key = xpriv.private_key;
        (private_key, PublicKey::new(private_key.public_key(&secp)))
    }

    fn message_payload(private_key: &SecretKey, message: &str) -> [u8; 65] {
        let secp = Secp256k1::new();
        let digest = Message::from_digest(signed_msg_hash(message).to_byte_array());
        MessageSignature::new(secp.sign_ecdsa_recoverable(&digest, private_key), true).serialize()
    }

    fn unsigned_psbt(pubkey: &PublicKey) -> Psbt {
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().expect("compressed key"));
        let spend = |vout| TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![spend(0), spend(1)],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: script_pubkey.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx should become a psbt");
        for input in psbt.inputs.iter_mut() {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: script_pubkey.clone(),
            });
        }
        psbt
    }

    fn sign_input(
        psbt: &Psbt,
        input_index: usize,
        private_key: &SecretKey,
        sighash_type: EcdsaSighashType,
    ) -> ecdsa::Signature {
        let utxo = psbt.inputs[input_index]
            .witness_utxo
            .clone()
            .expect("witness utxo");
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wpkh_signature_hash(input_index, &utxo.script_pubkey, utxo.value, sighash_type)
            .expect("p2wpkh sighash");
        let secp = Secp256k1::new();
        ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), private_key),
            sighash_type,
        }
    }

    fn signed_psbt() -> (SecretKey, PublicKey, Psbt) {
        let (private_key, pubkey) = key(7);
        let mut psbt = unsigned_psbt(&pubkey);
        let signature = sign_input(&psbt, 0, &private_key, EcdsaSighashType::All);
        psbt.inputs[0].partial_sigs.insert(pubkey, signature);
        (private_key, pubkey, psbt)
    }

    #[test]
    fn valid_message_signature_verifies() {
        let (private_key, pubkey) = key(7);
        let payload = message_payload(&private_key, MESSAGE);
        verify_message_signature(&pubkey, MESSAGE, &payload).expect("signature should verify");
    }

    #[test]
    fn corrupted_message_signature_fails() {
        let (private_key, pubkey) = key(7);
        let mut payload = message_payload(&private_key, MESSAGE);
        payload[1] ^= 0x01;
        assert!(verify_message_signature(&pubkey, MESSAGE, &payload).is_err());
    }

    #[test]
    fn message_signature_over_another_message_fails() {
        let (private_key, pubkey) = key(7);
        let payload = message_payload(&private_key, MESSAGE);
        assert!(verify_message_signature(&pubkey, "hello", &payload).is_err());
    }

    #[test]
    fn message_signature_by_another_key_fails() {
        let (private_key, _) = key(7);
        let (_, other_pubkey) = key(8);
        let payload = message_payload(&private_key, MESSAGE);
        assert!(verify_message_signature(&other_pubkey, MESSAGE, &payload).is_err());
    }

    #[test]
    fn message_signature_with_wrong_length_fails() {
        let (private_key, pubkey) = key(7);
        let payload = message_payload(&private_key, MESSAGE);
        assert!(verify_message_signature(&pubkey, MESSAGE, &payload[..64]).is_err());
    }

    #[test]
    fn message_signature_with_flipped_recovery_id_fails() {
        let (private_key, pubkey) = key(7);
        let mut payload = message_payload(&private_key, MESSAGE);
        payload[0] ^= 0x01;
        assert!(verify_message_signature(&pubkey, MESSAGE, &payload).is_err());
    }

    #[test]
    fn valid_psbt_signature_verifies() {
        let (_, pubkey, psbt) = signed_psbt();
        verify_psbt_signature(&psbt, 0, &pubkey).expect("signature should verify");
        verify_all_psbt_signatures(&psbt, &pubkey).expect("signature should verify");
    }

    #[test]
    fn psbt_without_expected_signature_fails() {
        let (_, pubkey) = key(7);
        let psbt = unsigned_psbt(&pubkey);
        assert!(verify_all_psbt_signatures(&psbt, &pubkey).is_err());
    }

    #[test]
    fn psbt_signature_over_another_input_fails() {
        let (_, pubkey, mut psbt) = signed_psbt();
        let signature = psbt.inputs[0].partial_sigs[&pubkey];
        psbt.inputs[1].partial_sigs.insert(pubkey, signature);
        assert!(verify_psbt_signature(&psbt, 1, &pubkey).is_err());
        assert!(verify_all_psbt_signatures(&psbt, &pubkey).is_err());
    }

    #[test]
    fn psbt_signature_by_another_key_fails() {
        let (_, pubkey) = key(7);
        let (other_key, _) = key(8);
        let mut psbt = unsigned_psbt(&pubkey);
        let signature = sign_input(&psbt, 0, &other_key, EcdsaSighashType::All);
        psbt.inputs[0].partial_sigs.insert(pubkey, signature);
        assert!(verify_psbt_signature(&psbt, 0, &pubkey).is_err());
    }

    #[test]
    fn psbt_signature_with_corrupted_bytes_fails() {
        let (_, pubkey, mut psbt) = signed_psbt();
        let signature = psbt.inputs[0].partial_sigs[&pubkey];
        let mut compact = signature.signature.serialize_compact();
        compact[40] ^= 0x01;
        psbt.inputs[0].partial_sigs.insert(
            pubkey,
            ecdsa::Signature {
                signature: SecpSignature::from_compact(&compact).expect("compact signature"),
                sighash_type: signature.sighash_type,
            },
        );
        assert!(verify_psbt_signature(&psbt, 0, &pubkey).is_err());
    }

    #[test]
    fn psbt_signature_with_mismatched_sighash_type_fails() {
        let (private_key, pubkey) = key(7);
        let mut psbt = unsigned_psbt(&pubkey);
        let mut signature = sign_input(&psbt, 0, &private_key, EcdsaSighashType::All);
        signature.sighash_type = EcdsaSighashType::Single;
        psbt.inputs[0].partial_sigs.insert(pubkey, signature);
        assert!(verify_psbt_signature(&psbt, 0, &pubkey).is_err());
    }

    #[test]
    fn psbt_parity_ignores_signature_values() {
        let (_, pubkey, reference) = signed_psbt();
        let (other_key, _) = key(8);
        let mut candidate = reference.clone();
        let signature = sign_input(&candidate, 0, &other_key, EcdsaSighashType::All);
        candidate.inputs[0].partial_sigs.insert(pubkey, signature);
        assert_ne!(
            reference.inputs[0].partial_sigs,
            candidate.inputs[0].partial_sigs
        );
        assert_psbt_parity(&reference, &candidate).expect("psbts should be at parity");
    }

    #[test]
    fn psbt_parity_rejects_differing_bip32_derivation() {
        let (_, pubkey, reference) = signed_psbt();
        let mut candidate = reference.clone();
        candidate.inputs[0]
            .bip32_derivation
            .insert(pubkey.inner, (Default::default(), Default::default()));
        assert!(assert_psbt_parity(&reference, &candidate).is_err());
    }

    #[test]
    fn psbt_parity_rejects_differing_witness_utxo() {
        let (_, _, reference) = signed_psbt();
        let mut candidate = reference.clone();
        candidate.inputs[0]
            .witness_utxo
            .as_mut()
            .expect("witness utxo")
            .value = Amount::from_sat(49_999);
        assert!(assert_psbt_parity(&reference, &candidate).is_err());
    }

    #[test]
    fn psbt_parity_rejects_missing_signature() {
        let (_, pubkey, reference) = signed_psbt();
        let mut candidate = reference.clone();
        candidate.inputs[0].partial_sigs.remove(&pubkey);
        assert!(assert_psbt_parity(&reference, &candidate).is_err());
    }
}
