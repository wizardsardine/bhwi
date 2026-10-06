use bhwi::bitcoin::psbt::Psbt;

/// Removes witness UTXOs for inputs whose full previous transaction shows a non-witness script.
///
/// Inputs without a matching previous output are left unchanged.
///
/// # Panics
///
/// Panics if an input with a full previous transaction has no corresponding
/// entry in `psbt.unsigned_tx.input`.
pub fn strip_legacy_witness_utxos(psbt: &mut Psbt) {
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let Some(utxo) = input.non_witness_utxo.as_ref().and_then(|tx| {
            tx.output
                .get(psbt.unsigned_tx.input[index].previous_output.vout as usize)
        }) else {
            continue;
        };
        if !utxo.script_pubkey.is_witness_program() {
            input.witness_utxo = None;
        }
    }
}

/// Accumulates signatures across the several rounds a multi-policy PSBT needs.
///
/// Merges only partial ECDSA signatures, Taproot script signatures, and a
/// present Taproot key signature. Inputs are paired by index up to the shorter
/// list; transaction identity and equal input counts are not checked. Existing
/// signatures with the same key are replaced.
pub fn merge_psbt_signatures(target: &mut Psbt, signed: Psbt) {
    for (target, signed) in target.inputs.iter_mut().zip(signed.inputs) {
        target.partial_sigs.extend(signed.partial_sigs);
        target.tap_script_sigs.extend(signed.tap_script_sigs);
        if signed.tap_key_sig.is_some() {
            target.tap_key_sig = signed.tap_key_sig;
        }
    }
}
