use bhwi::bitcoin::psbt::Psbt;

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
pub fn merge_psbt_signatures(target: &mut Psbt, signed: Psbt) {
    for (target, signed) in target.inputs.iter_mut().zip(signed.inputs) {
        target.partial_sigs.extend(signed.partial_sigs);
        target.tap_script_sigs.extend(signed.tap_script_sigs);
        if signed.tap_key_sig.is_some() {
            target.tap_key_sig = signed.tap_key_sig;
        }
    }
}
