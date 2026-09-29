/// Ledger policy inference and signing-context preparation.
#[cfg(feature = "ledger")]
pub mod ledger;

use bhwi::bitcoin::{Network, psbt::Psbt, secp256k1::ecdsa::Signature};

use crate::{
    DeviceContext, HWIDeviceError,
    device::{Device, DeviceType},
};
#[cfg(feature = "ledger")]
use crate::{
    psbt::{merge_psbt_signatures, strip_legacy_witness_utxos},
    signing::ledger::{LedgerAddressType, LedgerSigningError, ledger_signing_contexts},
};

/// Non-exhaustive because `Ledger` appears with a feature anything in the build
/// can turn on, whatever the caller itself was compiled with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// Ledger wallet-policy inference or signing-context preparation failed.
    #[cfg(feature = "ledger")]
    #[error(transparent)]
    Ledger(#[from] LedgerSigningError),

    /// The device operation failed.
    #[error(transparent)]
    Device(#[from] HWIDeviceError),
}

/// A PSBT returned by the device.
pub struct SignedPsbt {
    /// The PSBT with any signatures the device added.
    pub psbt: Psbt,
    /// Whether the device changed the PSBT.
    pub signed: bool,
}

/// Signs under a caller-built policy rather than deriving one from the PSBT.
pub async fn sign_psbt_with_context(
    device: &mut Device,
    psbt: Psbt,
    context: DeviceContext,
) -> Result<SignedPsbt, SignError> {
    // A Ledger rejects a legacy input that also carries a witness utxo.
    #[cfg(feature = "ledger")]
    let psbt = {
        let mut psbt = psbt;
        if device.device_type() == DeviceType::Ledger {
            strip_legacy_witness_utxos(&mut psbt);
        }
        psbt
    };
    let original = psbt.serialize();
    let signed_psbt = device.device().sign_tx(psbt, Some(context)).await?;
    Ok(SignedPsbt {
        signed: signed_psbt.serialize() != original,
        psbt: signed_psbt,
    })
}

/// Signs with every wallet policy the PSBT needs, which on a Ledger means one
/// `sign_tx` round per policy.
pub async fn sign_psbt(
    device: &mut Device,
    psbt: Psbt,
    network: Network,
) -> Result<SignedPsbt, SignError> {
    #[cfg(not(feature = "ledger"))]
    let _ = network;

    let original = psbt.serialize();

    #[cfg(feature = "ledger")]
    if device.device_type() == DeviceType::Ledger {
        let contexts = ledger_signing_contexts(device, &psbt, network).await?;
        if contexts.is_empty() {
            return Ok(SignedPsbt {
                psbt,
                signed: false,
            });
        }
        let mut signed_psbt = psbt;
        for signing in contexts {
            let mut signing_psbt = signed_psbt.clone();
            if signing.address_type == LedgerAddressType::Legacy {
                strip_legacy_witness_utxos(&mut signing_psbt);
            }
            let result = device
                .device()
                .sign_tx(signing_psbt, Some(signing.context))
                .await?;
            merge_psbt_signatures(&mut signed_psbt, result);
        }
        return Ok(SignedPsbt {
            signed: signed_psbt.serialize() != original,
            psbt: signed_psbt,
        });
    }

    let signed_psbt = device.device().sign_tx(psbt, None).await?;
    Ok(SignedPsbt {
        signed: signed_psbt.serialize() != original,
        psbt: signed_psbt,
    })
}

/// Normalizes a message-signature header by removing Coldcard's offset when present.
///
/// Coldcard headers at least 8 are reduced by 8; other headers are unchanged.
pub fn message_signature_header(device_type: DeviceType, header: u8) -> u8 {
    if device_type == DeviceType::Coldcard && header >= 8 {
        return header - 8;
    }
    header
}

/// Encodes a normalized header and compact ECDSA signature as 65 bytes.
pub fn message_signature(device_type: DeviceType, header: u8, signature: &Signature) -> [u8; 65] {
    let mut payload = [0u8; 65];
    payload[0] = message_signature_header(device_type, header);
    payload[1..].copy_from_slice(&signature.serialize_compact());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_coldcard_header_is_shifted() {
        for device_type in DeviceType::ALL {
            let shifted = device_type == DeviceType::Coldcard;
            assert_eq!(
                message_signature_header(device_type, 40),
                if shifted { 32 } else { 40 },
                "{device_type}"
            );
        }
    }

    #[test]
    fn a_header_below_the_offset_is_left_alone() {
        assert_eq!(message_signature_header(DeviceType::Coldcard, 7), 7);
    }
}
