/// Ledger policy inference and signing-context preparation.
#[cfg(feature = "ledger")]
pub mod ledger;

use bhwi::bitcoin::secp256k1::ecdsa::Signature;

use crate::device::DeviceType;

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
