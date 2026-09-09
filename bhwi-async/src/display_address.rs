use std::str::FromStr;

use bhwi::{
    bitcoin::{
        address::AddressType,
        bip32::{self, DerivationPath, Fingerprint, Xpub},
        hex::{self, DisplayHex},
        secp256k1::{PublicKey as SecpPublicKey, XOnlyPublicKey},
    },
    common::{DisplayAddress, MultisigAddressType, MultisigDisplayAddress},
    miniscript::{DescriptorPublicKey, descriptor::DescriptorKeyParseError},
};

use bhwi::common::DeviceContext;
use bhwi::miniscript::descriptor::WalletPolicy;

use crate::{
    HWIDeviceError,
    device::{Device, DeviceType, supports_multisig_display_address},
};

#[derive(Debug, thiserror::Error)]
pub enum DisplayAddressContextError {
    #[error("{0} needs the wallet policy descriptor of the registered wallet")]
    MissingPolicy(DeviceType),

    #[error("{0} needs both the wallet policy descriptor and its registration hmac")]
    IncompletePolicy(DeviceType),
}

/// BitBox02 needs the policy descriptor every time, Ledger needs it with its
/// registration hmac, and the rest resolve the name on the device.
pub fn display_address_context(
    device_type: DeviceType,
    name: &str,
    policy: Option<WalletPolicy>,
    hmac: Option<[u8; 32]>,
) -> Result<Option<DeviceContext>, DisplayAddressContextError> {
    let _ = (name, &policy, hmac);
    match device_type {
        #[cfg(feature = "bitbox")]
        DeviceType::BitBox02 => Ok(Some(DeviceContext::BitBox {
            policy: policy.ok_or(DisplayAddressContextError::MissingPolicy(device_type))?,
        })),
        #[cfg(feature = "ledger")]
        DeviceType::Ledger => match (policy, hmac) {
            (None, None) => Ok(None),
            (Some(policy), Some(hmac)) => Ok(Some(crate::signing::ledger::registered_context(
                name.to_owned(),
                policy,
                Some(hmac),
            ))),
            _ => Err(DisplayAddressContextError::IncompletePolicy(device_type)),
        },
        _ => Ok(None),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DisplayAddressError {
    #[error("Unsupported displayaddress descriptor: {0}")]
    UnsupportedDescriptor(String),

    #[error("Descriptor missing origin info: {0}")]
    MissingOrigin(String),

    #[error("Descriptor fingerprint does not match device: {0}")]
    FingerprintMismatch(String),

    #[error("Key in descriptor does not match device: {0}")]
    KeyMismatch(String),

    #[error("Character '{0}' is not a valid base58 character")]
    InvalidBase58Character(char),

    #[error(
        "Either the redeem script provided is invalid or the keypaths provided are insufficient"
    )]
    InvalidMultisig,

    #[error(transparent)]
    Bip32(#[from] bip32::Error),

    #[error(transparent)]
    Fingerprint(#[from] hex::HexToArrayError),

    #[error(transparent)]
    Key(#[from] DescriptorKeyParseError),

    #[error(transparent)]
    Threshold(#[from] std::num::ParseIntError),

    #[error(transparent)]
    Device(#[from] HWIDeviceError),
}

/// Singlesig first, then multisig on devices that take one at display time.
/// When neither parses, the singlesig error is the one reported.
pub async fn display_address_from_descriptor(
    device: &mut Device,
    descriptor: &str,
) -> Result<DisplayAddress, DisplayAddressError> {
    let device_type = device.device_type();
    let singlesig_error = match singlesig_display_address_from_descriptor(device, descriptor).await
    {
        Ok(address) => return Ok(address),
        Err(error) => error,
    };
    if !supports_multisig_display_address(device_type) {
        return Err(singlesig_error);
    }
    match multisig_display_address_from_descriptor(descriptor) {
        Ok(address) => Ok(DisplayAddress::ByMultisig(address)),
        Err(_) => Err(singlesig_error),
    }
}

pub async fn singlesig_display_address_from_descriptor(
    device: &mut Device,
    descriptor: &str,
) -> Result<DisplayAddress, DisplayAddressError> {
    let descriptor = strip_descriptor_checksum(descriptor);
    let parsed = parse_singlesig_display_descriptor(descriptor)?;
    let fingerprint = device.fingerprint().await?;
    if parsed.fingerprint != fingerprint {
        return Err(DisplayAddressError::FingerprintMismatch(
            descriptor.to_owned(),
        ));
    }

    let xpub = device
        .device()
        .get_extended_pubkey(parsed.origin_path.clone(), false)
        .await?;

    if !descriptor_key_matches_xpub(&parsed.key, xpub) {
        return Err(DisplayAddressError::KeyMismatch(descriptor.to_owned()));
    }

    Ok(DisplayAddress::ByPath {
        path: parsed.full_path,
        display: true,
        address_format: Some(parsed.addr_type),
    })
}

#[derive(Debug)]
struct ParsedSingleSigDisplayDescriptor {
    addr_type: AddressType,
    fingerprint: Fingerprint,
    origin_path: DerivationPath,
    full_path: DerivationPath,
    key: String,
}

fn parse_singlesig_display_descriptor(
    descriptor: &str,
) -> Result<ParsedSingleSigDisplayDescriptor, DisplayAddressError> {
    let (addr_type, key_expr) = if let Some(inner) = descriptor
        .strip_prefix("sh(wpkh(")
        .and_then(|value| value.strip_suffix("))"))
    {
        (AddressType::P2sh, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("wpkh(")
        .and_then(|value| value.strip_suffix(')'))
    {
        (AddressType::P2wpkh, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("pkh(")
        .and_then(|value| value.strip_suffix(')'))
    {
        (AddressType::P2pkh, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("tr(")
        .and_then(|value| value.strip_suffix(')'))
    {
        (AddressType::P2tr, inner)
    } else {
        return Err(DisplayAddressError::UnsupportedDescriptor(
            descriptor.to_owned(),
        ));
    };

    let Some(rest) = key_expr.strip_prefix('[') else {
        return Err(DisplayAddressError::MissingOrigin(descriptor.to_owned()));
    };
    let Some((origin, key_and_suffix)) = rest.split_once(']') else {
        return Err(DisplayAddressError::MissingOrigin(descriptor.to_owned()));
    };
    let (fingerprint, origin_path) = parse_key_origin(origin)?;
    let (key, suffix_path) = split_key_suffix(key_and_suffix)?;
    validate_singlesig_display_key(key)?;
    let full_path = join_derivation_path(&origin_path, &suffix_path);

    Ok(ParsedSingleSigDisplayDescriptor {
        addr_type,
        fingerprint,
        origin_path,
        full_path,
        key: key.to_owned(),
    })
}

fn validate_singlesig_display_key(key: &str) -> Result<(), DisplayAddressError> {
    if SecpPublicKey::from_str(key).is_ok() || XOnlyPublicKey::from_str(key).is_ok() {
        return Ok(());
    }

    Xpub::from_str(key).map(|_| ()).map_err(|err| {
        invalid_base58_character(key)
            .map_or_else(|| err.into(), DisplayAddressError::InvalidBase58Character)
    })
}

fn invalid_base58_character(value: &str) -> Option<char> {
    const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    value.chars().find(|ch| !BASE58_ALPHABET.contains(*ch))
}

pub fn multisig_display_address_from_descriptor(
    descriptor: &str,
) -> Result<MultisigDisplayAddress, DisplayAddressError> {
    let descriptor = strip_descriptor_checksum(descriptor);
    let (address_type, sorted, inner) = parse_multisig_descriptor_envelope(descriptor)
        .ok_or_else(|| DisplayAddressError::UnsupportedDescriptor(descriptor.to_owned()))?;

    let mut parts = inner.split(',');
    // `split` always yields at least one item, so an empty threshold reaches the parser.
    let threshold = parts.next().unwrap_or_default().parse::<u8>()?;
    let keys = parts
        .map(|key| DescriptorPublicKey::from_str(key).map_err(DisplayAddressError::from))
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() || threshold == 0 || usize::from(threshold) > keys.len() {
        return Err(DisplayAddressError::InvalidMultisig);
    }
    Ok(MultisigDisplayAddress {
        threshold,
        address_type,
        sorted,
        keys,
    })
}

fn parse_multisig_descriptor_envelope(
    descriptor: &str,
) -> Option<(MultisigAddressType, bool, &str)> {
    let wrappers = [
        ("sh(wsh(", "))", MultisigAddressType::ShWit),
        ("wsh(", ")", MultisigAddressType::Wit),
        ("sh(", ")", MultisigAddressType::Legacy),
    ];
    for (prefix, suffix, address_type) in wrappers {
        let Some(inner) = descriptor
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
        else {
            continue;
        };
        if let Some(inner) = inner
            .strip_prefix("sortedmulti(")
            .and_then(|value| value.strip_suffix(')'))
        {
            return Some((address_type, true, inner));
        }
        if let Some(inner) = inner
            .strip_prefix("multi(")
            .and_then(|value| value.strip_suffix(')'))
        {
            return Some((address_type, false, inner));
        }
    }
    None
}

fn strip_descriptor_checksum(descriptor: &str) -> &str {
    descriptor
        .split_once('#')
        .map_or(descriptor, |(desc, _)| desc)
}

fn parse_key_origin(origin: &str) -> Result<(Fingerprint, DerivationPath), DisplayAddressError> {
    let (fingerprint, path) = origin
        .split_once('/')
        .map_or((origin, ""), |(fp, path)| (fp, path));
    let fingerprint = Fingerprint::from_str(fingerprint)?;
    let path = if path.is_empty() {
        DerivationPath::master()
    } else {
        DerivationPath::from_str(&format!("m/{path}"))?
    };
    Ok((fingerprint, path))
}

fn split_key_suffix(key_and_suffix: &str) -> Result<(&str, DerivationPath), DisplayAddressError> {
    let Some((key, suffix)) = key_and_suffix.split_once('/') else {
        return Ok((key_and_suffix, DerivationPath::master()));
    };
    let suffix = DerivationPath::from_str(&format!("m/{suffix}"))?;
    Ok((key, suffix))
}

fn join_derivation_path(base: &DerivationPath, suffix: &DerivationPath) -> DerivationPath {
    let mut children = base.as_ref().to_vec();
    children.extend_from_slice(suffix.as_ref());
    DerivationPath::from(children)
}

fn descriptor_key_matches_xpub(key: &str, xpub: Xpub) -> bool {
    key == xpub.to_string()
        || key.eq_ignore_ascii_case(&xpub.public_key.serialize().to_lower_hex_string())
        || key.eq_ignore_ascii_case(
            &xpub
                .public_key
                .x_only_public_key()
                .0
                .serialize()
                .to_lower_hex_string(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_singlesig_display_descriptor() {
        let descriptor = "sh(wpkh([f5acc2fd/49h/1h/0h]tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/0/7))#checksum";

        let parsed = parse_singlesig_display_descriptor(strip_descriptor_checksum(descriptor))
            .expect("display descriptor");

        assert_eq!(parsed.addr_type, AddressType::P2sh);
        assert_eq!(
            parsed.fingerprint,
            Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd])
        );
        assert_eq!(
            parsed.origin_path,
            DerivationPath::from_str("m/49h/1h/0h").unwrap()
        );
        assert_eq!(
            parsed.full_path,
            DerivationPath::from_str("m/49h/1h/0h/0/7").unwrap()
        );
        assert_eq!(
            parsed.key,
            "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
        );
    }

    #[test]
    fn display_descriptor_requires_origin() {
        let err = parse_singlesig_display_descriptor("wpkh(tpubDD8d3xExampleKeyMaterial/0/7)")
            .expect_err("missing origin");

        assert!(err.to_string().contains("Descriptor missing origin info"));
    }

    #[test]
    fn display_descriptor_rejects_invalid_base58_key_like_python_hwi() {
        let err = parse_singlesig_display_descriptor("wpkh([0f056943/84h/1h/0h]not_an_xpub/0/0)")
            .expect_err("invalid key");

        assert_eq!(
            err.to_string(),
            "Character '_' is not a valid base58 character"
        );
    }

    #[test]
    fn parses_coldcard_sortedmulti_display_descriptor() {
        let descriptor = "sh(wsh(sortedmulti(2,[f5acc2fd/48h/1h/0h/0h/0]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,[aaaaaaaa/48h/1h/1h/0h/0]03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a)))";

        let parsed = multisig_display_address_from_descriptor(descriptor)
            .expect("multisig display descriptor");

        assert_eq!(parsed.threshold, 2);
        assert!(matches!(parsed.address_type, MultisigAddressType::ShWit));
        assert!(parsed.sorted);
        assert_eq!(parsed.keys.len(), 2);
        let origins = parsed
            .keys
            .iter()
            .map(|key| match key {
                DescriptorPublicKey::Single(key) => key.origin.clone().unwrap().1,
                _ => panic!("expected concrete public key"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            origins,
            vec![
                DerivationPath::from_str("m/48h/1h/0h/0h/0").unwrap(),
                DerivationPath::from_str("m/48h/1h/1h/0h/0").unwrap(),
            ]
        );
    }
}
