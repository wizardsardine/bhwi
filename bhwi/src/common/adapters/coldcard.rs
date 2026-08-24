use bitcoin::PublicKey;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::secp256k1::Secp256k1;
use miniscript::{
    Descriptor, Miniscript, ScriptContext, Terminal,
    descriptor::{DescriptorPublicKey, ShInner, SinglePubKey, WalletPolicy, Wildcard},
};

use crate::coldcard::api;
use crate::coldcard::{
    ColdcardCommand, ColdcardError, ColdcardMultisigDisplayAddress, ColdcardMultisigDisplayKey,
    ColdcardResponse, ColdcardTransmit,
};
use crate::common::{
    Command, DeviceBackup, DisplayAddress, Error, Info, MultisigAddressType,
    MultisigDisplayAddress, Recipient, Response, Transmit, WalletRegistration,
};

impl TryFrom<Command> for ColdcardCommand {
    type Error = ColdcardError;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        match command {
            Command::Setup(..) => Err(ColdcardError::MissingCommandInfo(
                "Setup not supported by Coldcard",
            )),
            Command::Wipe => Err(ColdcardError::MissingCommandInfo(
                "Wipe not supported by Coldcard",
            )),
            Command::Restore(..) => Err(ColdcardError::MissingCommandInfo(
                "Restore not supported by Coldcard",
            )),
            Command::TogglePassphrase => Err(ColdcardError::MissingCommandInfo(
                "Toggle passphrase not supported by Coldcard",
            )),
            Command::Backup => Ok(Self::Backup),
            Command::Unlock { .. } => Ok(Self::StartEncryption),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, .. } => Ok(Self::GetXpub(path)),
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetVersion),
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path,
                    address_format,
                    ..
                },
                ..,
            ) => Ok(Self::ShowAddress {
                path,
                addr_fmt: address_format
                    .map(api::request::addr_fmt::from_address_type)
                    .unwrap_or(api::request::addr_fmt::AF_P2WPKH),
            }),
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    descriptor_name,
                    change,
                    index,
                    ..
                },
                ..,
            ) => Ok(Self::MiniscriptAddress {
                name: descriptor_name,
                change,
                index,
            }),
            Command::DisplayAddress(DisplayAddress::ByMultisig(address), ..) => {
                Ok(Self::ShowP2shAddress {
                    address: coldcard_multisig_display_address(address)?,
                })
            }
            Command::RegisterWallet { name, policy } => Ok(Self::RegisterWallet {
                payload: coldcard_registration_payload(&name, &policy)?,
            }),
            Command::SignTx(psbt, context) => {
                if context.is_some() {
                    return Err(ColdcardError::MissingCommandInfo(
                        "Coldcard SignTx does not support device context",
                    ));
                }
                Ok(Self::SignPsbt { psbt })
            }
        }
    }
}

fn coldcard_registration_payload(
    name: &str,
    policy: &WalletPolicy,
) -> Result<Vec<u8>, ColdcardError> {
    if !(2..=20).contains(&name.len())
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(ColdcardError::InvalidInput(
            "Coldcard wallet names must be 2 to 20 printable ASCII characters".to_string(),
        ));
    }

    let descriptor = policy
        .clone()
        .into_descriptor()
        .map_err(|error| ColdcardError::InvalidInput(error.to_string()))?;
    let (threshold, signer_count) = coldcard_sortedmulti_size(&descriptor).ok_or_else(|| {
        ColdcardError::InvalidInput(
            "Coldcard registration supports only sh(sortedmulti), wsh(sortedmulti), and sh(wsh(sortedmulti)) descriptors"
                .to_string(),
        )
    })?;
    if threshold == 0 || threshold > signer_count || signer_count > 15 {
        return Err(ColdcardError::InvalidInput(
            "Coldcard multisig policies require 1 to 15 signers and a valid threshold".to_string(),
        ));
    }
    for key in descriptor.iter_pk() {
        validate_coldcard_registration_key(&key)?;
    }

    let descriptor = format!("{descriptor:#}");
    let payload = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "desc": descriptor,
    }))
    .map_err(|error| ColdcardError::Serialization(error.to_string()))?;
    if !(101..=4000).contains(&payload.len()) {
        return Err(ColdcardError::InvalidInput(
            "Coldcard multisig registration payload must be 101 to 4000 bytes".to_string(),
        ));
    }
    Ok(payload)
}

fn coldcard_sortedmulti_size(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Option<(usize, usize)> {
    match descriptor {
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::Ms(miniscript) => sortedmulti_size(miniscript),
            ShInner::Wsh(wsh) => sortedmulti_size(wsh.as_inner()),
            ShInner::Wpkh(_) => None,
        },
        Descriptor::Wsh(wsh) => sortedmulti_size(wsh.as_inner()),
        _ => None,
    }
}

fn sortedmulti_size<Ctx: ScriptContext>(
    miniscript: &Miniscript<DescriptorPublicKey, Ctx>,
) -> Option<(usize, usize)> {
    match &miniscript.node {
        Terminal::SortedMulti(threshold) => Some((threshold.k(), threshold.n())),
        _ => None,
    }
}

fn validate_coldcard_registration_key(key: &DescriptorPublicKey) -> Result<(), ColdcardError> {
    let normal = |index| ChildNumber::from_normal_idx(index).expect("small index");
    let valid_single_path = |path: &DerivationPath| path.as_ref() == [normal(0)];
    let valid_multi_paths = |paths: &[DerivationPath]| {
        if paths.len() != 2 || paths.iter().any(|path| path.as_ref().len() != 1) {
            return false;
        }
        let mut branches = paths
            .iter()
            .map(|path| path.as_ref()[0])
            .collect::<Vec<_>>();
        branches.sort_unstable();
        branches == [normal(0), normal(1)]
    };

    let valid = match key {
        DescriptorPublicKey::XPub(key) => {
            key.origin.is_some()
                && key.wildcard == Wildcard::Unhardened
                && valid_single_path(&key.derivation_path)
        }
        DescriptorPublicKey::MultiXPub(key) => {
            key.origin.is_some()
                && key.wildcard == Wildcard::Unhardened
                && valid_multi_paths(key.derivation_paths.paths())
        }
        DescriptorPublicKey::Single(_) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ColdcardError::InvalidInput(
            "Coldcard multisig keys require origins, extended public keys, and /0/* or /<0;1>/* derivation"
                .to_string(),
        ))
    }
}

fn multisig_address_format(address_type: MultisigAddressType) -> u32 {
    match address_type {
        MultisigAddressType::Legacy => api::request::addr_fmt::AF_P2SH,
        MultisigAddressType::ShWit => api::request::addr_fmt::AF_P2WSH_P2SH,
        MultisigAddressType::Wit => api::request::addr_fmt::AF_P2WSH,
    }
}

fn coldcard_multisig_display_address(
    address: MultisigDisplayAddress,
) -> Result<ColdcardMultisigDisplayAddress, ColdcardError> {
    if !address.sorted {
        return Err(ColdcardError::Device(
            "Coldcards only allow sortedmulti descriptors".to_string(),
        ));
    }
    let secp = Secp256k1::verification_only();
    let mut keys = address
        .keys
        .into_iter()
        .map(|key| match key {
            DescriptorPublicKey::Single(single) => {
                let (fingerprint, path) = single.origin.ok_or_else(|| {
                    ColdcardError::Serialization(
                        "Coldcard multisig display requires key origin information".to_string(),
                    )
                })?;
                let SinglePubKey::FullKey(public_key) = single.key else {
                    return Err(ColdcardError::Serialization(
                        "Coldcard multisig display requires full public keys".to_string(),
                    ));
                };
                Ok(ColdcardMultisigDisplayKey {
                    fingerprint,
                    path,
                    public_key,
                })
            }
            DescriptorPublicKey::XPub(xpub) => {
                if xpub.wildcard != Wildcard::None {
                    return Err(ColdcardError::Serialization(
                        "Coldcard multisig display requires a concrete derivation path".to_string(),
                    ));
                }
                let (fingerprint, origin_path) = xpub.origin.ok_or_else(|| {
                    ColdcardError::Serialization(
                        "Coldcard multisig display requires key origin information".to_string(),
                    )
                })?;
                let derived = xpub
                    .xkey
                    .derive_pub(&secp, &xpub.derivation_path)
                    .map_err(|error| ColdcardError::Serialization(error.to_string()))?;
                Ok(ColdcardMultisigDisplayKey {
                    fingerprint,
                    path: origin_path.extend(&xpub.derivation_path),
                    public_key: PublicKey::new(derived.public_key),
                })
            }
            DescriptorPublicKey::MultiXPub(_) => Err(ColdcardError::Serialization(
                "Coldcard multisig display does not support multipath keys".to_string(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort_by_key(|key| key.public_key.inner.serialize());
    Ok(ColdcardMultisigDisplayAddress {
        threshold: address.threshold,
        address_format: multisig_address_format(address.address_type),
        keys,
    })
}

impl From<ColdcardResponse> for Response {
    fn from(response: ColdcardResponse) -> Self {
        match response {
            ColdcardResponse::MasterFingerprint(fingerprint) => {
                Self::MasterFingerprint(fingerprint)
            }
            ColdcardResponse::Xpub(xpub) => Self::Xpub(xpub),
            ColdcardResponse::Version {
                version,
                device_model,
            } => Self::Info(Info {
                version,
                networks: vec![],
                firmware: Some(device_model),
                initialized: None,
            }),
            ColdcardResponse::MyPub { encryption_key, .. } => Self::EncryptionKey(encryption_key),
            ColdcardResponse::Signature(header, signature) => Self::Signature(header, signature),
            ColdcardResponse::Ok => Self::TaskDone,
            ColdcardResponse::Busy => Self::TaskBusy,
            ColdcardResponse::Address(address) => Self::Address(address),
            ColdcardResponse::Backup(bytes) => Self::Backup(DeviceBackup::File(bytes)),
            ColdcardResponse::SignedPsbt(psbt) => Self::SignedPsbt(psbt),
            ColdcardResponse::WalletRegistrationPending => {
                Self::WalletRegistration(WalletRegistration::PendingUserConfirmation)
            }
        }
    }
}

impl From<ColdcardTransmit> for Transmit {
    fn from(transmit: ColdcardTransmit) -> Self {
        Self {
            recipient: Recipient::Device,
            payload: transmit.payload,
            encrypted: transmit.encrypted,
        }
    }
}

impl From<ColdcardError> for Error {
    fn from(error: ColdcardError) -> Self {
        match error {
            ColdcardError::Encryption(error) => Self::Encryption(error),
            ColdcardError::MissingCommandInfo(error) => Self::MissingCommandInfo(error),
            ColdcardError::Device(error) => Self::Device(format!("Coldcard Error: {error}")),
            ColdcardError::NoErrorOrResult => Self::NoErrorOrResult,
            ColdcardError::Serialization(error) => Self::Serialization(error),
            ColdcardError::InvalidInput(error) => Self::InvalidInput(error),
            ColdcardError::UnexpectedResponseMessage { got, expected } => Self::unexpected_result(
                format!("{got:?}").into_bytes(),
                format!("coldcard unexpected response: expected {expected:?}, got {got:?}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    const REGISTRATION_POLICY: &str = "wsh(sortedmulti(2,[f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*,[00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*))";

    #[test]
    fn registration_payload_contains_name_and_full_descriptor() {
        let policy = WalletPolicy::from_str(REGISTRATION_POLICY).unwrap();
        let payload = coldcard_registration_payload("cold-wallet", &policy).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["name"], "cold-wallet");
        assert_eq!(payload["desc"], REGISTRATION_POLICY);
    }

    #[test]
    fn registration_rejects_unsupported_policy_and_name() {
        let singlesig = WalletPolicy::from_str(
            "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*)",
        )
        .unwrap();
        let error = coldcard_registration_payload("cold-wallet", &singlesig).unwrap_err();
        assert!(error.to_string().contains("supports only"));

        let policy = WalletPolicy::from_str(REGISTRATION_POLICY).unwrap();
        let error = coldcard_registration_payload("x", &policy).unwrap_err();
        assert!(error.to_string().contains("2 to 20"));
    }

    #[test]
    fn registration_rejects_keys_without_origins() {
        let policy = WalletPolicy::from_str(
            "wsh(sortedmulti(2,tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*,tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*))",
        )
        .unwrap();
        let error = coldcard_registration_payload("cold-wallet", &policy).unwrap_err();
        assert!(error.to_string().contains("require origins"));
    }

    #[test]
    fn path_display_maps_to_protocol_address_format() {
        let command = ColdcardCommand::try_from(Command::DisplayAddress(
            DisplayAddress::ByPath {
                path: "m/49'/1'/0'/0/0".parse().unwrap(),
                display: true,
                address_format: Some(bitcoin::address::AddressType::P2sh),
            },
            None,
        ))
        .unwrap();

        assert!(matches!(
            command,
            ColdcardCommand::ShowAddress {
                addr_fmt: api::request::addr_fmt::AF_P2WPKH_P2SH,
                ..
            }
        ));
    }

    #[test]
    fn transmit_maps_to_device_recipient() {
        let transmit = Transmit::from(ColdcardTransmit {
            payload: vec![1, 2, 3],
            encrypted: true,
        });
        assert!(matches!(transmit.recipient, Recipient::Device));
        assert_eq!(transmit.payload, vec![1, 2, 3]);
        assert!(transmit.encrypted);
    }
}
