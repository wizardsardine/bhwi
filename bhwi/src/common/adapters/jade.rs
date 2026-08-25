use bitcoin::address::AddressType;
use bitcoin::hashes::{Hash, sha256};
use miniscript::descriptor::{DescriptorPublicKey, Wildcard};

use crate::common::{
    Command, DisplayAddress, Error, Info, MultisigAddressType, MultisigDisplayAddress, Recipient,
    Response, Transmit, WalletRegistration,
};
use crate::jade::api;
use crate::jade::{
    JadeCommand, JadeError, JadeRecipient, JadeResponse, JadeTransmit, ReceiveAddress,
};

impl TryFrom<Command> for JadeCommand {
    type Error = Error;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        match command {
            Command::Setup(..) => Err(Error::MissingCommandInfo("Setup not supported by Jade")),
            Command::Wipe => Err(Error::MissingCommandInfo("Wipe not supported by Jade")),
            Command::Restore(..) => Err(Error::MissingCommandInfo("Restore not supported by Jade")),
            Command::TogglePassphrase => Err(Error::MissingCommandInfo(
                "Toggle passphrase not supported by Jade",
            )),
            Command::PromptPin | Command::SendPin(_) => Err(Error::MissingCommandInfo(
                "PIN entry from the host not needed by Jade",
            )),
            Command::Backup => Err(Error::MissingCommandInfo("Backup not supported by Jade")),
            Command::Unlock { .. } => Ok(Self::Auth),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, .. } => Ok(Self::GetXpub(path)),
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    index,
                    change,
                    descriptor_name,
                    ..
                },
                _,
            ) => Ok(Self::GetReceiveAddress(ReceiveAddress::Descriptor {
                index,
                change,
                descriptor_name,
            })),
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path,
                    address_format,
                    ..
                },
                _,
            ) => Ok(Self::GetReceiveAddress(ReceiveAddress::Path {
                path,
                variant: jade_path_variant(address_format)?,
            })),
            Command::DisplayAddress(DisplayAddress::ByMultisig(address), _) => {
                jade_multisig_command(address)
            }
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetInfo),
            Command::RegisterWallet { name, policy } => {
                let (descriptor, keys) = crate::policy::extract_parts(&policy)
                    .map_err(|error| Error::Serialization(error.to_string()))?;
                // Jade requires the explicit multipath spelling instead of the
                // BIP-388 wallet-policy shorthand.
                let descriptor = descriptor.replace("/**", "/<0;1>/*");
                let datavalues = keys
                    .iter()
                    .enumerate()
                    .map(|(index, key)| (format!("@{index}"), crate::policy::format_key_info(key)))
                    .collect();
                Ok(Self::RegisterDescriptor {
                    descriptor_name: name,
                    descriptor,
                    datavalues,
                })
            }
            Command::SignTx(psbt, _) => Ok(Self::SignPsbt { psbt }),
        }
    }
}

fn jade_multisig_command(address: MultisigDisplayAddress) -> Result<JadeCommand, Error> {
    let variant = match address.address_type {
        MultisigAddressType::Legacy => "sh(multi(k))",
        MultisigAddressType::Wit => "wsh(multi(k))",
        MultisigAddressType::ShWit => "sh(wsh(multi(k)))",
    };
    let mut signer_origins = Vec::with_capacity(address.keys.len());
    let mut signers = Vec::with_capacity(address.keys.len());
    let mut paths = Vec::with_capacity(address.keys.len());

    for key in address.keys {
        let DescriptorPublicKey::XPub(key) = key else {
            return Err(Error::InvalidInput(
                "Jade multisig display requires extended public keys".into(),
            ));
        };
        if key.wildcard != Wildcard::None {
            return Err(Error::InvalidInput(
                "Jade multisig display requires concrete key derivation paths".into(),
            ));
        }
        let (fingerprint, origin_path) = key.origin.ok_or_else(|| {
            Error::InvalidInput("Jade multisig display requires key origin information".into())
        })?;
        let origin = origin_path.to_u32_vec();
        signer_origins.push((fingerprint.to_bytes(), origin.clone()));
        signers.push(api::MultisigSigner {
            fingerprint: fingerprint.to_bytes().to_vec(),
            derivation: origin,
            xpub: key.xkey.to_string(),
            path: Vec::new(),
        });
        paths.push(key.derivation_path.to_u32_vec());
    }

    signer_origins.sort();
    let mut summary = format!("{variant}|{}|", address.threshold);
    for (fingerprint, path) in signer_origins {
        summary.push_str(&hex::encode(fingerprint));
        summary.push('|');
        summary.push_str(&format!("{path:?}"));
        summary.push('|');
    }
    let digest = sha256::Hash::hash(summary.as_bytes());
    let multisig_name = format!("hwi{}", &digest.to_string()[..12]);

    Ok(JadeCommand::RegisterMultisig {
        multisig_name,
        descriptor: api::MultisigDescriptor {
            variant: variant.to_string(),
            sorted: address.sorted,
            threshold: address.threshold,
            signers,
            master_blinding_key: None,
        },
        paths,
    })
}

fn jade_path_variant(address_format: Option<AddressType>) -> Result<&'static str, Error> {
    match address_format.unwrap_or(AddressType::P2wpkh) {
        AddressType::P2pkh => Ok("pkh(k)"),
        AddressType::P2sh => Ok("sh(wpkh(k))"),
        AddressType::P2wpkh => Ok("wpkh(k)"),
        AddressType::P2wsh | AddressType::P2tr => Err(Error::UnsupportedDisplayAddress(
            "Jade does not support this path address format".into(),
        )),
        _ => Err(Error::UnsupportedDisplayAddress(
            "Jade does not support this path address format".into(),
        )),
    }
}

impl From<JadeResponse> for Response {
    fn from(response: JadeResponse) -> Self {
        match response {
            JadeResponse::TaskDone => Self::TaskDone,
            JadeResponse::MasterFingerprint(fingerprint) => Self::MasterFingerprint(fingerprint),
            JadeResponse::Xpub(xpub) => Self::Xpub(xpub),
            JadeResponse::Signature(header, signature) => Self::Signature(header, signature),
            JadeResponse::GetInfo(info) => Self::Info(Info {
                version: info.jade_version,
                networks: info.jade_networks.into(),
                firmware: None,
                initialized: None,
                label: None,
                on_device_passphrase_entry: None,
                needs_pin_sent: None,
                needs_passphrase_sent: None,
            }),
            JadeResponse::Address(address) => Self::Address(address),
            JadeResponse::RegisteredDescriptor => {
                Self::WalletRegistration(WalletRegistration::Complete { hmac: None })
            }
            JadeResponse::SignedPsbt(psbt) => Self::SignedPsbt(psbt),
        }
    }
}

impl From<JadeRecipient> for Recipient {
    fn from(recipient: JadeRecipient) -> Self {
        match recipient {
            JadeRecipient::Device => Self::Device,
            JadeRecipient::PinServer { url } => Self::PinServer { url },
        }
    }
}

impl From<JadeTransmit> for Transmit {
    fn from(transmit: JadeTransmit) -> Self {
        Self {
            recipient: transmit.recipient.into(),
            payload: transmit.payload,
            encrypted: false,
        }
    }
}

impl From<JadeError> for Error {
    fn from(error: JadeError) -> Self {
        match error {
            JadeError::Cbor => Self::Serialization("cbor".to_string()),
            JadeError::NoErrorOrResult => Self::NoErrorOrResult,
            JadeError::Rpc(error) => Self::Rpc(error.code, error.message),
            JadeError::Serialization(error) => Self::Serialization(error),
            JadeError::UnexpectedResult(message) => Self::unexpected_result(
                message.clone().into_bytes(),
                format!("jade unexpected result: {message}"),
            ),
            JadeError::HandshakeRefused => Self::AuthenticationRefused,
            JadeError::UnsupportedDisplayAddress => {
                Self::UnsupportedDisplayAddress("unsupported display address on Jade".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn path_display_rejects_unsupported_jade_address_format() {
        let result = JadeCommand::try_from(Command::DisplayAddress(
            DisplayAddress::ByPath {
                path: "m/86'/1'/0'/0/0".parse().unwrap(),
                display: true,
                address_format: Some(AddressType::P2tr),
            },
            None,
        ));

        assert!(matches!(result, Err(Error::UnsupportedDisplayAddress(_))));
    }

    #[test]
    fn multisig_display_uses_upstream_hwi_registration_shape_and_name() {
        let keys = [
            "[f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/0/7",
            "[00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/0/7",
        ]
        .map(|key| DescriptorPublicKey::from_str(key).unwrap())
        .to_vec();

        let command = jade_multisig_command(MultisigDisplayAddress {
            threshold: 2,
            address_type: MultisigAddressType::Wit,
            sorted: true,
            keys,
        })
        .unwrap();

        let JadeCommand::RegisterMultisig {
            multisig_name,
            descriptor,
            paths,
        } = command
        else {
            panic!("expected multisig registration");
        };
        assert_eq!(multisig_name, "hwi78631c5c8b92");
        assert_eq!(descriptor.variant, "wsh(multi(k))");
        assert!(descriptor.sorted);
        assert_eq!(descriptor.threshold, 2);
        assert_eq!(descriptor.signers.len(), 2);
        assert!(
            descriptor
                .signers
                .iter()
                .all(|signer| signer.path.is_empty())
        );
        assert_eq!(paths, vec![vec![0, 7], vec![0, 7]]);
    }

    #[test]
    fn pin_server_transmit_maps_recipient() {
        let transmit = Transmit::from(JadeTransmit {
            recipient: JadeRecipient::PinServer {
                url: "https://pin.example".into(),
            },
            payload: vec![1, 2, 3],
        });

        assert!(matches!(
            transmit.recipient,
            Recipient::PinServer { ref url } if url == "https://pin.example"
        ));
        assert!(!transmit.encrypted);
    }
}
