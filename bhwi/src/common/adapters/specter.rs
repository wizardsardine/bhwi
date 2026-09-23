use bitcoin::address::AddressType;

use crate::common::{
    Command, DeviceContext, DisplayAddress, Error, Recipient, Response, Transmit,
    WalletRegistration,
};
use crate::specter::{
    SpecterAddressType, SpecterCommand, SpecterError, SpecterResponse, SpecterTransmit,
    descriptor_address,
};

impl TryFrom<Command> for SpecterCommand {
    type Error = SpecterError;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        match command {
            Command::GetMasterFingerprint | Command::Unlock { .. } => Ok(Self::Fingerprint),
            Command::GetXpub {
                path,
                display: false,
            } => Ok(Self::Xpub { path }),
            Command::GetXpub { display: true, .. } => Err(SpecterError::UnsupportedCommand(
                "Specter-DIY has no displayed xpub command",
            )),
            Command::SignTx(psbt, context) => {
                if context.is_some() && !matches!(context, Some(DeviceContext::Specter { .. })) {
                    return Err(SpecterError::MissingContext(
                        "Specter signing accepts only DeviceContext::Specter",
                    ));
                }
                Ok(Self::SignPsbt { psbt })
            }
            Command::SignMessage { message, path } => Ok(Self::SignMessage { path, message }),
            Command::RegisterWallet { name, policy } => Ok(Self::RegisterWallet { name, policy }),
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path,
                    display: true,
                    address_format,
                },
                _,
            ) => {
                let script_type = match address_format.unwrap_or(AddressType::P2wpkh) {
                    AddressType::P2pkh => SpecterAddressType::Pkh,
                    AddressType::P2sh => SpecterAddressType::ShWpkh,
                    AddressType::P2wpkh => SpecterAddressType::Wpkh,
                    _ => {
                        return Err(SpecterError::UnsupportedDisplayAddress(
                            "path display supports pkh, sh-wpkh, and wpkh".into(),
                        ));
                    }
                };
                Ok(Self::ShowAddress {
                    script_type,
                    // rust-bitcoin displays derivation paths without the root marker;
                    // Specter's showaddr command needs m/ to distinguish a path
                    // from a fingerprint-prefixed origin.
                    derivation: format!("m/{path}"),
                    script: None,
                })
            }
            Command::DisplayAddress(DisplayAddress::ByPath { display: false, .. }, _) => {
                Err(SpecterError::UnsupportedDisplayAddress(
                    "Specter-DIY cannot retrieve an undisplayed address".into(),
                ))
            }
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    index,
                    change,
                    display: true,
                    ..
                },
                Some(DeviceContext::Specter { policy }),
            ) => {
                let (script_type, derivation, script) = descriptor_address(&policy, change, index)?;
                Ok(Self::ShowAddress {
                    script_type,
                    derivation,
                    script,
                })
            }
            Command::DisplayAddress(DisplayAddress::ByDescriptor { display: false, .. }, _) => {
                Err(SpecterError::UnsupportedDisplayAddress(
                    "Specter-DIY cannot retrieve an undisplayed address".into(),
                ))
            }
            Command::DisplayAddress(DisplayAddress::ByDescriptor { .. }, _) => {
                Err(SpecterError::MissingContext(
                    "Specter descriptor display requires DeviceContext::Specter",
                ))
            }
            Command::DisplayAddress(DisplayAddress::ByMultisig(_), _) => {
                Err(SpecterError::UnsupportedDisplayAddress(
                    "raw multisig display requires a descriptor policy".into(),
                ))
            }
            Command::GetVersion => Err(SpecterError::UnsupportedCommand(
                "firmware version is not exposed by this protocol",
            )),
            Command::Backup
            | Command::Setup(..)
            | Command::Wipe
            | Command::Restore(..)
            | Command::TogglePassphrase
            | Command::PromptPin
            | Command::SendPin(_) => Err(SpecterError::UnsupportedCommand(
                "operation is selected or performed on Specter-DIY itself",
            )),
        }
    }
}

impl From<SpecterResponse> for Response {
    fn from(response: SpecterResponse) -> Self {
        match response {
            SpecterResponse::TaskDone => {
                Self::WalletRegistration(WalletRegistration::Complete { hmac: None })
            }
            SpecterResponse::MasterFingerprint(fingerprint) => Self::MasterFingerprint(fingerprint),
            SpecterResponse::Xpub(xpub) => Self::Xpub(xpub),
            SpecterResponse::SignedPsbt(psbt) => Self::SignedPsbt(psbt),
            SpecterResponse::Signature(header, signature) => Self::Signature(header, signature),
            SpecterResponse::Address(address) => Self::Address(address),
        }
    }
}

impl From<SpecterTransmit> for Transmit {
    fn from(transmit: SpecterTransmit) -> Self {
        Self {
            recipient: Recipient::Device,
            payload: transmit.payload,
            encrypted: false,
        }
    }
}

impl From<SpecterError> for Error {
    fn from(error: SpecterError) -> Self {
        match error {
            SpecterError::MissingContext(message) | SpecterError::UnsupportedCommand(message) => {
                Self::MissingCommandInfo(message)
            }
            SpecterError::UnsupportedDisplayAddress(message) => {
                Self::UnsupportedDisplayAddress(message)
            }
            SpecterError::InvalidInput(message)
            | SpecterError::MalformedPayload(message)
            | SpecterError::NetworkMismatch(message) => Self::InvalidInput(message),
            SpecterError::UserCancelled => Self::UserCancelled,
            SpecterError::Refused(message) => Self::Device(format!("Specter-DIY: {message}")),
            SpecterError::MalformedFraming(message) | SpecterError::State(message) => {
                Self::Serialization(message.into())
            }
            SpecterError::ResponseTooLarge => {
                Self::Serialization("Specter response too large".into())
            }
            SpecterError::Timeout => Self::Request("Specter request timed out"),
            SpecterError::Disconnected => Self::Request("Specter transport disconnected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::DerivationPath;
    use miniscript::descriptor::WalletPolicy;

    use super::*;

    const POLICY: &str = "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*)";

    #[test]
    fn path_display_uses_a_rooted_specter_derivation() {
        let command = Command::DisplayAddress(
            DisplayAddress::ByPath {
                path: "m/84'/0'/0'/0/0".parse().unwrap(),
                display: true,
                address_format: Some(AddressType::P2wpkh),
            },
            None,
        );
        let SpecterCommand::ShowAddress { derivation, .. } =
            SpecterCommand::try_from(command).unwrap()
        else {
            panic!("expected a Specter address command");
        };
        assert_eq!(derivation, "m/84'/0'/0'/0/0");
    }

    #[test]
    fn descriptor_display_requires_policy_and_resolves_branch() {
        let command = Command::DisplayAddress(
            DisplayAddress::ByDescriptor {
                index: 7,
                change: true,
                display: true,
                descriptor_name: "ignored".into(),
            },
            Some(DeviceContext::Specter {
                policy: WalletPolicy::from_str(POLICY).unwrap(),
            }),
        );
        let command = SpecterCommand::try_from(command).unwrap();
        let SpecterCommand::ShowAddress {
            script_type,
            derivation,
            ..
        } = command
        else {
            panic!("expected a Specter address command");
        };
        assert_eq!(script_type, SpecterAddressType::Wpkh);
        assert_eq!(derivation, "f5acc2fd/84'/1'/0'/1/7");
    }

    #[test]
    fn undisplayed_and_xpub_display_are_rejected() {
        assert!(
            SpecterCommand::try_from(Command::GetXpub {
                path: DerivationPath::master(),
                display: true
            })
            .is_err()
        );
    }
}
