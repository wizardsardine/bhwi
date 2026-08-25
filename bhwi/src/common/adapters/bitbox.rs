use bitcoin::address::AddressType;
use bitcoin::bip32::{ChildNumber, DerivationPath};

use crate::bitbox::error::{BitBoxDeviceError, BitBoxError};
use crate::bitbox::policy;
use crate::bitbox::proto as pb;
use crate::bitbox::{BitBoxCommand, BitBoxResponse, BitBoxTransmit, ManagementContext};
use crate::common::{
    Command, DeviceBackup, DeviceContext, DisplayAddress, Error, Info, Recipient, Response,
    Transmit, WalletRegistration,
};

impl TryFrom<Command> for BitBoxCommand {
    type Error = BitBoxError;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        match command {
            Command::Setup(options, context) => {
                if !options.backup_passphrase.is_empty() {
                    return Err(BitBoxError::InvalidInput(
                        "Passphrase not needed when setting up a BitBox02.",
                    ));
                }
                let Some(DeviceContext::BitBoxManagement(ManagementContext::Setup {
                    mode,
                    timestamp,
                    timezone_offset,
                })) = context
                else {
                    return Err(BitBoxError::InvalidInput(
                        "BitBox setup requires DeviceContext::BitBoxManagement",
                    ));
                };
                Ok(Self::Setup {
                    label: options.label,
                    mode,
                    timestamp,
                    timezone_offset,
                })
            }
            Command::Wipe => Ok(Self::Wipe),
            Command::Restore(options, context) => {
                let Some(DeviceContext::BitBoxManagement(ManagementContext::Restore {
                    timestamp,
                    timezone_offset,
                })) = context
                else {
                    return Err(BitBoxError::InvalidInput(
                        "BitBox restore requires DeviceContext::BitBoxManagement",
                    ));
                };
                Ok(Self::Restore {
                    label: options.label,
                    timestamp,
                    timezone_offset,
                })
            }
            Command::TogglePassphrase => Ok(Self::TogglePassphrase),
            Command::PromptPin | Command::SendPin(_) => Err(BitBoxError::InvalidInput(
                "PIN entry from the host not needed by BitBox02",
            )),
            Command::Unlock { .. } => Ok(Self::UnlockAndPair),
            Command::GetVersion => Ok(Self::GetVersion),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, display } => Ok(Self::GetXpub {
                keypath: path,
                display,
            }),
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path,
                    display,
                    address_format,
                },
                _,
            ) => Ok(Self::ShowSimpleAddress {
                simple_type: simple_type_from_address_format(&path, address_format)?,
                keypath: path,
                display,
            }),
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    index,
                    change,
                    display,
                    ..
                },
                context,
            ) => {
                let policy = match context {
                    Some(DeviceContext::BitBox { policy }) => {
                        policy::Policy::from_wallet_policy(&policy)?
                    }
                    _ => {
                        return Err(BitBoxError::InvalidInput(
                            "BitBox requires DeviceContext::BitBox for descriptor address display",
                        ));
                    }
                };
                Ok(Self::ShowDescriptorAddress {
                    policy,
                    change,
                    index,
                    display,
                })
            }
            Command::DisplayAddress(DisplayAddress::ByMultisig(_), _) => Err(
                BitBoxError::InvalidInput("BitBox raw multisig display is not implemented"),
            ),
            Command::RegisterWallet { name, policy } => Ok(Self::RegisterScriptConfig {
                policy: policy::Policy::from_wallet_policy(&policy)?,
                name,
            }),
            Command::SignTx(psbt, context) => {
                // A BitBox context supplies the registered policy. Without it, the
                // interpreter can still infer single-sig inputs from the PSBT.
                let policy = match context {
                    None => None,
                    Some(DeviceContext::BitBox { policy }) => {
                        Some(policy::Policy::from_wallet_policy(&policy)?)
                    }
                    Some(_) => {
                        return Err(BitBoxError::InvalidInput(
                            "BitBox requires DeviceContext::BitBox for policy signing",
                        ));
                    }
                };
                Ok(Self::SignPsbt {
                    psbt: Box::new(psbt),
                    force_script_config: None,
                    policy,
                })
            }
            Command::SignMessage { message, path } => Ok(Self::SignMessage {
                simple_type: simple_type_from_path(&path),
                keypath: path,
                message,
            }),
            Command::Backup => Ok(Self::Backup),
        }
    }
}

fn simple_type_from_path(path: &DerivationPath) -> pb::btc_script_config::SimpleType {
    use pb::btc_script_config::SimpleType;

    match path.into_iter().next() {
        Some(ChildNumber::Hardened { index: 49 }) => SimpleType::P2wpkhP2sh,
        Some(ChildNumber::Hardened { index: 86 }) => SimpleType::P2tr,
        _ => SimpleType::P2wpkh,
    }
}

fn simple_type_from_address_format(
    path: &DerivationPath,
    address_format: Option<AddressType>,
) -> Result<pb::btc_script_config::SimpleType, BitBoxError> {
    use pb::btc_script_config::SimpleType;

    match address_format {
        None => Ok(simple_type_from_path(path)),
        Some(AddressType::P2sh) => Ok(SimpleType::P2wpkhP2sh),
        Some(AddressType::P2wpkh) => Ok(SimpleType::P2wpkh),
        Some(AddressType::P2tr) => Ok(SimpleType::P2tr),
        Some(AddressType::P2pkh | AddressType::P2wsh) | Some(_) => Err(BitBoxError::InvalidInput(
            "BitBox does not support this address format",
        )),
    }
}

impl From<BitBoxResponse> for Response {
    fn from(response: BitBoxResponse) -> Self {
        match response {
            BitBoxResponse::TaskDone => Self::TaskDone,
            BitBoxResponse::DeviceAction(success) => Self::DeviceAction(success),
            BitBoxResponse::Info(info) => Self::Info(Info {
                version: info.version,
                networks: vec![],
                firmware: Some(info.name),
                initialized: Some(info.initialized),
                label: None,
                on_device_passphrase_entry: None,
                needs_pin_sent: None,
            }),
            BitBoxResponse::MasterFingerprint(fingerprint) => Self::MasterFingerprint(fingerprint),
            BitBoxResponse::Xpub(xpub) => Self::Xpub(xpub),
            BitBoxResponse::Address(address) => Self::Address(address),
            BitBoxResponse::IsRegistered(_) => Self::TaskDone,
            BitBoxResponse::Registered => {
                Self::WalletRegistration(WalletRegistration::Complete { hmac: None })
            }
            BitBoxResponse::SignedPsbt(psbt) => Self::SignedPsbt(*psbt),
            BitBoxResponse::Signature(header, signature) => Self::Signature(header, signature),
            BitBoxResponse::Backup => Self::Backup(DeviceBackup::Complete),
        }
    }
}

impl From<BitBoxError> for Error {
    fn from(error: BitBoxError) -> Self {
        match error {
            BitBoxError::Device(BitBoxDeviceError::UserAbort)
            | BitBoxError::NoisePairingRejected => Self::AuthenticationRefused,
            BitBoxError::ProtobufDecode(error) | BitBoxError::ProtobufEncode(error) => {
                Self::Serialization(error)
            }
            other => Self::Serialization(other.to_string()),
        }
    }
}

impl From<BitBoxTransmit> for Transmit {
    fn from(transmit: BitBoxTransmit) -> Self {
        Self {
            recipient: Recipient::Device,
            payload: transmit.payload,
            encrypted: transmit.encrypted,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::DerivationPath;

    use super::*;
    use crate::bitbox::{SetupEntropy, SetupMode};
    use crate::common::{RestoreOptions, SetupOptions};

    fn simple(path: &str) -> pb::btc_script_config::SimpleType {
        simple_type_from_path(&DerivationPath::from_str(path).unwrap())
    }

    #[test]
    fn simple_type_matches_purpose() {
        use pb::btc_script_config::SimpleType;

        assert_eq!(simple("m/84'/0'/0'/0/0"), SimpleType::P2wpkh);
        assert_eq!(simple("m/49'/0'/0'/0/0"), SimpleType::P2wpkhP2sh);
        assert_eq!(simple("m/86'/0'/0'/0/0"), SimpleType::P2tr);
        assert_eq!(simple("m/44'/0'/0'/0/0"), SimpleType::P2wpkh);
    }

    #[test]
    fn display_path_address_format_selects_simple_type() {
        use pb::btc_script_config::SimpleType;

        let path = DerivationPath::from_str("m/49'/0'/0'/0/0").unwrap();

        assert_eq!(
            simple_type_from_address_format(&path, Some(AddressType::P2sh)).unwrap(),
            SimpleType::P2wpkhP2sh
        );
        assert_eq!(
            simple_type_from_address_format(&path, Some(AddressType::P2wpkh)).unwrap(),
            SimpleType::P2wpkh
        );
        assert_eq!(
            simple_type_from_address_format(&path, Some(AddressType::P2tr)).unwrap(),
            SimpleType::P2tr
        );
        assert_eq!(
            simple_type_from_address_format(&path, None).unwrap(),
            SimpleType::P2wpkhP2sh
        );
        assert!(simple_type_from_address_format(&path, Some(AddressType::P2pkh)).is_err());
    }

    #[test]
    fn backup_maps_to_bitbox_backup() {
        assert!(matches!(
            BitBoxCommand::try_from(Command::Backup),
            Ok(BitBoxCommand::Backup)
        ));
    }

    #[test]
    fn setup_maps_to_bitbox_setup() {
        let command = BitBoxCommand::try_from(Command::Setup(
            SetupOptions {
                label: "BHWI".into(),
                backup_passphrase: String::new(),
            },
            Some(DeviceContext::BitBoxManagement(ManagementContext::Setup {
                mode: SetupMode::NewWallet {
                    entropy: SetupEntropy::new([42; 32]),
                },
                timestamp: 1_601_450_521,
                timezone_offset: 3_600,
            })),
        ))
        .unwrap();

        assert!(matches!(
            command,
            BitBoxCommand::Setup {
                label,
                mode: SetupMode::NewWallet { .. },
                timestamp: 1_601_450_521,
                timezone_offset: 3_600,
            } if label == "BHWI"
        ));
    }

    #[test]
    fn setup_requires_context_and_rejects_passphrase() {
        let missing_context =
            BitBoxCommand::try_from(Command::Setup(SetupOptions::default(), None));
        assert!(matches!(missing_context, Err(BitBoxError::InvalidInput(_))));

        let passphrase = BitBoxCommand::try_from(Command::Setup(
            SetupOptions {
                label: String::new(),
                backup_passphrase: "secret".into(),
            },
            Some(DeviceContext::BitBoxManagement(ManagementContext::Setup {
                mode: SetupMode::RestoreFromMnemonic,
                timestamp: 0,
                timezone_offset: 0,
            })),
        ));
        assert!(matches!(passphrase, Err(BitBoxError::InvalidInput(_))));
    }

    #[test]
    fn setup_response_maps_to_device_action() {
        assert!(matches!(
            Response::from(BitBoxResponse::DeviceAction(false)),
            Response::DeviceAction(false)
        ));
    }

    #[test]
    fn wipe_maps_to_bitbox_wipe() {
        assert!(matches!(
            BitBoxCommand::try_from(Command::Wipe),
            Ok(BitBoxCommand::Wipe)
        ));
    }

    #[test]
    fn restore_maps_to_bitbox_restore_and_ignores_word_count() {
        let command = BitBoxCommand::try_from(Command::Restore(
            RestoreOptions {
                label: "Recovered".into(),
                word_count: 12,
            },
            Some(DeviceContext::BitBoxManagement(
                ManagementContext::Restore {
                    timestamp: 1_601_450_521,
                    timezone_offset: -3_600,
                },
            )),
        ))
        .unwrap();

        assert!(matches!(
            command,
            BitBoxCommand::Restore {
                label,
                timestamp: 1_601_450_521,
                timezone_offset: -3_600,
            } if label == "Recovered"
        ));
    }

    #[test]
    fn restore_requires_context() {
        assert!(matches!(
            BitBoxCommand::try_from(Command::Restore(RestoreOptions::default(), None)),
            Err(BitBoxError::InvalidInput(_))
        ));
    }

    #[test]
    fn toggle_passphrase_maps_to_bitbox_command() {
        assert!(matches!(
            BitBoxCommand::try_from(Command::TogglePassphrase),
            Ok(BitBoxCommand::TogglePassphrase)
        ));
    }

    #[test]
    fn backup_response_maps_to_completed_backup() {
        assert!(matches!(
            Response::from(BitBoxResponse::Backup),
            Response::Backup(DeviceBackup::Complete)
        ));
    }

    #[test]
    fn native_transmit_maps_to_device_recipient() {
        let transmit = Transmit::from(BitBoxTransmit {
            payload: vec![1, 2, 3],
            encrypted: true,
        });

        assert!(matches!(transmit.recipient, Recipient::Device));
        assert_eq!(transmit.payload, vec![1, 2, 3]);
        assert!(transmit.encrypted);
    }
}
