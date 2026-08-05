use crate::common::{
    Command, DeviceContext, DisplayAddress, Error, Info, Recipient, Response, Transmit,
    WalletRegistration,
};
use crate::ledger::apdu::ApduCommand;
use crate::ledger::store::StoreError;
use crate::ledger::{
    LedgerCommand, LedgerDisplayAddress, LedgerError, LedgerResponse, LedgerWalletPolicy, Version,
};

impl TryFrom<Command> for LedgerCommand {
    type Error = LedgerError;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        match command {
            Command::Setup(..) => Err(LedgerError::MissingCommandInfo(
                "Setup not supported by Ledger",
            )),
            Command::Wipe => Err(LedgerError::MissingCommandInfo(
                "Wipe not supported by Ledger",
            )),
            Command::Restore(..) => Err(LedgerError::MissingCommandInfo(
                "Restore not supported by Ledger",
            )),
            Command::TogglePassphrase => Err(LedgerError::MissingCommandInfo(
                "Toggle passphrase not supported by Ledger",
            )),
            Command::PromptPin | Command::SendPin(_) => Err(LedgerError::MissingCommandInfo(
                "PIN entry from the host not needed by Ledger",
            )),
            Command::Backup => Err(LedgerError::MissingCommandInfo(
                "Backup not supported by Ledger",
            )),
            Command::Unlock { options } => options
                .network
                .map(Self::OpenApp)
                .ok_or(LedgerError::MissingCommandInfo("network")),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, display } => Ok(Self::GetXpub { path, display }),
            Command::DisplayAddress(address, context) => {
                let address = match address {
                    DisplayAddress::ByPath { path, display, .. } => {
                        LedgerDisplayAddress::ByPath { path, display }
                    }
                    DisplayAddress::ByDescriptor {
                        index,
                        change,
                        display,
                        ..
                    } => {
                        let (policy, hmac) = context
                            .and_then(|context| match context {
                                DeviceContext::Ledger {
                                    wallet_policy,
                                    wallet_hmac,
                                } => Some((wallet_policy, wallet_hmac)),
                                #[cfg(feature = "bitbox")]
                                _ => None,
                            })
                            .ok_or(LedgerError::MissingCommandInfo(
                                "Ledger requires DeviceContext::Ledger for descriptor-based address display",
                            ))?;
                        LedgerDisplayAddress::ByWalletPolicy {
                            policy,
                            hmac,
                            change,
                            address_index: index,
                            display,
                        }
                    }
                    DisplayAddress::ByMultisig(_) => {
                        return Err(LedgerError::UnsupportedDisplayAddress(
                            "Ledger raw multisig display is not implemented".into(),
                        ));
                    }
                };
                Ok(Self::GetWalletAddress { address })
            }
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetAppInfo),
            Command::RegisterWallet { name, policy } => Ok(Self::RegisterWallet {
                policy: LedgerWalletPolicy::new(name, Version::V2, policy),
            }),
            Command::SignTx(psbt, context) => {
                let (policy, hmac) = context
                    .and_then(|context| match context {
                        DeviceContext::Ledger {
                            wallet_policy,
                            wallet_hmac,
                        } => Some((wallet_policy, wallet_hmac)),
                        #[cfg(feature = "bitbox")]
                        _ => None,
                    })
                    .ok_or(LedgerError::MissingCommandInfo("ledger sign tx context"))?;
                Ok(Self::SignPsbt { psbt, policy, hmac })
            }
        }
    }
}

impl From<LedgerResponse> for Response {
    fn from(response: LedgerResponse) -> Self {
        match response {
            LedgerResponse::AppInfo(response) => {
                let network = response.network();
                Self::Info(Info {
                    version: response.version,
                    networks: vec![network],
                    firmware: Some(response.app_name),
                    initialized: None,
                    label: None,
                    on_device_passphrase_entry: None,
                    needs_pin_sent: None,
                })
            }
            LedgerResponse::Signature(header, signature) => Self::Signature(header, signature),
            LedgerResponse::TaskDone => Self::TaskDone,
            LedgerResponse::Xpub(xpub) => Self::Xpub(xpub),
            LedgerResponse::MasterFingerprint(fingerprint) => Self::MasterFingerprint(fingerprint),
            LedgerResponse::Address(address) => Self::Address(address),
            LedgerResponse::WalletHmac(hmac) => {
                Self::WalletRegistration(WalletRegistration::Complete { hmac: Some(hmac) })
            }
            LedgerResponse::SignedPsbt(psbt) => Self::SignedPsbt(psbt),
        }
    }
}

impl From<LedgerError> for Error {
    fn from(error: LedgerError) -> Self {
        match error {
            LedgerError::MissingCommandInfo(error) => Self::MissingCommandInfo(error),
            LedgerError::NoErrorOrResult => Self::NoErrorOrResult,
            LedgerError::Apdu(error) => Self::Serialization(format!("{error:?}")),
            LedgerError::Store(error) => Self::Request(match error {
                StoreError::EmptyInput => "Store operation failed: empty request",
                StoreError::UnknownCommand(_) => "Store operation failed: unknown command",
                StoreError::UnsupportedRequest(_) => "Store operation failed: unsupported request",
                StoreError::InvalidIndexOrSize => {
                    "Store operation failed: invalid Merkle index or size"
                }
                StoreError::UnknownHash => "Store operation failed: unknown hash",
                StoreError::UnknownMerkleRoot => "Store operation failed: unknown Merkle root",
                StoreError::UnexpectedQueue => "Store operation failed: unexpected queue state",
            }),
            LedgerError::Wallet(_) => Self::Request("Wallet operation failed"),
            LedgerError::Interrupted => Self::Request("Operation interrupted"),
            LedgerError::UnexpectedResult(data, context) => Self::unexpected_result(data, context),
            LedgerError::UnsupportedDisplayAddress(context) => {
                Self::UnsupportedDisplayAddress(context)
            }
            LedgerError::FailedToOpenApp(_) => Self::AuthenticationRefused,
            LedgerError::InvalidPsbt(error) => Self::Serialization(error),
        }
    }
}

impl From<ApduCommand> for Transmit {
    fn from(command: ApduCommand) -> Self {
        Self {
            recipient: Recipient::Device,
            payload: command.encode(),
            encrypted: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::Network;
    use bitcoin::bip32::DerivationPath;
    use miniscript::descriptor::{DescriptorPublicKey, WalletPolicy};

    use super::*;
    use crate::Interpreter;
    use crate::common::LedgerInterpreter;

    const KEY: &str = "[f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";

    #[test]
    fn path_display_maps_to_ledger_native_address() {
        let path = DerivationPath::from_str("m/84'/1'/0'/0/7").unwrap();
        let command = LedgerCommand::try_from(Command::DisplayAddress(
            DisplayAddress::ByPath {
                path: path.clone(),
                display: true,
                address_format: None,
            },
            None,
        ))
        .unwrap();

        assert!(matches!(
            command,
            LedgerCommand::GetWalletAddress {
                address: LedgerDisplayAddress::ByPath {
                    path: mapped,
                    display: true,
                },
            } if mapped == path
        ));
    }

    #[test]
    fn descriptor_display_maps_context_to_wallet_policy_request() {
        let policy = LedgerWalletPolicy::new("wallet".into(), Version::V2, wallet_policy());
        let command = LedgerCommand::try_from(Command::DisplayAddress(
            DisplayAddress::ByDescriptor {
                index: 3,
                change: true,
                display: true,
                descriptor_name: "ignored-by-ledger".into(),
            },
            Some(DeviceContext::Ledger {
                wallet_policy: policy,
                wallet_hmac: Some([42; 32]),
            }),
        ))
        .unwrap();

        assert!(matches!(
            command,
            LedgerCommand::GetWalletAddress {
                address: LedgerDisplayAddress::ByWalletPolicy {
                    hmac: Some(hmac),
                    change: true,
                    address_index: 3,
                    display: true,
                    ..
                },
            } if hmac == [42; 32]
        ));
    }

    #[test]
    fn descriptor_display_requires_ledger_context() {
        let result = LedgerCommand::try_from(Command::DisplayAddress(
            DisplayAddress::ByDescriptor {
                index: 0,
                change: false,
                display: true,
                descriptor_name: "wallet".into(),
            },
            None,
        ));

        assert!(matches!(result, Err(LedgerError::MissingCommandInfo(_))));
    }

    #[test]
    fn policy_display_starts_with_wallet_address_apdu() {
        let policy = LedgerWalletPolicy::new("wallet".into(), Version::V2, wallet_policy());
        let mut interpreter = LedgerInterpreter::default();
        let transmit = interpreter
            .start(Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    index: 0,
                    change: false,
                    display: true,
                    descriptor_name: "wallet".into(),
                },
                Some(DeviceContext::Ledger {
                    wallet_policy: policy,
                    wallet_hmac: None,
                }),
            ))
            .unwrap();

        assert_eq!(
            transmit.payload[1],
            crate::ledger::apdu::BitcoinCommandCode::GetWalletAddress as u8
        );
    }

    #[test]
    fn nonstandard_xpub_path_retries_with_display() {
        let path = DerivationPath::from_str("m/0h/0h/4h").unwrap();
        let mut interpreter = LedgerInterpreter::default();

        let initial = interpreter
            .start(Command::GetXpub {
                path,
                display: false,
            })
            .unwrap();
        assert_eq!(initial.payload[5], 0);

        let retry = interpreter
            .exchange(vec![0x6a, 0x82])
            .unwrap()
            .expect("non-standard path should be retried");
        assert_eq!(retry.payload[5], 1);
    }

    fn wallet_policy() -> WalletPolicy {
        let mut policy = WalletPolicy::from_str("wpkh(@0/**)").unwrap();
        let key = DescriptorPublicKey::from_str(KEY).unwrap();
        policy.set_key_info(&[key]).unwrap();
        policy
    }

    #[test]
    fn unlock_preserves_network_mapping() {
        assert!(matches!(
            LedgerCommand::try_from(Command::Unlock {
                options: crate::common::UnlockOptions {
                    network: Some(Network::Testnet),
                },
            }),
            Ok(LedgerCommand::OpenApp(Network::Testnet))
        ));
    }
}
