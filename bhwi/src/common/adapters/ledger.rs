use crate::common::{
    Command, DeviceCode, DeviceContext, DisplayAddress, Error, ErrorKind, Info, Recipient,
    Response, Transmit, WalletRegistration,
};
use crate::ledger::apdu::{ApduCommand, ApduError, StatusWord};
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
                        // Extract via let-else so no cfg-gated wildcard arm is needed
                        // when other device context variants are feature-gated off.
                        let Some(DeviceContext::Ledger {
                            wallet_policy: policy,
                            wallet_hmac: hmac,
                        }) = context
                        else {
                            return Err(LedgerError::MissingCommandInfo(
                                "Ledger requires DeviceContext::Ledger for descriptor-based address display",
                            ));
                        };
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
                let Some(DeviceContext::Ledger {
                    wallet_policy: policy,
                    wallet_hmac: hmac,
                }) = context
                else {
                    return Err(LedgerError::MissingCommandInfo("ledger sign tx context"));
                };
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
                    needs_passphrase_sent: None,
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
            LedgerError::MissingCommandInfo(error) => Self::new(ErrorKind::Unsupported, error),
            LedgerError::NoErrorOrResult => {
                Self::new(ErrorKind::UnexpectedResponse, "no error or result returned")
            }
            LedgerError::Apdu(ApduError::StatusWordUnknown(status)) => unknown_status(status),
            LedgerError::Apdu(error) => Self::new(ErrorKind::Serialization, error.to_string()),
            LedgerError::Store(error) => Self::new(
                ErrorKind::Protocol,
                match error {
                    StoreError::EmptyInput => "Store operation failed: empty request",
                    StoreError::UnknownCommand(_) => "Store operation failed: unknown command",
                    StoreError::UnsupportedRequest(_) => {
                        "Store operation failed: unsupported request"
                    }
                    StoreError::InvalidIndexOrSize => {
                        "Store operation failed: invalid Merkle index or size"
                    }
                    StoreError::UnknownHash => "Store operation failed: unknown hash",
                    StoreError::UnknownMerkleRoot => "Store operation failed: unknown Merkle root",
                    StoreError::UnexpectedQueue => "Store operation failed: unexpected queue state",
                },
            ),
            LedgerError::Wallet(_) => Self::new(ErrorKind::Protocol, "Wallet operation failed"),
            LedgerError::Interrupted => Self::new(ErrorKind::Protocol, "Operation interrupted"),
            LedgerError::UnexpectedResult(data, context) => Self::new(
                ErrorKind::UnexpectedResponse,
                format!("unexpected response to {context}"),
            )
            .with_data(data),
            LedgerError::UnsupportedDisplayAddress(context) => {
                Self::new(ErrorKind::UnsupportedDisplayAddress, context)
            }
            LedgerError::FailedToOpenApp(_) => {
                Self::new(ErrorKind::NotReady, "Bitcoin app could not be opened")
            }
            LedgerError::Status(status, context) => Self::new(
                status_kind(status),
                LedgerError::Status(status, context).to_string(),
            )
            .with_device_code(DeviceCode::Ledger(status as u16)),
            LedgerError::AppNotReady(status, context) => Self::new(
                ErrorKind::NotReady,
                LedgerError::AppNotReady(status, context).to_string(),
            )
            .with_device_code(DeviceCode::Ledger(status as u16)),
            LedgerError::InvalidPsbt(error) => Self::new(ErrorKind::Serialization, error),
            LedgerError::UserCancelled(status) => Self::new(ErrorKind::UserCancelled, "")
                .with_device_code(DeviceCode::Ledger(status as u16)),
        }
    }
}

/// A refusal reaches here only from a command that never asks the user, so it is not a cancel.
fn status_kind(status: StatusWord) -> ErrorKind {
    match status {
        StatusWord::IncorrectData => ErrorKind::InvalidInput,
        StatusWord::NotSupported | StatusWord::InsNotSupported => ErrorKind::Unsupported,
        StatusWord::WrongP1P2 | StatusWord::WrongDataLength | StatusWord::BadState => {
            ErrorKind::Protocol
        }
        StatusWord::ClaNotSupported => ErrorKind::NotReady,
        StatusWord::SignatureFail => ErrorKind::DeviceFailure,
        StatusWord::Deny
        | StatusWord::SecurityStatusNotSatisfied
        | StatusWord::UserRefusedOnDevice
        | StatusWord::CommandNotAllowed => ErrorKind::Rejected,
        StatusWord::OK | StatusWord::InterruptedExecution => ErrorKind::Protocol,
    }
}

/// Status words from the Ledger OS rather than the Bitcoin app, so absent from its table.
fn unknown_status(status: u16) -> Error {
    let (kind, message) = match status {
        0x5515 => (ErrorKind::Locked, "Ledger device is locked".to_owned()),
        0x6511 | 0x6D02 | 0x6E01 => (ErrorKind::NotReady, "Bitcoin app is not open".to_owned()),
        0x6807 => (
            ErrorKind::NotReady,
            "Bitcoin app is not installed".to_owned(),
        ),
        _ => (
            ErrorKind::Other,
            format!("unknown status word 0x{status:04x}"),
        ),
    };
    Error::new(kind, message).with_device_code(DeviceCode::Ledger(status))
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
    fn sign_message_refusal_status_words_map_to_user_cancelled() {
        for status in [[0x69u8, 0x85], [0x69, 0x82]] {
            let mut interpreter = LedgerInterpreter::default();
            interpreter
                .start(Command::SignMessage {
                    message: b"hello".to_vec(),
                    path: DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                })
                .unwrap();
            let err = match interpreter.exchange(status.to_vec()) {
                Err(err) => err,
                Ok(_) => panic!("expected an error"),
            };
            assert_eq!(err.kind(), ErrorKind::UserCancelled, "{err:?}");
            assert_eq!(
                err.device_code(),
                Some(DeviceCode::Ledger(u16::from_be_bytes(status)))
            );
        }
    }

    fn status_error(command: Command, replies: &[Vec<u8>], status: u16) -> Error {
        let mut interpreter = LedgerInterpreter::default();
        interpreter.start(command).unwrap();
        for reply in replies {
            interpreter.exchange(reply.clone()).unwrap();
        }
        match interpreter.exchange(status.to_be_bytes().to_vec()) {
            Err(err) => err,
            Ok(_) => panic!("{status:#06x}: expected an error"),
        }
    }

    #[test]
    fn every_failed_status_keeps_its_word_and_kind() {
        let path = |s: &str| DerivationPath::from_str(s).unwrap();
        let by_path = move || {
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path: path("m/84'/1'/0'/0/0"),
                    display: true,
                    address_format: None,
                },
                None,
            )
        };
        let fingerprint = vec![0xf5, 0xac, 0xc2, 0xfd, 0x90, 0x00];
        let mut xpub = KEY.split(']').nth(1).unwrap().as_bytes().to_vec();
        xpub.extend([0x90, 0x00]);
        type Case = (&'static str, Box<dyn Fn() -> Command>, Vec<Vec<u8>>);
        let commands: Vec<Case> = vec![
            (
                "fingerprint",
                Box::new(|| Command::GetMasterFingerprint),
                vec![],
            ),
            (
                "silent xpub",
                Box::new(move || Command::GetXpub {
                    path: path("m/84'/1'/0'"),
                    display: false,
                }),
                vec![],
            ),
            ("address fingerprint step", Box::new(by_path), vec![]),
            (
                "address xpub step",
                Box::new(by_path),
                vec![fingerprint.clone()],
            ),
            ("address step", Box::new(by_path), vec![fingerprint, xpub]),
            (
                "sign message",
                Box::new(move || Command::SignMessage {
                    message: b"hello".to_vec(),
                    path: path("m/84'/1'/0'/0/0"),
                }),
                vec![],
            ),
            (
                "register",
                Box::new(|| Command::RegisterWallet {
                    name: "wallet".into(),
                    policy: wallet_policy(),
                }),
                vec![],
            ),
        ];
        for (name, command, replies) in commands {
            for (status, kind) in [
                (0x6A80, ErrorKind::InvalidInput),
                (0x6A82, ErrorKind::Unsupported),
                (0x6A86, ErrorKind::Protocol),
                (0x6A87, ErrorKind::Protocol),
                (0x6D00, ErrorKind::Unsupported),
                (0xB007, ErrorKind::Protocol),
                (0x6901, ErrorKind::Rejected),
            ] {
                if name == "silent xpub" && status == 0x6A82 {
                    continue;
                }
                let err = status_error(command(), &replies, status);
                assert_eq!(err.kind(), kind, "{name} {status:#06x}: {err:?}");
                assert_eq!(err.device_code(), Some(DeviceCode::Ledger(status)));
                assert!(err.message().contains(&format!("{status:#06x}")), "{err}");
            }
        }
    }

    #[test]
    fn policy_display_refusal_maps_to_user_cancelled() {
        let policy = LedgerWalletPolicy::new("wallet".into(), Version::V2, wallet_policy());
        let mut interpreter = LedgerInterpreter::default();
        interpreter
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
        let err = match interpreter.exchange(vec![0x69, 0x85]) {
            Err(err) => err,
            Ok(_) => panic!("expected an error"),
        };
        assert_eq!(err.kind(), ErrorKind::UserCancelled, "{err:?}");
    }

    #[test]
    fn sign_psbt_refusal_maps_to_user_cancelled() {
        use bitcoin::psbt::Psbt;
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
            absolute::LockTime, transaction::Version as TxVersion,
        };

        let psbt = Psbt::from_unsigned_tx(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        })
        .unwrap();
        let policy = LedgerWalletPolicy::new("wallet".into(), Version::V2, wallet_policy());
        let mut interpreter = LedgerInterpreter::default();
        interpreter
            .start(Command::SignTx(
                psbt,
                Some(DeviceContext::Ledger {
                    wallet_policy: policy,
                    wallet_hmac: None,
                }),
            ))
            .unwrap();
        let err = match interpreter.exchange(vec![0x69, 0x82]) {
            Err(err) => err,
            Ok(_) => panic!("expected an error"),
        };
        assert_eq!(err.kind(), ErrorKind::UserCancelled, "{err:?}");
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
