use crate::common::{
    Command, DeviceCode, DeviceContext, DisplayAddress, Error, ErrorKind, Info,
    MultisigAddressType, MultisigDisplayAddress, Response,
};
use crate::trezor::ManagementContext;
use crate::trezor::error::TrezorError;
use crate::trezor::interpreter::{
    TrezorCommand, TrezorDeviceInfo, TrezorMultisigAddress, TrezorMultisigAddressType,
    TrezorResponse, address_n, script_type,
};

impl TryFrom<Command> for TrezorCommand {
    type Error = TrezorError;

    fn try_from(command: Command) -> Result<Self, TrezorError> {
        Ok(match command {
            Command::Unlock { options } => TrezorCommand::Initialize(options.network),
            Command::GetVersion => TrezorCommand::GetFeatures,
            Command::GetMasterFingerprint => TrezorCommand::GetMasterFingerprint,
            Command::GetXpub { path, display } => TrezorCommand::GetXpub {
                address_n: address_n(&path),
                display,
            },
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path,
                    display,
                    address_format,
                },
                _,
            ) => TrezorCommand::GetAddress {
                address_n: address_n(&path),
                display,
                script_type: script_type(address_format, &path),
            },
            Command::DisplayAddress(DisplayAddress::ByDescriptor { .. }, _) => {
                return Err(TrezorError::UnsupportedDisplayAddress(
                    "descriptor address display is not yet supported",
                ));
            }
            Command::DisplayAddress(DisplayAddress::ByMultisig(address), _) => {
                TrezorCommand::GetMultisigAddress(multisig_address(address))
            }
            Command::SignTx(psbt, context) => {
                if context.is_some() {
                    return Err(TrezorError::Unsupported(
                        "Trezor SignTx does not support device context",
                    ));
                }
                TrezorCommand::SignTx(Box::new(psbt))
            }
            Command::SignMessage { message, path } => TrezorCommand::SignMessage {
                address_n: address_n(&path),
                message,
            },
            Command::RegisterWallet { .. } => {
                return Err(TrezorError::Unsupported("register_wallet is not supported"));
            }
            Command::Backup => {
                return Err(TrezorError::Unsupported("backup is not yet supported"));
            }
            Command::Setup(options, context) => {
                let Some(DeviceContext::TrezorManagement(ManagementContext::Setup {
                    host_entropy,
                })) = context
                else {
                    return Err(TrezorError::MissingContext(
                        "Trezor setup requires host entropy in the device context",
                    ));
                };
                TrezorCommand::Setup {
                    label: (!options.label.is_empty()).then_some(options.label),
                    host_entropy,
                }
            }
            Command::Wipe => TrezorCommand::Wipe,
            Command::Restore(options, context) => {
                let Some(DeviceContext::TrezorManagement(ManagementContext::Restore {
                    u2f_counter,
                })) = context
                else {
                    return Err(TrezorError::MissingContext(
                        "Trezor restore requires a U2F counter in the device context",
                    ));
                };
                let word_count = u32::try_from(options.word_count).map_err(|_| {
                    TrezorError::InvalidInput("restore word count must be positive".into())
                })?;
                if !matches!(word_count, 12 | 18 | 24) {
                    return Err(TrezorError::InvalidInput(
                        "restore word count must be 12, 18, or 24".into(),
                    ));
                }
                TrezorCommand::Restore {
                    label: (!options.label.is_empty()).then_some(options.label),
                    word_count,
                    u2f_counter,
                }
            }
            Command::TogglePassphrase => TrezorCommand::TogglePassphrase,
            Command::PromptPin => TrezorCommand::PromptPin,
            Command::SendPin(context) => {
                let Some(DeviceContext::TrezorManagement(ManagementContext::Pin(pin))) = context
                else {
                    return Err(TrezorError::MissingContext(
                        "Trezor sendpin requires the PIN positions in the device context",
                    ));
                };
                TrezorCommand::SendPin(pin)
            }
        })
    }
}

impl From<TrezorResponse> for Response {
    fn from(response: TrezorResponse) -> Self {
        match response {
            TrezorResponse::Info(info) => Response::Info(device_info(info)),
            TrezorResponse::MasterFingerprint(fingerprint) => {
                Response::MasterFingerprint(fingerprint)
            }
            TrezorResponse::Xpub(xpub) => Response::Xpub(xpub),
            TrezorResponse::Address(address) => Response::Address(address),
            TrezorResponse::Signature(header, signature) => Response::Signature(header, signature),
            TrezorResponse::SignedPsbt(psbt) => Response::SignedPsbt(*psbt),
            TrezorResponse::DeviceAction(success) => Response::DeviceAction(success),
        }
    }
}

impl From<TrezorError> for Error {
    fn from(e: TrezorError) -> Self {
        engine_error(e, DeviceCode::Trezor)
    }
}

pub(super) fn engine_error(e: TrezorError, device_code: fn(i32) -> DeviceCode) -> Error {
    match e {
        TrezorError::Decode(err) => Error::new(ErrorKind::Serialization, err.to_string()),
        TrezorError::MalformedFrame => {
            Error::new(ErrorKind::Serialization, "malformed device message frame")
        }
        TrezorError::UnexpectedMessage(t, ctx) => Error::new(
            ErrorKind::UnexpectedResponse,
            format!("unexpected response to {ctx}: message type {t}"),
        ),
        TrezorError::Failure(Some(code), msg) => {
            Error::new(failure_kind(code), msg).with_device_code(device_code(code))
        }
        TrezorError::Failure(None, msg) => Error::new(ErrorKind::Other, msg),
        TrezorError::Locked(ctx) => Error::new(ErrorKind::Locked, ctx),
        TrezorError::NetworkMismatch => Error::new(
            ErrorKind::WrongNetwork,
            "device returned a key for the wrong network",
        ),
        TrezorError::ActionCancelled(code) => {
            Error::new(ErrorKind::UserCancelled, "").with_device_code(device_code(code))
        }
        TrezorError::AlreadyInitialized => Error::new(
            ErrorKind::AlreadyInitialized,
            "Device is already initialized. Use wipe first and try again",
        ),
        TrezorError::Unsupported(s) => Error::new(ErrorKind::Unsupported, s),
        TrezorError::MissingContext(s) => Error::new(ErrorKind::MissingContext, s),
        TrezorError::UnsupportedDisplayAddress(s) => {
            Error::new(ErrorKind::UnsupportedDisplayAddress, s)
        }
        TrezorError::PassphraseTooLong => {
            Error::new(ErrorKind::InvalidInput, "Passphrase too long")
        }
        TrezorError::NonNumericPin => {
            Error::new(ErrorKind::InvalidInput, "Non-numeric PIN provided")
        }
        TrezorError::AlreadyUnlocked(s) => Error::new(ErrorKind::AlreadyUnlocked, s),
        TrezorError::InvalidInput(s) => Error::new(ErrorKind::InvalidInput, s),
    }
}

fn failure_kind(code: i32) -> ErrorKind {
    use crate::trezor::proto::common::failure::FailureType;
    match FailureType::try_from(code) {
        Ok(FailureType::FailurePinExpected) => ErrorKind::Locked,
        Ok(FailureType::FailurePinInvalid) => ErrorKind::WrongPin,
        Ok(FailureType::FailureNotInitialized) => ErrorKind::NotInitialized,
        Ok(FailureType::FailureFirmwareError) => ErrorKind::DeviceFailure,
        _ => ErrorKind::Other,
    }
}

fn device_info(info: TrezorDeviceInfo) -> Info {
    let needs_host_passphrase = !info.on_device_passphrase_entry && info.passphrase_protection;
    Info {
        version: info.version,
        networks: vec![info.network],
        firmware: info.model,
        initialized: info.initialized,
        label: info.label,
        on_device_passphrase_entry: Some(info.on_device_passphrase_entry),
        needs_pin_sent: Some(info.needs_pin_sent),
        needs_passphrase_sent: Some(needs_host_passphrase),
    }
}

fn multisig_address(address: MultisigDisplayAddress) -> TrezorMultisigAddress {
    TrezorMultisigAddress {
        threshold: address.threshold,
        address_type: match address.address_type {
            MultisigAddressType::Legacy => TrezorMultisigAddressType::Legacy,
            MultisigAddressType::ShWit => TrezorMultisigAddressType::ShWit,
            MultisigAddressType::Wit => TrezorMultisigAddressType::Wit,
        },
        sorted: address.sorted,
        keys: address.keys,
    }
}
