use crate::common::{
    Command, DeviceContext, DisplayAddress, Error, Info, MultisigAddressType,
    MultisigDisplayAddress, Response,
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
                    return Err(TrezorError::Unsupported(
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
                    return Err(TrezorError::Unsupported(
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
                    return Err(TrezorError::Unsupported(
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
        match e {
            TrezorError::Decode(err) => Error::Serialization(err.to_string()),
            TrezorError::MalformedFrame => {
                Error::Serialization("malformed trezor message frame".into())
            }
            TrezorError::UnexpectedMessage(t, ctx) => {
                Error::unexpected_result(t.to_be_bytes().to_vec(), format!("trezor: {ctx}"))
            }
            TrezorError::Failure(code, msg) => Error::Rpc(code, Some(msg)),
            TrezorError::Locked(ctx) => Error::Device(ctx.into()),
            TrezorError::NetworkMismatch => {
                Error::InvalidInput("device returned a key for the wrong network".into())
            }
            TrezorError::ActionCancelled => Error::AuthenticationRefused,
            TrezorError::AlreadyInitialized => {
                Error::Device("Device is already initialized. Use wipe first and try again".into())
            }
            TrezorError::Unsupported(s) => Error::MissingCommandInfo(s),
            TrezorError::UnsupportedDisplayAddress(s) => Error::UnsupportedDisplayAddress(s.into()),
            TrezorError::PassphraseTooLong => Error::InvalidInput("Passphrase too long".into()),
            TrezorError::NonNumericPin => Error::InvalidInput("Non-numeric PIN provided".into()),
            TrezorError::AlreadyUnlocked(s) => Error::DeviceAlreadyUnlocked(s),
            TrezorError::InvalidInput(s) => Error::InvalidInput(s),
        }
    }
}

fn device_info(info: TrezorDeviceInfo) -> Info {
    // Only the Model One takes the passphrase from the host; later models use
    // their own screen. A device that reports no model is a Model One.
    let is_model_one = info.model.as_deref().unwrap_or("1") == "1";
    Info {
        version: info.version,
        networks: vec![info.network],
        firmware: info.model,
        initialized: info.initialized,
        label: info.label,
        on_device_passphrase_entry: Some(info.on_device_passphrase_entry),
        needs_pin_sent: Some(info.needs_pin_sent),
        needs_passphrase_sent: Some(is_model_one && info.passphrase_protection),
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
