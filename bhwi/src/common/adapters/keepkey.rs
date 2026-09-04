use crate::common::{
    Command, DeviceContext, DisplayAddress, MultisigAddressType, MultisigDisplayAddress,
};
use crate::keepkey::{
    KeepKeyCommand, KeepKeyError, KeepKeyMultisigAddress, KeepKeyMultisigAddressType,
    ManagementContext,
};
use crate::trezor::interpreter::{address_n, script_type};

impl TryFrom<Command> for KeepKeyCommand {
    type Error = KeepKeyError;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        Ok(match command {
            Command::Unlock { options } => Self::Initialize(options.network),
            Command::GetVersion => Self::GetFeatures,
            Command::GetMasterFingerprint => Self::GetMasterFingerprint,
            Command::GetXpub { path, display } => Self::GetXpub {
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
            ) => Self::GetAddress {
                address_n: address_n(&path),
                display,
                script_type: script_type(address_format, &path),
            },
            Command::DisplayAddress(DisplayAddress::ByDescriptor { .. }, _) => {
                return Err(KeepKeyError::UnsupportedDisplayAddress(
                    "descriptor address display is not yet supported",
                ));
            }
            Command::DisplayAddress(DisplayAddress::ByMultisig(address), _) => {
                Self::GetMultisigAddress(multisig_address(address))
            }
            Command::SignTx(psbt, context) => {
                if context.is_some() {
                    return Err(KeepKeyError::Unsupported(
                        "KeepKey SignTx does not support device context",
                    ));
                }
                Self::SignTx(Box::new(psbt))
            }
            Command::SignMessage { message, path } => Self::SignMessage {
                address_n: address_n(&path),
                message,
            },
            Command::RegisterWallet { .. } => {
                return Err(KeepKeyError::Unsupported(
                    "register_wallet is not supported",
                ));
            }
            Command::Backup => {
                return Err(KeepKeyError::Unsupported(
                    "The Keepkey does not support creating a backup via software",
                ));
            }
            Command::Setup(options, context) => {
                let Some(DeviceContext::KeepKeyManagement(ManagementContext::Setup {
                    host_entropy,
                })) = context
                else {
                    return Err(KeepKeyError::Unsupported(
                        "KeepKey setup requires host entropy in the device context",
                    ));
                };
                Self::Setup {
                    label: (!options.label.is_empty()).then_some(options.label),
                    host_entropy,
                }
            }
            Command::Wipe => Self::Wipe,
            Command::Restore(options, context) => {
                let Some(DeviceContext::KeepKeyManagement(ManagementContext::Restore {
                    u2f_counter,
                })) = context
                else {
                    return Err(KeepKeyError::Unsupported(
                        "KeepKey restore requires a U2F counter in the device context",
                    ));
                };
                let word_count = u32::try_from(options.word_count).map_err(|_| {
                    KeepKeyError::InvalidInput("restore word count must be positive".into())
                })?;
                if !matches!(word_count, 12 | 18 | 24) {
                    return Err(KeepKeyError::InvalidInput(
                        "restore word count must be 12, 18, or 24".into(),
                    ));
                }
                Self::Restore {
                    label: (!options.label.is_empty()).then_some(options.label),
                    word_count,
                    u2f_counter,
                }
            }
            Command::TogglePassphrase => Self::TogglePassphrase,
            Command::PromptPin => Self::PromptPin,
            Command::SendPin(context) => {
                let Some(DeviceContext::KeepKeyManagement(ManagementContext::Pin(pin))) = context
                else {
                    return Err(KeepKeyError::Unsupported(
                        "KeepKey sendpin requires the PIN positions in the device context",
                    ));
                };
                Self::SendPin(pin)
            }
        })
    }
}

fn multisig_address(address: MultisigDisplayAddress) -> KeepKeyMultisigAddress {
    KeepKeyMultisigAddress {
        threshold: address.threshold,
        address_type: match address.address_type {
            MultisigAddressType::Legacy => KeepKeyMultisigAddressType::Legacy,
            MultisigAddressType::ShWit => KeepKeyMultisigAddressType::ShWit,
            MultisigAddressType::Wit => KeepKeyMultisigAddressType::Wit,
        },
        sorted: address.sorted,
        keys: address.keys,
    }
}
