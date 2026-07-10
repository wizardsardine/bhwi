use std::{
    ffi::OsString,
    io::{self, BufRead},
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
};

use bhwi::{
    bitcoin::psbt::Psbt,
    common::{MultisigAddressType, MultisigDisplayAddress, MultisigDisplayKey},
    ledger::{LedgerWalletPolicy, Version, singlesig_wallet_policy},
};
use bhwi_async::{DeviceBackup, DeviceContext, DisplayAddress};
use bitcoin::{
    Network, NetworkKind, PublicKey, ScriptBuf,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub},
    blockdata::{
        opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_16},
        script::{Instruction, PushBytes},
    },
    psbt::Input,
    secp256k1::{PublicKey as SecpPublicKey, XOnlyPublicKey},
};
use clap::{ArgAction, ArgGroup, Parser, Subcommand, ValueEnum, error::ErrorKind};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    descriptor::{DescriptorType, WalletPolicy, checksum},
};
use serde::{Serialize, Serializer};

use crate::{
    Device, DeviceManager, DeviceType,
    config::DeviceSelector,
    get_descriptors::GetDescriptorOptions,
    udev::{UdevRuleSelection, install_udev_rules},
};

type HwiResult<T> = std::result::Result<T, HwiError>;

#[derive(Debug, Clone, Parser)]
#[command(author, version, about = "Python HWI compatible interface")]
pub struct HwiCli {
    #[command(subcommand)]
    command: HwiCliCommand,
    #[arg(long = "device-type", short = 't')]
    device_type: Option<String>,
    #[arg(long = "device-path", short = 'd')]
    device_path: Option<String>,
    #[arg(long, short = 'f')]
    fingerprint: Option<Fingerprint>,
    #[arg(long, short = 'p')]
    password: Option<String>,
    #[arg(long, default_value = "main")]
    chain: String,
    #[arg(long)]
    debug: bool,
    #[arg(long)]
    emulators: bool,
    #[arg(long)]
    stdin: bool,
    #[arg(long, short = 'i')]
    interactive: bool,
    #[arg(long)]
    expert: bool,
    #[arg(long, hide = true)]
    stdinpass: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum HwiCliCommand {
    Enumerate,
    Getmasterxpub {
        #[arg(long = "addr-type", value_enum, default_value = "wit")]
        addr_type: HwiAddressType,
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    Signtx {
        psbt: String,
    },
    Signmessage {
        message: String,
        #[arg(value_parser = clap::value_parser!(DerivationPath))]
        path: DerivationPath,
    },
    #[command(group(
        ArgGroup::new("address_target")
            .required(true)
            .args(["path", "desc"])
    ))]
    Displayaddress {
        #[arg(long, conflicts_with = "desc")]
        path: Option<DerivationPath>,
        #[arg(long, conflicts_with = "path")]
        desc: Option<String>,
        #[arg(long = "addr-type", value_enum, default_value = "wit")]
        addr_type: HwiAddressType,
    },
    Getxpub {
        #[arg(value_parser = clap::value_parser!(DerivationPath))]
        path: DerivationPath,
    },
    Getdescriptors {
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    Getkeypool {
        start: u32,
        end: u32,
        #[arg(long, action = ArgAction::SetTrue, conflicts_with = "nokeypool")]
        keypool: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        nokeypool: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        internal: bool,
        #[arg(long = "addr-type", value_enum, conflicts_with = "all")]
        addr_type: Option<HwiAddressType>,
        #[arg(long, action = ArgAction::SetTrue)]
        all: bool,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long)]
        path: Option<String>,
    },
    Setup {
        #[arg(long, short = 'l', default_value = "")]
        label: String,
        #[arg(long = "backup_passphrase", short = 'b', default_value = "")]
        backup_passphrase: String,
    },
    Wipe,
    Restore {
        #[arg(long = "word_count", short = 'w', default_value_t = 24)]
        word_count: i32,
        #[arg(long, short = 'l', default_value = "")]
        label: String,
    },
    Backup {
        #[arg(long, short = 'l', default_value = "")]
        label: String,
        #[arg(long = "backup_passphrase", short = 'b', default_value = "")]
        backup_passphrase: String,
    },
    Promptpin,
    Sendpin {
        pin: String,
    },
    Togglepassphrase,
    Installudevrules {
        #[arg(long, default_value = "/etc/udev/rules.d/")]
        location: PathBuf,
    },
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Debug, Clone)]
pub struct HwiRequest {
    pub selector: DeviceSelector,
    pub command: HwiCommand,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HwiCommand {
    Enumerate,
    GetMasterXpub {
        addr_type: HwiAddressType,
        account: u32,
    },
    SignTx {
        psbt: String,
    },
    SignMessage {
        message: String,
        path: DerivationPath,
    },
    DisplayAddress(HwiDisplayAddressRequest),
    GetXpub {
        path: DerivationPath,
        expert: bool,
    },
    GetDescriptors {
        account: u32,
    },
    GetKeypool {
        start: u32,
        end: u32,
        internal: bool,
        keypool: bool,
        account: u32,
        addr_type: HwiAddressType,
        all: bool,
        path: Option<String>,
    },
    Backup {
        label: String,
        backup_passphrase: String,
    },
    UnsupportedDeviceAction(HwiUnsupportedDeviceAction),
    InstallUdevRules {
        location: PathBuf,
    },
    Unsupported(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HwiUnsupportedDeviceAction {
    Setup {
        interactive: bool,
        label: String,
        backup_passphrase: String,
    },
    Wipe,
    Restore {
        interactive: bool,
        word_count: i32,
        label: String,
    },
    Backup {
        label: String,
        backup_passphrase: String,
    },
    PromptPin,
    SendPin {
        pin: String,
    },
    TogglePassphrase,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HwiDisplayAddressRequest {
    Path {
        path: DerivationPath,
        addr_type: HwiAddressType,
    },
    Descriptor {
        descriptor: String,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum HwiAddressType {
    #[value(name = "legacy")]
    Legacy,
    #[value(name = "sh_wit")]
    ShWit,
    #[value(name = "wit")]
    Wit,
    #[value(name = "tap")]
    Tap,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct HwiError {
    pub error: String,
    pub code: i32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HwiErrorCode {
    NoDeviceType,
    BadArgument,
    UnsupportedCommand,
    DeviceFailure,
    DeviceConnectionError,
    NeedToBeRoot,
}

impl HwiErrorCode {
    fn code(self) -> i32 {
        match self {
            HwiErrorCode::NoDeviceType => -1,
            HwiErrorCode::BadArgument => -7,
            HwiErrorCode::UnsupportedCommand => -9,
            HwiErrorCode::DeviceFailure => -13,
            HwiErrorCode::DeviceConnectionError => -3,
            HwiErrorCode::NeedToBeRoot => -16,
        }
    }
}

impl HwiError {
    fn new(code: HwiErrorCode, error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.code(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HwiEnumeratedDevice {
    #[serde(rename = "type")]
    pub device_type: String,
    pub model: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<Option<String>>,
    #[serde(
        default,
        serialize_with = "option_fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub fingerprint: Option<Fingerprint>,
    pub needs_pin_sent: bool,
    pub needs_passphrase_sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum HwiResponse {
    Enumerate(Vec<HwiEnumeratedDevice>),
    GetXpub(HwiGetXpubResponse),
    GetDescriptors(HwiGetDescriptorsResponse),
    GetKeypool(Vec<HwiGetKeypoolEntry>),
    SignTx(HwiSignTxResponse),
    SignMessage(HwiSignMessageResponse),
    DisplayAddress(HwiDisplayAddressResponse),
    Success(HwiSuccessResponse),
    Error(HwiError),
}

#[derive(Debug, Serialize)]
pub struct HwiSuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct HwiSignTxResponse {
    pub psbt: String,
    pub signed: bool,
}

#[derive(Debug, Serialize)]
pub struct HwiSignMessageResponse {
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct HwiDisplayAddressResponse {
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct HwiGetXpubResponse {
    pub xpub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testnet: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u8>,
    #[serde(
        default,
        serialize_with = "option_fingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_fingerprint: Option<Fingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_num: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chaincode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HwiGetDescriptorsResponse {
    pub receive: Vec<String>,
    pub internal: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HwiGetKeypoolEntry {
    pub desc: String,
    pub range: [u32; 2],
    pub timestamp: &'static str,
    pub internal: bool,
    pub keypool: bool,
    pub active: bool,
    pub watchonly: bool,
}

pub fn parse_args<I, T>(args: I) -> HwiResult<HwiRequest>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = HwiCli::try_parse_from(args)
        .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?;
    request_from_cli(cli)
}

pub async fn process_request(request: HwiRequest) -> HwiResponse {
    match request.command {
        HwiCommand::Enumerate => enumerate(request.selector).await,
        HwiCommand::GetMasterXpub { addr_type, account } => {
            get_master_xpub(request.selector, addr_type, account).await
        }
        HwiCommand::SignTx { psbt } => sign_tx(request.selector, psbt).await,
        HwiCommand::SignMessage { message, path } => {
            sign_message(request.selector, message, path).await
        }
        HwiCommand::DisplayAddress(address) => display_address(request.selector, address).await,
        HwiCommand::GetXpub { path, expert } => get_xpub(request.selector, path, expert).await,
        HwiCommand::GetDescriptors { account } => get_descriptors(request.selector, account).await,
        HwiCommand::GetKeypool {
            start,
            end,
            internal,
            keypool,
            account,
            addr_type,
            all,
            path,
        } => {
            get_keypool(
                request.selector,
                HwiGetKeypoolRequest {
                    start,
                    end,
                    internal,
                    keypool,
                    account,
                    addr_type,
                    all,
                    path,
                },
            )
            .await
        }
        HwiCommand::Backup {
            label,
            backup_passphrase,
        } => backup_device(request.selector, label, backup_passphrase).await,
        HwiCommand::UnsupportedDeviceAction(action) => {
            unsupported_device_action(request.selector, action).await
        }
        HwiCommand::InstallUdevRules { location } => install_udev_rules_hwi(location),
        HwiCommand::Unsupported(command) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            format!("Unsupported HWI command: {command}"),
        )),
    }
}

pub async fn run_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = match args_from_stdin(args) {
        Ok(args) => args,
        Err(err) => {
            return print_response(HwiResponse::Error(HwiError::new(
                HwiErrorCode::BadArgument,
                err.to_string(),
            )));
        }
    };
    let request = match HwiCli::try_parse_from(args) {
        Ok(args) => match request_from_cli(args) {
            Ok(request) => request,
            Err(err) => return print_response(HwiResponse::Error(err)),
        },
        Err(err) if err.kind() == ErrorKind::DisplayHelp => {
            print!("{err}");
            return ExitCode::SUCCESS;
        }
        Err(err) if err.kind() == ErrorKind::DisplayVersion => {
            print!("{err}");
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            return print_response(HwiResponse::Error(HwiError::new(
                HwiErrorCode::BadArgument,
                err.to_string(),
            )));
        }
    };
    print_response(process_request(request).await)
}

fn args_from_stdin<I, T>(args: I) -> io::Result<Vec<OsString>>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if !args.iter().any(|arg| arg == "--stdin") {
        return Ok(args);
    }

    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.is_empty() {
            break;
        }
        args.extend(line.split_whitespace().map(OsString::from));
    }

    Ok(args)
}

async fn enumerate(selector: DeviceSelector) -> HwiResponse {
    let manager = DeviceManager::new(selector);
    let devices = match manager.enumerate().await {
        Ok(devices) => devices,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };
    let mut response = Vec::with_capacity(devices.len());
    for mut device in devices {
        let mut error = None;
        let mut code = None;
        let fingerprint = match device.device().unlock(manager.selector.network).await {
            Ok(()) => match device.fingerprint().await {
                Ok(fingerprint) => Some(fingerprint),
                Err(err) => {
                    error = Some(err.to_string());
                    code = Some(HwiErrorCode::DeviceConnectionError.code());
                    None
                }
            },
            Err(err) => {
                error = Some(err.to_string());
                code = Some(HwiErrorCode::DeviceConnectionError.code());
                None
            }
        };
        response.push(HwiEnumeratedDevice {
            device_type: device.device_type().to_string(),
            model: hwi_enumerate_model(device.device_type(), device.model(), device.is_emulated()),
            path: hwi_enumerate_path(device.device_type(), device.path(), device.is_emulated()),
            label: label_for(device.device_type()),
            fingerprint,
            needs_pin_sent: false,
            needs_passphrase_sent: false,
            error,
            code,
        });
    }
    HwiResponse::Enumerate(response)
}

fn install_udev_rules_hwi(location: PathBuf) -> HwiResponse {
    match install_udev_rules(&location, UdevRuleSelection::All) {
        Ok(()) => HwiResponse::Success(HwiSuccessResponse { success: true }),
        Err(err) if err.needs_root() => HwiResponse::Error(HwiError::new(
            HwiErrorCode::NeedToBeRoot,
            "installudevrules failed: Need to be root.",
        )),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceFailure,
            format!("installudevrules failed: {err}"),
        )),
    }
}

async fn unsupported_device_action(
    selector: DeviceSelector,
    action: HwiUnsupportedDeviceAction,
) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }

    let manager = DeviceManager::new(selector);
    let device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    let error = match action {
        HwiUnsupportedDeviceAction::Setup { interactive, .. } if !interactive => {
            "setup requires interactive mode".to_owned()
        }
        HwiUnsupportedDeviceAction::Restore { interactive, .. } if !interactive => {
            "restore requires interactive mode".to_owned()
        }
        action => hwi_unavailable_action_message(device.device_type(), &action),
    };

    HwiResponse::Error(HwiError::new(HwiErrorCode::UnsupportedCommand, error))
}

async fn backup_device(
    selector: DeviceSelector,
    label: String,
    backup_passphrase: String,
) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }

    let manager = DeviceManager::new(selector);
    let mut device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    let unsupported = HwiUnsupportedDeviceAction::Backup {
        label: label.clone(),
        backup_passphrase: backup_passphrase.clone(),
    };
    if device.device_type() != DeviceType::BitBox02 {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            hwi_unavailable_action_message(device.device_type(), &unsupported),
        ));
    }
    if !label.is_empty() || !backup_passphrase.is_empty() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "Label/passphrase not needed when exporting mnemonic from the BitBox02.",
        ));
    }

    match device.device().backup_device().await {
        Ok(DeviceBackup::Complete) => HwiResponse::Success(HwiSuccessResponse { success: true }),
        Ok(DeviceBackup::File(_)) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceFailure,
            "BitBox02 backup unexpectedly returned file data",
        )),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

async fn get_master_xpub(
    selector: DeviceSelector,
    addr_type: HwiAddressType,
    account: u32,
) -> HwiResponse {
    let path = match master_xpub_path(addr_type, selector.network, account) {
        Ok(path) => path,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::BadArgument, err.to_string()));
        }
    };
    get_xpub(selector, path, false).await
}

async fn sign_tx(selector: DeviceSelector, psbt: String) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }

    let parsed = match Psbt::from_str(psbt.trim()) {
        Ok(psbt) => psbt,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::BadArgument, err.to_string()));
        }
    };

    let manager = DeviceManager::new(selector);
    let mut device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    let original = parsed.to_string();
    let context = if device.device_type() == DeviceType::Ledger {
        match ledger_signing_context(&mut device, &parsed).await {
            Ok(Some(context)) => Some(context),
            Ok(None) => {
                return HwiResponse::SignTx(HwiSignTxResponse {
                    psbt: original,
                    signed: false,
                });
            }
            Err(err) => {
                return HwiResponse::Error(HwiError::new(HwiErrorCode::BadArgument, err));
            }
        }
    } else {
        None
    };

    match device.device().sign_tx(parsed, context).await {
        Ok(signed_psbt) => {
            let signed = signed_psbt.to_string();
            HwiResponse::SignTx(HwiSignTxResponse {
                signed: signed != original,
                psbt: signed,
            })
        }
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

async fn sign_message(
    selector: DeviceSelector,
    message: String,
    path: DerivationPath,
) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }

    let manager = DeviceManager::new(selector);
    let mut device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    let device_type = device.device_type();
    match device.device().sign_message(message.as_bytes(), path).await {
        Ok((header, signature)) => HwiResponse::SignMessage(HwiSignMessageResponse {
            signature: message_signature_base64(
                python_hwi_message_header(device_type, header),
                &signature,
            ),
        }),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

async fn display_address(
    selector: DeviceSelector,
    request: HwiDisplayAddressRequest,
) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }

    let manager = DeviceManager::new(selector);
    let mut device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    let display = match request {
        HwiDisplayAddressRequest::Path { path, addr_type } => {
            if device.device_type() == DeviceType::Coldcard && addr_type == HwiAddressType::Tap {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::UnsupportedCommand,
                    "Coldcard does not support displaying Taproot addresses yet",
                ));
            }
            if device.device_type() == DeviceType::Jade && addr_type == HwiAddressType::Tap {
                return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceFailure, "tap"));
            }
            Ok(DisplayAddress::ByPath {
                path,
                display: true,
                address_format: Some(address_type_for(addr_type)),
            })
        }
        HwiDisplayAddressRequest::Descriptor { descriptor } => {
            match singlesig_display_address_from_descriptor(&mut device, &descriptor).await {
                Ok(address) => Ok(address),
                Err(single_sig_error) => {
                    if device.device_type() == DeviceType::Coldcard {
                        match multisig_display_address_from_descriptor(&descriptor) {
                            Ok(address) => Ok(DisplayAddress::ByMultisig(address)),
                            Err(_) => return HwiResponse::Error(single_sig_error),
                        }
                    } else {
                        return HwiResponse::Error(single_sig_error);
                    }
                }
            }
        }
    };

    let display = match display {
        Ok(display) => display,
        Err(error) => return HwiResponse::Error(error),
    };

    match device.device().display_address(display, None).await {
        Ok(address) => HwiResponse::DisplayAddress(HwiDisplayAddressResponse { address }),
        Err(err) => display_address_error(err.to_string()),
    }
}

fn python_hwi_message_header(device_type: DeviceType, header: u8) -> u8 {
    if device_type == DeviceType::Coldcard && header >= 8 {
        // Python HWI normalizes Coldcard's compact-signature header by
        // clearing the device-specific compressed/pubkey offset.
        header - 8
    } else {
        header
    }
}

fn message_signature_base64(
    header: u8,
    signature: &bitcoin::secp256k1::ecdsa::Signature,
) -> String {
    let mut payload = [0u8; 65];
    payload[0] = header;
    payload[1..].copy_from_slice(&signature.serialize_compact());
    BASE64_STANDARD.encode(payload)
}

async fn get_xpub(selector: DeviceSelector, path: DerivationPath, expert: bool) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }

    let manager = DeviceManager::new(selector);
    let mut device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    match device.device().get_extended_pubkey(path, false).await {
        Ok(xpub) => HwiResponse::GetXpub(get_xpub_response(xpub, expert)),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

async fn get_descriptors(selector: DeviceSelector, account: u32) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }

    let manager = DeviceManager::new(selector);
    let mut device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    let fingerprint = match device.fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };
    let device_type = device.device_type();
    let model = device.model().to_owned();
    let network = manager.selector.network;
    let mut response = HwiGetDescriptorsResponse {
        receive: Vec::new(),
        internal: Vec::new(),
    };

    for internal in [false, true] {
        for addr_type in hwi_descriptor_addr_types(device_type, &model) {
            let descriptor_type = descriptor_type_for(addr_type);
            let options = GetDescriptorOptions::with_account(
                fingerprint,
                account,
                internal,
                descriptor_type,
                network,
            );
            let descriptor = match manager.get_descriptor(device.device(), options).await {
                Ok(descriptor) => descriptor,
                Err(err) => {
                    return HwiResponse::Error(HwiError::new(
                        HwiErrorCode::DeviceConnectionError,
                        err.to_string(),
                    ));
                }
            };
            let descriptor = match hwi_descriptor_string(&descriptor) {
                Ok(descriptor) => descriptor,
                Err(err) => {
                    return HwiResponse::Error(HwiError::new(
                        HwiErrorCode::BadArgument,
                        err.to_string(),
                    ));
                }
            };
            if internal {
                response.internal.push(descriptor);
            } else {
                response.receive.push(descriptor);
            }
        }
    }

    HwiResponse::GetDescriptors(response)
}

struct HwiGetKeypoolRequest {
    start: u32,
    end: u32,
    internal: bool,
    keypool: bool,
    account: u32,
    addr_type: HwiAddressType,
    all: bool,
    path: Option<String>,
}

async fn get_keypool(selector: DeviceSelector, request: HwiGetKeypoolRequest) -> HwiResponse {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }
    if request.start > request.end {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::BadArgument,
            "keypool start index must be less than or equal to end index",
        ));
    }

    let manager = DeviceManager::new(selector);
    let mut device = match manager.get_device_with_fingerprint().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };

    let fingerprint = match device.fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                err.to_string(),
            ));
        }
    };
    let device_type = device.device_type();
    let model = device.model().to_owned();
    let network = manager.selector.network;
    let addr_types = if request.all {
        hwi_descriptor_addr_types(device_type, &model)
    } else if request.addr_type == HwiAddressType::Tap && !hwi_can_sign_taproot(device_type, &model)
    {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "Device does not support Taproot",
        ));
    } else {
        vec![request.addr_type]
    };

    let branches = if request.path.is_none() && !request.internal {
        vec![false, true]
    } else {
        vec![request.internal]
    };

    let mut entries = Vec::new();
    for addr_type in addr_types {
        for internal in branches.iter().copied() {
            let descriptor_type = descriptor_type_for(addr_type);
            let options = match request.path.as_deref() {
                Some(path) => match keypool_path_descriptor_options(
                    fingerprint,
                    path,
                    internal,
                    descriptor_type,
                    network,
                ) {
                    Ok(options) => options,
                    Err(error) => return HwiResponse::Error(error),
                },
                None => GetDescriptorOptions::with_account(
                    fingerprint,
                    request.account,
                    internal,
                    descriptor_type,
                    network,
                ),
            };
            let descriptor = match manager.get_descriptor(device.device(), options).await {
                Ok(descriptor) => descriptor,
                Err(err) => {
                    return HwiResponse::Error(HwiError::new(
                        HwiErrorCode::DeviceConnectionError,
                        err.to_string(),
                    ));
                }
            };
            let desc = match hwi_descriptor_string(&descriptor) {
                Ok(descriptor) => descriptor,
                Err(err) => {
                    return HwiResponse::Error(HwiError::new(
                        HwiErrorCode::BadArgument,
                        err.to_string(),
                    ));
                }
            };
            entries.push(HwiGetKeypoolEntry {
                desc,
                range: [request.start, request.end],
                timestamp: "now",
                internal,
                keypool: request.keypool,
                active: request.keypool,
                watchonly: true,
            });
        }
    }

    HwiResponse::GetKeypool(entries)
}

async fn ledger_signing_context(
    device: &mut Device,
    psbt: &Psbt,
) -> Result<Option<DeviceContext>, String> {
    let fingerprint = device.fingerprint().await.map_err(|err| err.to_string())?;
    if let Some(context) = ledger_singlesig_context(device, psbt, fingerprint).await? {
        return Ok(Some(context));
    }
    if let Some(context) = ledger_multisig_context(device, psbt, fingerprint).await? {
        return Ok(Some(context));
    }
    Ok(None)
}

async fn ledger_singlesig_context(
    device: &mut Device,
    psbt: &Psbt,
    fingerprint: Fingerprint,
) -> Result<Option<DeviceContext>, String> {
    let Some(path) = ledger_singlesig_account_path(psbt, fingerprint)? else {
        return Ok(None);
    };
    let xpub = device
        .device()
        .get_extended_pubkey(path.clone(), false)
        .await
        .map_err(|err| err.to_string())?;
    let policy = singlesig_wallet_policy(&extend_account_path_for_policy(&path), fingerprint, xpub)
        .map_err(|err| err.to_string())?;
    Ok(Some(DeviceContext::Ledger {
        wallet_policy: LedgerWalletPolicy::new(String::new(), Version::V2, policy),
        wallet_hmac: None,
    }))
}

async fn ledger_multisig_context(
    device: &mut Device,
    psbt: &Psbt,
    fingerprint: Fingerprint,
) -> Result<Option<DeviceContext>, String> {
    let Some(policy) = ledger_multisig_policy(psbt, fingerprint)? else {
        return Ok(None);
    };
    let name = ledger_multisig_wallet_name(&policy);
    let hmac = device
        .device()
        .register_wallet(&name, &policy)
        .await
        .map_err(|err| err.to_string())?;
    let wallet_policy = WalletPolicy::from_str(&policy).map_err(|err| err.to_string())?;
    Ok(Some(DeviceContext::Ledger {
        wallet_policy: LedgerWalletPolicy::new(name, Version::V2, wallet_policy),
        wallet_hmac: Some(hmac),
    }))
}

fn ledger_singlesig_account_path(
    psbt: &Psbt,
    fingerprint: Fingerprint,
) -> Result<Option<DerivationPath>, String> {
    let mut account_path = None;
    for input in &psbt.inputs {
        if multisig_script(input).is_some() {
            continue;
        }
        for (origin_fingerprint, path) in input.bip32_derivation.values() {
            if *origin_fingerprint != fingerprint || !is_standard_singlesig_path(path) {
                continue;
            }
            let candidate = account_path_from_full_path(path)?;
            match &account_path {
                Some(existing) if existing != &candidate => {
                    return Err("Conflicting Ledger single-sig account paths in PSBT".to_owned());
                }
                Some(_) => {}
                None => account_path = Some(candidate),
            }
        }
    }
    Ok(account_path)
}

fn ledger_multisig_policy(psbt: &Psbt, fingerprint: Fingerprint) -> Result<Option<String>, String> {
    let mut policy = None;
    for input in &psbt.inputs {
        let Some((address_type, script)) = multisig_script(input) else {
            continue;
        };
        let Some((threshold, pubkeys)) = parse_multisig_script(&script)? else {
            continue;
        };
        if !pubkeys.iter().any(|pubkey| {
            input
                .bip32_derivation
                .get(&pubkey.inner)
                .is_some_and(|(key_fingerprint, _)| *key_fingerprint == fingerprint)
        }) {
            continue;
        }

        let mut keys = Vec::with_capacity(pubkeys.len());
        let mut complete = true;
        for pubkey in pubkeys {
            let Some(key_source) = input.bip32_derivation.get(&pubkey.inner) else {
                complete = false;
                break;
            };
            let Some(key) = global_xpub_key_expression(psbt, key_source) else {
                complete = false;
                break;
            };
            keys.push(format!("{key}/<0;1>/*"));
        }
        if !complete {
            continue;
        }

        let candidate = multisig_policy_descriptor(address_type, threshold, &keys);
        match &policy {
            Some(existing) if existing != &candidate => {
                return Err("Conflicting Ledger multisig policies in PSBT".to_owned());
            }
            Some(_) => {}
            None => policy = Some(candidate),
        }
    }
    Ok(policy)
}

fn account_path_from_full_path(path: &DerivationPath) -> Result<DerivationPath, String> {
    let children = path.as_ref();
    if children.len() < 3 {
        return Err("Derivation path is too short for Ledger account policy".to_owned());
    }
    Ok(DerivationPath::from(children[..3].to_vec()))
}

fn extend_account_path_for_policy(path: &DerivationPath) -> DerivationPath {
    let mut children = path.as_ref().to_vec();
    children.push(ChildNumber::from_normal_idx(0).expect("valid receive branch"));
    children.push(ChildNumber::from_normal_idx(0).expect("valid address index"));
    DerivationPath::from(children)
}

fn is_standard_singlesig_path(path: &DerivationPath) -> bool {
    let children = path.as_ref();
    if children.len() < 5 {
        return false;
    }
    matches!(
        children[0],
        child if child == hardened(44)
            || child == hardened(49)
            || child == hardened(84)
            || child == hardened(86)
    ) && children[1].is_hardened()
        && children[2].is_hardened()
        && !children[3].is_hardened()
        && !children[4].is_hardened()
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LedgerMultisigAddressType {
    Legacy,
    ShWit,
    Wit,
}

fn multisig_script(input: &Input) -> Option<(LedgerMultisigAddressType, ScriptBuf)> {
    if let Some(witness_script) = &input.witness_script {
        let address_type = if input.redeem_script.as_ref().is_some_and(|s| s.is_p2wsh()) {
            LedgerMultisigAddressType::ShWit
        } else {
            LedgerMultisigAddressType::Wit
        };
        return Some((address_type, witness_script.clone()));
    }
    input
        .redeem_script
        .as_ref()
        .map(|script| (LedgerMultisigAddressType::Legacy, script.clone()))
}

fn parse_multisig_script(script: &ScriptBuf) -> Result<Option<(usize, Vec<PublicKey>)>, String> {
    let mut instructions = script.instructions();
    let Some(first) = instructions.next() else {
        return Ok(None);
    };
    let threshold = match first.map_err(|err| err.to_string())? {
        Instruction::Op(op) => pushnum(op).filter(|n| *n <= 15),
        Instruction::PushBytes(_) => None,
    };
    let Some(threshold) = threshold else {
        return Ok(None);
    };

    let mut pubkeys = Vec::new();
    let signer_count = loop {
        let Some(instruction) = instructions.next() else {
            return Ok(None);
        };
        match instruction.map_err(|err| err.to_string())? {
            Instruction::PushBytes(bytes) if bytes.len() == 33 => {
                let public_key = PublicKey::from_slice(push_bytes_as_bytes(bytes))
                    .map_err(|err| err.to_string())?;
                pubkeys.push(public_key);
            }
            Instruction::Op(op) => {
                break pushnum(op);
            }
            Instruction::PushBytes(_) => return Ok(None),
        }
    };

    let Some(signer_count) = signer_count else {
        return Ok(None);
    };
    let Some(last) = instructions.next() else {
        return Ok(None);
    };
    if last.map_err(|err| err.to_string())? != Instruction::Op(OP_CHECKMULTISIG)
        || instructions.next().is_some()
        || signer_count != pubkeys.len()
        || threshold == 0
        || threshold > signer_count
    {
        return Ok(None);
    }
    Ok(Some((threshold, pubkeys)))
}

fn global_xpub_key_expression(psbt: &Psbt, key_source: &KeySource) -> Option<String> {
    let (fingerprint, key_path) = key_source;
    psbt.xpub
        .iter()
        .find(|(_, (xpub_fingerprint, xpub_path))| {
            xpub_fingerprint == fingerprint && path_starts_with(key_path, xpub_path)
        })
        .map(|(xpub, (_, xpub_path))| {
            let origin = xpub_path.to_string();
            let origin = origin.trim_start_matches('m').trim_start_matches('/');
            if origin.is_empty() {
                format!("[{fingerprint}]{xpub}")
            } else {
                format!("[{fingerprint}/{origin}]{xpub}")
            }
        })
}

fn path_starts_with(path: &DerivationPath, prefix: &DerivationPath) -> bool {
    path.as_ref().starts_with(prefix.as_ref())
}

fn multisig_policy_descriptor(
    address_type: LedgerMultisigAddressType,
    threshold: usize,
    keys: &[String],
) -> String {
    let body = format!("sortedmulti({threshold},{})", keys.join(","));
    match address_type {
        LedgerMultisigAddressType::Legacy => format!("sh({body})"),
        LedgerMultisigAddressType::ShWit => format!("sh(wsh({body}))"),
        LedgerMultisigAddressType::Wit => format!("wsh({body})"),
    }
}

fn ledger_multisig_wallet_name(policy: &str) -> String {
    let threshold = policy
        .split_once("sortedmulti(")
        .and_then(|(_, rest)| rest.split_once(','))
        .and_then(|(threshold, _)| threshold.parse::<usize>().ok())
        .unwrap_or(0);
    let signers = policy
        .matches("/**")
        .count()
        .max(policy.matches("/<0;1>/*").count());
    format!("{threshold} of {signers} Multisig")
}

fn pushnum(op: bitcoin::blockdata::opcodes::Opcode) -> Option<usize> {
    if op == OP_PUSHNUM_1 {
        return Some(1);
    }
    if op.to_u8() >= OP_PUSHNUM_1.to_u8() && op.to_u8() <= OP_PUSHNUM_16.to_u8() {
        return Some((op.to_u8() - OP_PUSHNUM_1.to_u8() + 1) as usize);
    }
    None
}

fn push_bytes_as_bytes(bytes: &PushBytes) -> &[u8] {
    bytes.as_bytes()
}

fn hardened(index: u32) -> ChildNumber {
    ChildNumber::from_hardened_idx(index).expect("valid hardened child")
}

fn master_xpub_path(
    addr_type: HwiAddressType,
    network: Network,
    account: u32,
) -> Result<DerivationPath, bitcoin::bip32::Error> {
    Ok([
        ChildNumber::from_hardened_idx(bip44_purpose(addr_type))?,
        ChildNumber::from_hardened_idx(bip44_chain(network))?,
        ChildNumber::from_hardened_idx(account)?,
    ]
    .as_ref()
    .into())
}

fn bip44_purpose(addr_type: HwiAddressType) -> u32 {
    match addr_type {
        HwiAddressType::Legacy => 44,
        HwiAddressType::ShWit => 49,
        HwiAddressType::Wit => 84,
        HwiAddressType::Tap => 86,
    }
}

fn bip44_chain(network: Network) -> u32 {
    if network == Network::Bitcoin { 0 } else { 1 }
}

fn descriptor_type_for(addr_type: HwiAddressType) -> DescriptorType {
    match addr_type {
        HwiAddressType::Legacy => DescriptorType::Pkh,
        HwiAddressType::ShWit => DescriptorType::ShWpkh,
        HwiAddressType::Wit => DescriptorType::Wpkh,
        HwiAddressType::Tap => DescriptorType::Tr,
    }
}

fn address_type_for(addr_type: HwiAddressType) -> bitcoin::address::AddressType {
    match addr_type {
        HwiAddressType::Legacy => bitcoin::address::AddressType::P2pkh,
        HwiAddressType::ShWit => bitcoin::address::AddressType::P2sh,
        HwiAddressType::Wit => bitcoin::address::AddressType::P2wpkh,
        HwiAddressType::Tap => bitcoin::address::AddressType::P2tr,
    }
}

async fn singlesig_display_address_from_descriptor(
    device: &mut Device,
    descriptor: &str,
) -> Result<DisplayAddress, HwiError> {
    let descriptor = strip_descriptor_checksum(descriptor);
    let parsed = parse_singlesig_display_descriptor(descriptor)?;
    let fingerprint = device
        .fingerprint()
        .await
        .map_err(|err| HwiError::new(HwiErrorCode::DeviceConnectionError, err.to_string()))?;
    if parsed.fingerprint != fingerprint {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            format!("Descriptor fingerprint does not match device: {descriptor}"),
        ));
    }

    let xpub = device
        .device()
        .get_extended_pubkey(parsed.origin_path.clone(), false)
        .await
        .map_err(|err| HwiError::new(HwiErrorCode::DeviceConnectionError, err.to_string()))?;

    if !descriptor_key_matches_xpub(&parsed.key, xpub) {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            format!("Key in descriptor does not match device: {descriptor}"),
        ));
    }

    Ok(DisplayAddress::ByPath {
        path: parsed.full_path,
        display: true,
        address_format: Some(address_type_for(parsed.addr_type)),
    })
}

#[derive(Debug)]
struct ParsedSingleSigDisplayDescriptor {
    addr_type: HwiAddressType,
    fingerprint: Fingerprint,
    origin_path: DerivationPath,
    full_path: DerivationPath,
    key: String,
}

fn parse_singlesig_display_descriptor(
    descriptor: &str,
) -> Result<ParsedSingleSigDisplayDescriptor, HwiError> {
    let (addr_type, key_expr) = if let Some(inner) = descriptor
        .strip_prefix("sh(wpkh(")
        .and_then(|value| value.strip_suffix("))"))
    {
        (HwiAddressType::ShWit, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("wpkh(")
        .and_then(|value| value.strip_suffix(')'))
    {
        (HwiAddressType::Wit, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("pkh(")
        .and_then(|value| value.strip_suffix(')'))
    {
        (HwiAddressType::Legacy, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("tr(")
        .and_then(|value| value.strip_suffix(')'))
    {
        (HwiAddressType::Tap, inner)
    } else {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            format!("Unsupported displayaddress descriptor: {descriptor}"),
        ));
    };

    let Some(rest) = key_expr.strip_prefix('[') else {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            format!("Descriptor missing origin info: {descriptor}"),
        ));
    };
    let Some((origin, key_and_suffix)) = rest.split_once(']') else {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            format!("Descriptor missing origin info: {descriptor}"),
        ));
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

fn validate_singlesig_display_key(key: &str) -> Result<(), HwiError> {
    if SecpPublicKey::from_str(key).is_ok() || XOnlyPublicKey::from_str(key).is_ok() {
        return Ok(());
    }

    Xpub::from_str(key).map(|_| ()).map_err(|err| {
        let error = invalid_base58_character(key).map_or_else(
            || err.to_string(),
            |ch| format!("Character '{ch}' is not a valid base58 character"),
        );
        HwiError::new(HwiErrorCode::BadArgument, error)
    })
}

fn invalid_base58_character(value: &str) -> Option<char> {
    const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    value.chars().find(|ch| !BASE58_ALPHABET.contains(*ch))
}

fn multisig_display_address_from_descriptor(
    descriptor: &str,
) -> Result<MultisigDisplayAddress, HwiError> {
    let descriptor = strip_descriptor_checksum(descriptor);
    let (address_type, inner) = if let Some(inner) = descriptor
        .strip_prefix("sh(wsh(sortedmulti(")
        .and_then(|value| value.strip_suffix(")))"))
    {
        (MultisigAddressType::ShWit, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("wsh(sortedmulti(")
        .and_then(|value| value.strip_suffix("))"))
    {
        (MultisigAddressType::Wit, inner)
    } else if let Some(inner) = descriptor
        .strip_prefix("sh(sortedmulti(")
        .and_then(|value| value.strip_suffix("))"))
    {
        (MultisigAddressType::Legacy, inner)
    } else if descriptor.contains("multi(") {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "Coldcards only allow sortedmulti descriptors",
        ));
    } else {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            format!("Unsupported displayaddress descriptor: {descriptor}"),
        ));
    };

    let mut parts = inner.split(',');
    let threshold = parts
        .next()
        .ok_or_else(|| {
            HwiError::new(
                HwiErrorCode::BadArgument,
                format!("Invalid multisig descriptor: {descriptor}"),
            )
        })?
        .parse::<u8>()
        .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?;
    let mut keys = parts
        .map(parse_multisig_display_key)
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() || threshold == 0 || usize::from(threshold) > keys.len() {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "Either the redeem script provided is invalid or the keypaths provided are insufficient",
        ));
    }
    keys.sort_by_key(|key| key.public_key.serialize());

    Ok(MultisigDisplayAddress {
        threshold,
        address_type,
        keys,
    })
}

fn parse_multisig_display_key(key_expr: &str) -> Result<MultisigDisplayKey, HwiError> {
    let Some(rest) = key_expr.strip_prefix('[') else {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "Coldcard multisig display requires key origin information",
        ));
    };
    let Some((origin, key_and_suffix)) = rest.split_once(']') else {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "Coldcard multisig display requires key origin information",
        ));
    };
    let (fingerprint, origin_path) = parse_key_origin(origin)?;
    let (key, suffix_path) = split_key_suffix(key_and_suffix)?;
    let public_key = SecpPublicKey::from_str(key)
        .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?;
    Ok(MultisigDisplayKey {
        fingerprint,
        path: join_derivation_path(&origin_path, &suffix_path),
        public_key,
    })
}

fn strip_descriptor_checksum(descriptor: &str) -> &str {
    descriptor
        .split_once('#')
        .map_or(descriptor, |(desc, _)| desc)
}

fn parse_key_origin(origin: &str) -> Result<(Fingerprint, DerivationPath), HwiError> {
    let (fingerprint, path) = origin
        .split_once('/')
        .map_or((origin, ""), |(fp, path)| (fp, path));
    let fingerprint = Fingerprint::from_str(fingerprint)
        .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?;
    let path = if path.is_empty() {
        DerivationPath::master()
    } else {
        DerivationPath::from_str(&format!("m/{path}"))
            .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?
    };
    Ok((fingerprint, path))
}

fn split_key_suffix(key_and_suffix: &str) -> Result<(&str, DerivationPath), HwiError> {
    let Some((key, suffix)) = key_and_suffix.split_once('/') else {
        return Ok((key_and_suffix, DerivationPath::master()));
    };
    let suffix = DerivationPath::from_str(&format!("m/{suffix}"))
        .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?;
    Ok((key, suffix))
}

fn join_derivation_path(base: &DerivationPath, suffix: &DerivationPath) -> DerivationPath {
    let mut children = base.as_ref().to_vec();
    children.extend_from_slice(suffix.as_ref());
    DerivationPath::from(children)
}

fn descriptor_key_matches_xpub(key: &str, xpub: Xpub) -> bool {
    key == xpub.to_string()
        || key.eq_ignore_ascii_case(&hex::encode(xpub.public_key.serialize()))
        || key.eq_ignore_ascii_case(&hex::encode(
            xpub.public_key.x_only_public_key().0.serialize(),
        ))
}

fn display_address_error(error: String) -> HwiResponse {
    let error = match error.find("Coldcard Error:") {
        Some(idx) => error[idx..].to_owned(),
        None => error,
    };
    let code = if error.contains("unsupported display address")
        || error.contains("does not support displaying")
        || error.contains("does not support this path address format")
    {
        HwiErrorCode::UnsupportedCommand
    } else if error.contains("Coldcard Error:") {
        HwiErrorCode::BadArgument
    } else {
        HwiErrorCode::DeviceConnectionError
    };
    HwiResponse::Error(HwiError::new(code, error))
}

fn hwi_descriptor_addr_types(device_type: DeviceType, model: &str) -> Vec<HwiAddressType> {
    let mut types = vec![
        HwiAddressType::Legacy,
        HwiAddressType::Wit,
        HwiAddressType::ShWit,
    ];
    if hwi_can_sign_taproot(device_type, model) {
        types.push(HwiAddressType::Tap);
    }
    types
}

fn hwi_can_sign_taproot(device_type: DeviceType, model: &str) -> bool {
    match device_type {
        DeviceType::BitBox02 => false,
        DeviceType::Ledger => true,
        DeviceType::Jade => false,
        DeviceType::Coldcard => model.contains("edge"),
    }
}

fn hwi_descriptor_string(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<String, checksum::Error> {
    let descriptor = format!("{descriptor:#}").replace('\'', "h");
    let mut checksum = checksum::Engine::new();
    checksum.input(&descriptor)?;
    Ok(format!("{descriptor}#{}", checksum.checksum()))
}

fn keypool_path_descriptor_options(
    master_fingerprint: Fingerprint,
    path: &str,
    internal: bool,
    descriptor_type: DescriptorType,
    network: Network,
) -> Result<GetDescriptorOptions, HwiError> {
    if !path.starts_with("m/") {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "Path must start with m/",
        ));
    }
    let Some(path) = path.strip_suffix("/*") else {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "Path must end with /*",
        ));
    };
    let path = DerivationPath::from_str(path)
        .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?;
    Ok(GetDescriptorOptions::with_path(
        master_fingerprint,
        path,
        internal,
        descriptor_type,
        network,
    ))
}

fn get_xpub_response(xpub: Xpub, expert: bool) -> HwiGetXpubResponse {
    if !expert {
        return HwiGetXpubResponse {
            xpub: xpub.to_string(),
            testnet: None,
            private: None,
            depth: None,
            parent_fingerprint: None,
            child_num: None,
            chaincode: None,
            pubkey: None,
        };
    }

    HwiGetXpubResponse {
        xpub: xpub.to_string(),
        testnet: Some(xpub.network == NetworkKind::Test),
        private: Some(false),
        depth: Some(xpub.depth),
        parent_fingerprint: Some(xpub.parent_fingerprint),
        child_num: Some(u32::from(xpub.child_number)),
        chaincode: Some(hex::encode(xpub.chain_code)),
        pubkey: Some(hex::encode(xpub.public_key.serialize())),
    }
}

fn label_for(device_type: DeviceType) -> Option<Option<String>> {
    match device_type {
        DeviceType::Coldcard | DeviceType::Ledger => Some(None),
        DeviceType::BitBox02 | DeviceType::Jade => None,
    }
}

fn hwi_enumerate_model(device_type: DeviceType, model: &str, is_emulated: bool) -> String {
    match (device_type, is_emulated) {
        (DeviceType::BitBox02, true) => "bitbox02_nova_multi".to_owned(),
        _ => model.to_owned(),
    }
}

fn hwi_enumerate_path(device_type: DeviceType, path: &str, is_emulated: bool) -> String {
    match (device_type, is_emulated) {
        (DeviceType::BitBox02, true) => path.strip_prefix("tcp:").unwrap_or(path).to_owned(),
        _ => path.to_owned(),
    }
}

fn hwi_unavailable_action_message(
    device_type: DeviceType,
    action: &HwiUnsupportedDeviceAction,
) -> String {
    match (device_type, action) {
        (DeviceType::Ledger, HwiUnsupportedDeviceAction::Setup { .. }) => {
            "The Ledger Nano S and X do not support software setup"
        }
        (DeviceType::Ledger, HwiUnsupportedDeviceAction::Wipe) => {
            "The Ledger Nano S and X do not support wiping via software"
        }
        (DeviceType::Ledger, HwiUnsupportedDeviceAction::Restore { .. }) => {
            "The Ledger Nano S and X do not support restoring via software"
        }
        (DeviceType::Ledger, HwiUnsupportedDeviceAction::Backup { .. }) => {
            "The Ledger Nano S and X do not support creating a backup via software"
        }
        (DeviceType::Ledger, HwiUnsupportedDeviceAction::PromptPin) => {
            "The Ledger Nano S and X do not need a PIN sent from the host"
        }
        (DeviceType::Ledger, HwiUnsupportedDeviceAction::SendPin { .. }) => {
            "The Ledger Nano S and X do not need a PIN sent from the host"
        }
        (DeviceType::Ledger, HwiUnsupportedDeviceAction::TogglePassphrase) => {
            "The Ledger Nano S and X do not support toggling passphrase from the host"
        }
        (DeviceType::Jade, HwiUnsupportedDeviceAction::Setup { .. }) => {
            "Blockstream Jade does not support software setup"
        }
        (DeviceType::Jade, HwiUnsupportedDeviceAction::Wipe) => {
            "Blockstream Jade does not support wiping via software"
        }
        (DeviceType::Jade, HwiUnsupportedDeviceAction::Restore { .. }) => {
            "Blockstream Jade does not support restoring via software"
        }
        (DeviceType::Jade, HwiUnsupportedDeviceAction::Backup { .. }) => {
            "Blockstream Jade does not support creating a backup via software"
        }
        (DeviceType::Jade, HwiUnsupportedDeviceAction::PromptPin) => {
            "Blockstream Jade does not need a PIN sent from the host"
        }
        (DeviceType::Jade, HwiUnsupportedDeviceAction::SendPin { .. }) => {
            "Blockstream Jade does not need a PIN sent from the host"
        }
        (DeviceType::Jade, HwiUnsupportedDeviceAction::TogglePassphrase) => {
            "Blockstream Jade does not support toggling passphrase from the host"
        }
        (DeviceType::Coldcard, HwiUnsupportedDeviceAction::Setup { .. }) => {
            "The Coldcard does not support software setup"
        }
        (DeviceType::Coldcard, HwiUnsupportedDeviceAction::Wipe) => {
            "The Coldcard does not support wiping via software"
        }
        (DeviceType::Coldcard, HwiUnsupportedDeviceAction::Restore { .. }) => {
            "The Coldcard does not support restoring via software"
        }
        (DeviceType::Coldcard, HwiUnsupportedDeviceAction::Backup { .. }) => {
            "The Coldcard does not support creating a backup via software"
        }
        (DeviceType::Coldcard, HwiUnsupportedDeviceAction::PromptPin) => {
            "The Coldcard does not need a PIN sent from the host"
        }
        (DeviceType::Coldcard, HwiUnsupportedDeviceAction::SendPin { .. }) => {
            "The Coldcard does not need a PIN sent from the host"
        }
        (DeviceType::Coldcard, HwiUnsupportedDeviceAction::TogglePassphrase) => {
            "The Coldcard does not support toggling passphrase from the host"
        }
        (DeviceType::BitBox02, HwiUnsupportedDeviceAction::Setup { .. }) => {
            "BitBox02 software setup is not implemented"
        }
        (DeviceType::BitBox02, HwiUnsupportedDeviceAction::Wipe) => {
            "BitBox02 software wiping is not implemented"
        }
        (DeviceType::BitBox02, HwiUnsupportedDeviceAction::Restore { .. }) => {
            "BitBox02 software restore is not implemented"
        }
        (DeviceType::BitBox02, HwiUnsupportedDeviceAction::Backup { .. }) => {
            "BitBox02 software backup is not implemented"
        }
        (DeviceType::BitBox02, HwiUnsupportedDeviceAction::PromptPin) => {
            "BitBox02 does not need a PIN sent from the host"
        }
        (DeviceType::BitBox02, HwiUnsupportedDeviceAction::SendPin { .. }) => {
            "BitBox02 does not need a PIN sent from the host"
        }
        (DeviceType::BitBox02, HwiUnsupportedDeviceAction::TogglePassphrase) => {
            "BitBox02 passphrase toggling is not implemented"
        }
    }
    .to_owned()
}

fn print_response(response: HwiResponse) -> ExitCode {
    match response {
        HwiResponse::Error(error) => {
            println!(
                "{}",
                serde_json::to_string(&HwiResponse::Error(error)).expect("serialize HWI error")
            );
            ExitCode::from(1)
        }
        response => {
            println!(
                "{}",
                serde_json::to_string(&response).expect("serialize HWI response")
            );
            ExitCode::SUCCESS
        }
    }
}

fn parse_device_type(value: &str) -> HwiResult<DeviceType> {
    match value.to_ascii_lowercase().as_str() {
        "bitbox02" => Ok(DeviceType::BitBox02),
        "coldcard" => Ok(DeviceType::Coldcard),
        "jade" => Ok(DeviceType::Jade),
        "ledger" => Ok(DeviceType::Ledger),
        _ => Err(HwiError::new(
            HwiErrorCode::BadArgument,
            format!("Unsupported device type: {value}"),
        )),
    }
}

fn request_from_cli(args: HwiCli) -> HwiResult<HwiRequest> {
    let _accepted_python_hwi_globals = (
        args.password,
        args.debug,
        args.stdin,
        args.interactive,
        args.stdinpass,
    );
    let expert = args.expert;
    let device_type = args
        .device_type
        .as_deref()
        .map(parse_device_type)
        .transpose()?;
    let network = parse_chain(&args.chain)?;
    let command = match args.command {
        HwiCliCommand::Enumerate => HwiCommand::Enumerate,
        HwiCliCommand::Getmasterxpub { addr_type, account } => {
            HwiCommand::GetMasterXpub { addr_type, account }
        }
        HwiCliCommand::Signtx { psbt } => HwiCommand::SignTx { psbt },
        HwiCliCommand::Signmessage { message, path } => HwiCommand::SignMessage { message, path },
        HwiCliCommand::Displayaddress {
            path,
            desc,
            addr_type,
        } => match (path, desc) {
            (Some(path), None) => {
                HwiCommand::DisplayAddress(HwiDisplayAddressRequest::Path { path, addr_type })
            }
            (None, Some(descriptor)) => {
                HwiCommand::DisplayAddress(HwiDisplayAddressRequest::Descriptor { descriptor })
            }
            _ => {
                return Err(HwiError::new(
                    HwiErrorCode::BadArgument,
                    "displayaddress requires exactly one of --path or --desc",
                ));
            }
        },
        HwiCliCommand::Getxpub { path } => HwiCommand::GetXpub { path, expert },
        HwiCliCommand::Getdescriptors { account } => HwiCommand::GetDescriptors { account },
        HwiCliCommand::Getkeypool {
            start,
            end,
            keypool: _keypool,
            nokeypool,
            internal,
            addr_type,
            all,
            account,
            path,
        } => HwiCommand::GetKeypool {
            start,
            end,
            internal,
            keypool: !nokeypool,
            account,
            addr_type: addr_type.unwrap_or(HwiAddressType::Wit),
            all,
            path,
        },
        HwiCliCommand::Setup {
            label,
            backup_passphrase,
        } => HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::Setup {
            interactive: args.interactive,
            label,
            backup_passphrase,
        }),
        HwiCliCommand::Wipe => {
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::Wipe)
        }
        HwiCliCommand::Restore { word_count, label } => {
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::Restore {
                interactive: args.interactive,
                word_count,
                label,
            })
        }
        HwiCliCommand::Backup {
            label,
            backup_passphrase,
        } => HwiCommand::Backup {
            label,
            backup_passphrase,
        },
        HwiCliCommand::Promptpin => {
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::PromptPin)
        }
        HwiCliCommand::Sendpin { pin } => {
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::SendPin { pin })
        }
        HwiCliCommand::Togglepassphrase => {
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::TogglePassphrase)
        }
        HwiCliCommand::Installudevrules { location } => HwiCommand::InstallUdevRules { location },
        HwiCliCommand::External(argv) => {
            let command = argv
                .first()
                .and_then(|arg| arg.to_str())
                .unwrap_or("<unknown>")
                .to_owned();
            HwiCommand::Unsupported(command)
        }
    };
    Ok(HwiRequest {
        selector: DeviceSelector {
            network,
            fingerprint: args.fingerprint,
            device_type,
            device_path: args.device_path,
            include_emulators: args.emulators,
        },
        command,
    })
}

fn parse_chain(value: &str) -> HwiResult<Network> {
    match value {
        "main" | "mainnet" => Ok(Network::Bitcoin),
        "test" | "testnet" => Ok(Network::Testnet),
        _ => Network::from_str(value).map_err(|err| {
            HwiError::new(
                HwiErrorCode::BadArgument,
                format!("Unsupported chain {value}: {err}"),
            )
        }),
    }
}

fn option_fingerprint<S>(value: &Option<Fingerprint>, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(v) = value {
        hex::serialize(v, ser)
    } else {
        ser.serialize_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime,
        blockdata::{opcodes::all::OP_CHECKMULTISIG, script::Builder},
        secp256k1::Secp256k1,
        transaction::Version as TxVersion,
    };

    #[test]
    fn parses_enumerate_selector() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "-f",
            "f5acc2fd",
            "-t",
            "ledger",
            "-d",
            "tcp:localhost:9999",
            "--emulators",
            "enumerate",
        ])
        .expect("request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(
            request.selector.device_path.as_deref(),
            Some("tcp:localhost:9999")
        );
        assert!(request.selector.include_emulators);
        assert_eq!(request.command, HwiCommand::Enumerate);
    }

    #[test]
    fn parses_enumerate_python_hwi_global_flags() {
        let request = parse_args([
            "hwi",
            "--password",
            "passphrase",
            "--debug",
            "--stdin",
            "--interactive",
            "--expert",
            "--stdinpass",
            "enumerate",
        ])
        .expect("request");

        assert_eq!(request.command, HwiCommand::Enumerate);
    }

    #[test]
    fn parses_enumerate_python_hwi_short_flags() {
        let request = parse_args([
            "hwi",
            "-p",
            "passphrase",
            "-i",
            "-f",
            "f5acc2fd",
            "-t",
            "ledger",
            "-d",
            "tcp:localhost:9999",
            "enumerate",
        ])
        .expect("request");

        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(
            request.selector.device_path.as_deref(),
            Some("tcp:localhost:9999")
        );
        assert_eq!(request.command, HwiCommand::Enumerate);
    }

    #[test]
    fn parses_getxpub_with_expert_flag() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--expert",
            "--device-type",
            "ledger",
            "--emulators",
            "getxpub",
            "m/44h/1h/0h/0/3",
        ])
        .expect("request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert!(request.selector.include_emulators);
        assert_eq!(
            request.command,
            HwiCommand::GetXpub {
                path: DerivationPath::from_str("m/44h/1h/0h/0/3").unwrap(),
                expert: true,
            }
        );
    }

    #[test]
    fn parses_getmasterxpub_defaults() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "--emulators",
            "getmasterxpub",
        ])
        .expect("request");

        assert_eq!(
            request.command,
            HwiCommand::GetMasterXpub {
                addr_type: HwiAddressType::Wit,
                account: 0,
            }
        );
    }

    #[test]
    fn parses_getmasterxpub_addr_type_and_account() {
        let request = parse_args([
            "hwi",
            "--device-type",
            "ledger",
            "getmasterxpub",
            "--addr-type",
            "sh_wit",
            "--account",
            "7",
        ])
        .expect("request");

        assert_eq!(
            request.command,
            HwiCommand::GetMasterXpub {
                addr_type: HwiAddressType::ShWit,
                account: 7,
            }
        );
    }

    #[test]
    fn parses_signtx_psbt_argument() {
        let psbt = "cHNidP8BAHECAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAAFYAAAAAAAABAR8AAAAAAAAAAFYA";
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "signtx",
            psbt,
        ])
        .expect("request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(
            request.command,
            HwiCommand::SignTx {
                psbt: psbt.to_owned(),
            }
        );
    }

    #[test]
    fn parses_signmessage_arguments() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "signmessage",
            "hello",
            "m/44'/1'/0'/0",
        ])
        .expect("request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(
            request.command,
            HwiCommand::SignMessage {
                message: "hello".to_owned(),
                path: DerivationPath::from_str("m/44'/1'/0'/0").unwrap(),
            }
        );
    }

    #[test]
    fn parses_displayaddress_path() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "displayaddress",
            "--addr-type",
            "sh_wit",
            "--path",
            "m/49h/1h/0h/0/0",
        ])
        .expect("request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(
            request.command,
            HwiCommand::DisplayAddress(HwiDisplayAddressRequest::Path {
                path: DerivationPath::from_str("m/49h/1h/0h/0/0").unwrap(),
                addr_type: HwiAddressType::ShWit,
            })
        );
    }

    #[test]
    fn parses_displayaddress_descriptor() {
        let descriptor = "wpkh([f5acc2fd/84h/1h/0h]tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/0/0)";
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "displayaddress",
            "--desc",
            descriptor,
        ])
        .expect("request");

        assert_eq!(
            request.command,
            HwiCommand::DisplayAddress(HwiDisplayAddressRequest::Descriptor {
                descriptor: descriptor.to_owned(),
            })
        );
    }

    #[test]
    fn parses_getdescriptors_account() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "getdescriptors",
            "--account",
            "3",
        ])
        .expect("request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(request.command, HwiCommand::GetDescriptors { account: 3 });
    }

    #[test]
    fn parses_getkeypool_defaults() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "--emulators",
            "getkeypool",
            "0",
            "10",
        ])
        .expect("request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert!(request.selector.include_emulators);
        assert_eq!(
            request.command,
            HwiCommand::GetKeypool {
                start: 0,
                end: 10,
                internal: false,
                keypool: true,
                account: 0,
                addr_type: HwiAddressType::Wit,
                all: false,
                path: None,
            }
        );
    }

    #[test]
    fn parses_getkeypool_all_options() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "getkeypool",
            "--nokeypool",
            "--internal",
            "--all",
            "--account",
            "2",
            "--path",
            "m/84h/1h/0h/1/*",
            "5",
            "8",
        ])
        .expect("request");

        assert_eq!(
            request.command,
            HwiCommand::GetKeypool {
                start: 5,
                end: 8,
                internal: true,
                keypool: false,
                account: 2,
                addr_type: HwiAddressType::Wit,
                all: true,
                path: Some("m/84h/1h/0h/1/*".to_owned()),
            }
        );
    }

    #[test]
    fn parses_getkeypool_addr_type() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "getkeypool",
            "--addr-type",
            "sh_wit",
            "--keypool",
            "5",
            "8",
        ])
        .expect("request");

        assert_eq!(
            request.command,
            HwiCommand::GetKeypool {
                start: 5,
                end: 8,
                internal: false,
                keypool: true,
                account: 0,
                addr_type: HwiAddressType::ShWit,
                all: false,
                path: None,
            }
        );
    }

    #[test]
    fn accepts_python_hwi_version_flag() {
        let error = HwiCli::try_parse_from(["hwi", "--version"]).expect_err("version exits");

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn rejects_unknown_device_type_as_hwi_error() {
        let error = parse_args(["hwi", "--device-type", "trezor", "enumerate"])
            .expect_err("unsupported device type");

        assert_eq!(error.code, HwiErrorCode::BadArgument.code());
        assert!(error.error.contains("Unsupported device type"));
    }

    #[test]
    fn accepts_bitbox02_device_type() {
        let request =
            parse_args(["hwi", "--device-type", "bitbox02", "enumerate"]).expect("bitbox02 parses");

        assert_eq!(request.selector.device_type, Some(DeviceType::BitBox02));
    }

    #[test]
    fn parses_setup_unsupported_action() {
        let request = parse_args([
            "hwi",
            "--chain",
            "test",
            "--device-type",
            "ledger",
            "--interactive",
            "setup",
            "-l",
            "HWI Ledger",
            "-b",
            "backup passphrase",
        ])
        .expect("unsupported setup request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(
            request.command,
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::Setup {
                interactive: true,
                label: "HWI Ledger".to_owned(),
                backup_passphrase: "backup passphrase".to_owned(),
            })
        );
    }

    #[test]
    fn parses_restore_unsupported_action() {
        let request = parse_args([
            "hwi",
            "--device-type",
            "jade",
            "--interactive",
            "restore",
            "--word_count",
            "12",
            "--label",
            "HWI Jade",
        ])
        .expect("unsupported restore request");

        assert_eq!(
            request.command,
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::Restore {
                interactive: true,
                word_count: 12,
                label: "HWI Jade".to_owned(),
            })
        );
    }

    #[test]
    fn parses_backup_action() {
        let request = parse_args([
            "hwi",
            "--device-type",
            "coldcard",
            "backup",
            "--label",
            "HWI Coldcard",
            "--backup_passphrase",
            "backup passphrase",
        ])
        .expect("unsupported backup request");

        assert_eq!(
            request.command,
            HwiCommand::Backup {
                label: "HWI Coldcard".to_owned(),
                backup_passphrase: "backup passphrase".to_owned(),
            }
        );
    }

    #[test]
    fn parses_pin_and_passphrase_unsupported_actions() {
        let promptpin = parse_args(["hwi", "--device-type", "ledger", "promptpin"])
            .expect("unsupported promptpin request");
        assert_eq!(
            promptpin.command,
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::PromptPin)
        );

        let sendpin = parse_args(["hwi", "--device-type", "ledger", "sendpin", "1234"])
            .expect("unsupported sendpin request");
        assert_eq!(
            sendpin.command,
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::SendPin {
                pin: "1234".to_owned()
            })
        );

        let togglepassphrase = parse_args(["hwi", "--device-type", "ledger", "togglepassphrase"])
            .expect("unsupported togglepassphrase request");
        assert_eq!(
            togglepassphrase.command,
            HwiCommand::UnsupportedDeviceAction(HwiUnsupportedDeviceAction::TogglePassphrase)
        );
    }

    #[test]
    fn parses_installudevrules_without_device_selection() {
        let request = parse_args(["hwi", "installudevrules", "--location", "/tmp/bhwi-rules.d"])
            .expect("installudevrules request");

        assert_eq!(request.selector.device_type, None);
        assert_eq!(request.selector.fingerprint, None);
        assert_eq!(
            request.command,
            HwiCommand::InstallUdevRules {
                location: PathBuf::from("/tmp/bhwi-rules.d"),
            }
        );
    }

    #[test]
    fn captures_unknown_unsupported_commands() {
        let request = parse_args(["hwi", "unknowncommand"]).expect("unsupported command request");

        assert_eq!(
            request.command,
            HwiCommand::Unsupported("unknowncommand".to_owned())
        );
    }

    #[test]
    fn unsupported_action_without_selector_returns_no_device_type() {
        let request = parse_args(["hwi", "wipe"]).expect("unsupported wipe request");
        let response = futures::executor::block_on(process_request(request));
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };

        assert_eq!(error.code, HwiErrorCode::NoDeviceType.code());
        assert_eq!(
            error.error,
            "You must specify a device type or fingerprint for all commands except enumerate"
        );
    }

    #[test]
    fn unsupported_action_messages_match_python_hwi() {
        assert_eq!(
            hwi_unavailable_action_message(DeviceType::Ledger, &HwiUnsupportedDeviceAction::Wipe),
            "The Ledger Nano S and X do not support wiping via software"
        );
        assert_eq!(
            hwi_unavailable_action_message(
                DeviceType::Jade,
                &HwiUnsupportedDeviceAction::TogglePassphrase,
            ),
            "Blockstream Jade does not support toggling passphrase from the host"
        );
        assert_eq!(
            hwi_unavailable_action_message(
                DeviceType::Coldcard,
                &HwiUnsupportedDeviceAction::PromptPin,
            ),
            "The Coldcard does not need a PIN sent from the host"
        );
    }

    #[test]
    fn ledger_and_coldcard_labels_are_serialized_as_null() {
        assert_eq!(
            serde_json::to_value(HwiEnumeratedDevice {
                device_type: "ledger".to_owned(),
                model: "ledger_nano_s".to_owned(),
                path: "tcp:localhost:9999".to_owned(),
                label: label_for(DeviceType::Ledger),
                fingerprint: None,
                needs_pin_sent: false,
                needs_passphrase_sent: false,
                error: None,
                code: None,
            })
            .expect("json")["label"],
            serde_json::Value::Null
        );
        assert_eq!(
            serde_json::to_value(HwiEnumeratedDevice {
                device_type: "coldcard".to_owned(),
                model: "coldcard".to_owned(),
                path: "/tmp/ckcc-simulator.sock".to_owned(),
                label: label_for(DeviceType::Coldcard),
                fingerprint: None,
                needs_pin_sent: false,
                needs_passphrase_sent: false,
                error: None,
                code: None,
            })
            .expect("json")["label"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn jade_label_and_missing_fingerprint_are_omitted() {
        let json = serde_json::to_value(HwiEnumeratedDevice {
            device_type: "jade".to_owned(),
            model: "jade".to_owned(),
            path: "localhost:30121".to_owned(),
            label: label_for(DeviceType::Jade),
            fingerprint: None,
            needs_pin_sent: false,
            needs_passphrase_sent: false,
            error: Some("connection failed".to_owned()),
            code: Some(HwiErrorCode::DeviceConnectionError.code()),
        })
        .expect("json");

        assert!(json.get("label").is_none());
        assert!(json.get("fingerprint").is_none());
    }

    #[test]
    fn bitbox_emulator_enumerate_shape_matches_python_hwi() {
        let json = serde_json::to_value(HwiEnumeratedDevice {
            device_type: "bitbox02".to_owned(),
            model: hwi_enumerate_model(DeviceType::BitBox02, "bitbox02_simulator", true),
            path: hwi_enumerate_path(DeviceType::BitBox02, "tcp:127.0.0.1:15423", true),
            label: label_for(DeviceType::BitBox02),
            fingerprint: None,
            needs_pin_sent: false,
            needs_passphrase_sent: false,
            error: None,
            code: None,
        })
        .expect("json");

        assert_eq!(json["model"], "bitbox02_nova_multi");
        assert_eq!(json["path"], "127.0.0.1:15423");
        assert!(json.get("label").is_none());
    }

    #[test]
    fn getxpub_non_expert_serializes_only_xpub() {
        let xpub = sample_xpub();

        let json = serde_json::to_value(HwiResponse::GetXpub(get_xpub_response(xpub, false)))
            .expect("json");

        assert_eq!(json, serde_json::json!({ "xpub": xpub.to_string() }));
    }

    #[test]
    fn signmessage_serializes_only_signature() {
        let json = serde_json::to_value(HwiResponse::SignMessage(HwiSignMessageResponse {
            signature: "base64-signature".to_owned(),
        }))
        .expect("json");

        assert_eq!(json, serde_json::json!({ "signature": "base64-signature" }));
    }

    #[test]
    fn displayaddress_serializes_only_address() {
        let json = serde_json::to_value(HwiResponse::DisplayAddress(HwiDisplayAddressResponse {
            address: "tb1qexample".to_owned(),
        }))
        .expect("json");

        assert_eq!(json, serde_json::json!({ "address": "tb1qexample" }));
    }

    #[test]
    fn getdescriptors_serializes_receive_and_internal() {
        let json = serde_json::to_value(HwiResponse::GetDescriptors(HwiGetDescriptorsResponse {
            receive: vec!["wpkh(...)#receive".to_owned()],
            internal: vec!["wpkh(...)#internal".to_owned()],
        }))
        .expect("json");

        assert_eq!(
            json,
            serde_json::json!({
                "receive": ["wpkh(...)#receive"],
                "internal": ["wpkh(...)#internal"],
            })
        );
    }

    #[test]
    fn getkeypool_serializes_importdescriptors_shape() {
        let json = serde_json::to_value(HwiResponse::GetKeypool(vec![HwiGetKeypoolEntry {
            desc: "wpkh(...)#keypool".to_owned(),
            range: [0, 10],
            timestamp: "now",
            internal: false,
            keypool: true,
            active: true,
            watchonly: true,
        }]))
        .expect("json");

        assert_eq!(
            json,
            serde_json::json!([
                {
                    "desc": "wpkh(...)#keypool",
                    "range": [0, 10],
                    "timestamp": "now",
                    "internal": false,
                    "keypool": true,
                    "active": true,
                    "watchonly": true,
                }
            ])
        );
    }

    #[test]
    fn signmessage_normalizes_coldcard_header_for_python_hwi() {
        assert_eq!(python_hwi_message_header(DeviceType::Coldcard, 40), 32);
        assert_eq!(python_hwi_message_header(DeviceType::Ledger, 32), 32);
        assert_eq!(python_hwi_message_header(DeviceType::Jade, 31), 31);
    }

    #[test]
    fn hwi_descriptor_string_uses_hardened_h_and_recomputes_checksum() {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(
            "wpkh([f5acc2fd/84'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/0/*)",
        )
        .expect("descriptor");

        let descriptor = hwi_descriptor_string(&descriptor).expect("descriptor string");

        assert!(descriptor.contains("/84h/1h/0h]"));
        assert!(!descriptor.contains('\''));
        checksum::verify_checksum(&descriptor).expect("valid checksum");
    }

    #[test]
    fn getkeypool_path_accepts_hwi_ranged_path() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);

        let options = keypool_path_descriptor_options(
            fingerprint,
            "m/84h/1h/0h/0/*",
            false,
            DescriptorType::Wpkh,
            Network::Testnet,
        )
        .expect("keypool path options");

        assert_eq!(options.master_fingerprint, fingerprint);
    }

    #[test]
    fn getkeypool_path_rejects_missing_master_prefix() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);

        let err = keypool_path_descriptor_options(
            fingerprint,
            "84h/1h/0h/0/*",
            false,
            DescriptorType::Wpkh,
            Network::Testnet,
        )
        .expect_err("missing master prefix");

        assert_eq!(err.code, HwiErrorCode::BadArgument.code());
        assert_eq!(err.error, "Path must start with m/");
    }

    #[test]
    fn getkeypool_path_rejects_missing_wildcard() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);

        let err = keypool_path_descriptor_options(
            fingerprint,
            "m/84h/1h/0h/0",
            false,
            DescriptorType::Wpkh,
            Network::Testnet,
        )
        .expect_err("missing wildcard");

        assert_eq!(err.code, HwiErrorCode::BadArgument.code());
        assert_eq!(err.error, "Path must end with /*");
    }

    #[test]
    fn parses_singlesig_display_descriptor() {
        let descriptor = "sh(wpkh([f5acc2fd/49h/1h/0h]tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/0/7))#checksum";

        let parsed = parse_singlesig_display_descriptor(strip_descriptor_checksum(descriptor))
            .expect("display descriptor");

        assert_eq!(parsed.addr_type, HwiAddressType::ShWit);
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

        assert_eq!(err.code, HwiErrorCode::BadArgument.code());
        assert!(err.error.contains("Descriptor missing origin info"));
    }

    #[test]
    fn display_descriptor_rejects_invalid_base58_key_like_python_hwi() {
        let err = parse_singlesig_display_descriptor("wpkh([0f056943/84h/1h/0h]not_an_xpub/0/0)")
            .expect_err("invalid key");

        assert_eq!(err.code, HwiErrorCode::BadArgument.code());
        assert_eq!(err.error, "Character '_' is not a valid base58 character");
    }

    #[test]
    fn parses_coldcard_sortedmulti_display_descriptor() {
        let descriptor = "sh(wsh(sortedmulti(2,[f5acc2fd/48h/1h/0h/0h/0]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,[aaaaaaaa/48h/1h/1h/0h/0]03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a)))";

        let parsed = multisig_display_address_from_descriptor(descriptor)
            .expect("multisig display descriptor");

        assert_eq!(parsed.threshold, 2);
        assert!(matches!(parsed.address_type, MultisigAddressType::ShWit));
        assert_eq!(parsed.keys.len(), 2);
        assert_eq!(
            parsed.keys[0].path,
            DerivationPath::from_str("m/48h/1h/0h/0h/0").unwrap()
        );
        assert_eq!(
            parsed.keys[1].path,
            DerivationPath::from_str("m/48h/1h/1h/0h/0").unwrap()
        );
    }

    #[test]
    fn descriptor_addr_types_match_python_hwi_taproot_capabilities() {
        assert_eq!(
            hwi_descriptor_addr_types(DeviceType::Ledger, "ledger_nano_s_simulator"),
            vec![
                HwiAddressType::Legacy,
                HwiAddressType::Wit,
                HwiAddressType::ShWit,
                HwiAddressType::Tap,
            ]
        );
        assert_eq!(
            hwi_descriptor_addr_types(DeviceType::Jade, "jade_simulator"),
            vec![
                HwiAddressType::Legacy,
                HwiAddressType::Wit,
                HwiAddressType::ShWit,
            ]
        );
        assert_eq!(
            hwi_descriptor_addr_types(DeviceType::Coldcard, "coldcard_simulator"),
            vec![
                HwiAddressType::Legacy,
                HwiAddressType::Wit,
                HwiAddressType::ShWit,
            ]
        );
        assert!(hwi_can_sign_taproot(
            DeviceType::Coldcard,
            "coldcard_simulator_edge"
        ));
    }

    #[test]
    fn getxpub_expert_serializes_python_hwi_field_names() {
        let xpub = sample_xpub();

        let json =
            serde_json::to_value(HwiResponse::GetXpub(get_xpub_response(xpub, true))).unwrap();
        let object = json.as_object().expect("expert getxpub object");

        assert_eq!(object.len(), 8);
        assert_eq!(json["xpub"], xpub.to_string());
        assert_eq!(json["testnet"], true);
        assert_eq!(json["private"], false);
        assert_eq!(json["depth"], xpub.depth);
        assert_eq!(
            json["parent_fingerprint"],
            xpub.parent_fingerprint.to_string()
        );
        assert_eq!(json["child_num"], u32::from(xpub.child_number));
        assert_eq!(json["chaincode"], hex::encode(xpub.chain_code));
        assert_eq!(json["pubkey"], hex::encode(xpub.public_key.serialize()));
        assert!(!object.contains_key("child_index"));
        assert!(!object.contains_key("chain_code"));
    }

    #[test]
    fn master_xpub_path_matches_python_hwi_addr_types() {
        for (addr_type, expected) in [
            (HwiAddressType::Legacy, "44'/1'/7'"),
            (HwiAddressType::ShWit, "49'/1'/7'"),
            (HwiAddressType::Wit, "84'/1'/7'"),
            (HwiAddressType::Tap, "86'/1'/7'"),
        ] {
            let path = master_xpub_path(addr_type, Network::Testnet, 7).unwrap();
            assert_eq!(path.to_string(), expected);
        }
    }

    #[test]
    fn master_xpub_path_uses_mainnet_coin_type_only_for_mainnet() {
        assert_eq!(
            master_xpub_path(HwiAddressType::Wit, Network::Bitcoin, 0)
                .unwrap()
                .to_string(),
            "84'/0'/0'"
        );
        for network in [
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            assert_eq!(
                master_xpub_path(HwiAddressType::Wit, network, 0)
                    .unwrap()
                    .to_string(),
                "84'/1'/0'"
            );
        }
    }

    #[test]
    fn ledger_singlesig_account_path_accepts_standard_bip84() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let path = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
        let psbt = psbt_with_input(Input {
            bip32_derivation: [(sample_child_pubkey(0).inner, (fingerprint, path))].into(),
            ..Default::default()
        });

        assert_eq!(
            ledger_singlesig_account_path(&psbt, fingerprint)
                .unwrap()
                .unwrap()
                .to_string(),
            "84'/1'/0'"
        );
    }

    #[test]
    fn ledger_singlesig_account_path_rejects_conflicting_accounts() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let psbt = psbt_with_inputs(vec![
            Input {
                bip32_derivation: [(
                    sample_child_pubkey(0).inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                    ),
                )]
                .into(),
                ..Default::default()
            },
            Input {
                bip32_derivation: [(
                    sample_child_pubkey(1).inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/84'/1'/1'/0/0").unwrap(),
                    ),
                )]
                .into(),
                ..Default::default()
            },
        ]);

        let err = ledger_singlesig_account_path(&psbt, fingerprint).expect_err("conflict");
        assert!(err.contains("Conflicting Ledger single-sig account paths"));
    }

    #[test]
    fn ledger_multisig_policy_reconstructs_hwi_like_wsh_sortedmulti() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let account_path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
        let xpub = sample_xpub();
        let pubkey_a = sample_child_pubkey(0);
        let pubkey_b = sample_child_pubkey(1);
        let mut psbt = psbt_with_input(Input {
            witness_script: Some(multisig_script_buf(2, &[pubkey_a, pubkey_b])),
            bip32_derivation: [
                (
                    pubkey_a.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap(),
                    ),
                ),
                (
                    pubkey_b.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/48'/1'/0'/2'/0/1").unwrap(),
                    ),
                ),
            ]
            .into(),
            ..Default::default()
        });
        psbt.xpub.insert(xpub, (fingerprint, account_path));

        let policy = ledger_multisig_policy(&psbt, fingerprint)
            .unwrap()
            .expect("policy");

        assert!(policy.starts_with("wsh(sortedmulti(2,"));
        assert_eq!(policy.matches("/<0;1>/*").count(), 2);
        assert!(policy.contains("[f5acc2fd/48'/1'/0'/2']"));
    }

    #[test]
    fn ledger_multisig_policy_skips_missing_global_xpub() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let pubkey_a = sample_child_pubkey(0);
        let pubkey_b = sample_child_pubkey(1);
        let psbt = psbt_with_input(Input {
            witness_script: Some(multisig_script_buf(2, &[pubkey_a, pubkey_b])),
            bip32_derivation: [
                (
                    pubkey_a.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap(),
                    ),
                ),
                (
                    pubkey_b.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/48'/1'/0'/2'/0/1").unwrap(),
                    ),
                ),
            ]
            .into(),
            ..Default::default()
        });

        assert!(
            ledger_multisig_policy(&psbt, fingerprint)
                .unwrap()
                .is_none()
        );
    }

    fn sample_xpub() -> Xpub {
        Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT")
            .expect("sample xpub")
    }

    fn sample_child_pubkey(index: u32) -> PublicKey {
        let secp = Secp256k1::verification_only();
        let xpub = sample_xpub()
            .derive_pub(
                &secp,
                &[
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(index).unwrap(),
                ],
            )
            .expect("derive pubkey");
        PublicKey::new(xpub.public_key)
    }

    fn multisig_script_buf(threshold: i64, pubkeys: &[PublicKey]) -> ScriptBuf {
        let mut builder = Builder::new().push_int(threshold);
        for pubkey in pubkeys {
            builder = builder.push_slice(pubkey.inner.serialize());
        }
        builder
            .push_int(pubkeys.len() as i64)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    fn psbt_with_input(input: Input) -> Psbt {
        psbt_with_inputs(vec![input])
    }

    fn psbt_with_inputs(inputs: Vec<Input>) -> Psbt {
        let unsigned_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|_| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("psbt");
        psbt.inputs = inputs;
        psbt
    }
}
