use std::{
    ffi::OsString,
    io::{self, BufRead},
    process::ExitCode,
    str::FromStr,
};

use bhwi::{
    bitcoin::psbt::Psbt,
    ledger::{LedgerWalletPolicy, Version, singlesig_wallet_policy},
};
use bhwi_async::DeviceContext;
use bitcoin::{
    Network, NetworkKind, PublicKey, ScriptBuf,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub},
    blockdata::{
        opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_16},
        script::{Instruction, PushBytes},
    },
    psbt::Input,
};
use clap::{ArgAction, Parser, Subcommand, ValueEnum, error::ErrorKind};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    descriptor::{DescriptorType, WalletPolicy, checksum},
};
use serde::{Serialize, Serializer};

use crate::{
    Device, DeviceManager, DeviceType, config::DeviceSelector,
    get_descriptors::GetDescriptorOptions,
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
    Unsupported(String),
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
    DeviceConnectionError,
}

impl HwiErrorCode {
    fn code(self) -> i32 {
        match self {
            HwiErrorCode::NoDeviceType => -1,
            HwiErrorCode::BadArgument => -7,
            HwiErrorCode::UnsupportedCommand => -9,
            HwiErrorCode::DeviceConnectionError => -3,
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
    Error(HwiError),
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
            model: device.model().to_owned(),
            path: device.path().to_owned(),
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
        DeviceType::BitBox02 | DeviceType::Coldcard | DeviceType::Ledger => Some(None),
        DeviceType::Jade => None,
    }
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
    fn captures_unsupported_commands() {
        let request = parse_args(["hwi", "setup"]).expect("unsupported command request");

        assert_eq!(request.command, HwiCommand::Unsupported("setup".to_owned()));
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
