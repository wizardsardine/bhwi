use std::{
    ffi::OsString,
    fs,
    io::{self, BufRead},
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
};

use bhwi::{
    bitcoin::psbt::Psbt,
    common::{MultisigAddressType, MultisigDisplayAddress},
    ledger::{LedgerWalletPolicy, Version, singlesig_wallet_policy},
};
use bhwi_async::{DeviceBackup, DeviceContext, DisplayAddress, RestoreOptions, SetupOptions};
use bitcoin::{
    Address, CompressedPublicKey, Network, NetworkKind, PublicKey, ScriptBuf, TxOut,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub},
    blockdata::{
        opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_16},
        script::{Instruction, PushBytes},
    },
    psbt::Input,
    secp256k1::{PublicKey as SecpPublicKey, Secp256k1, XOnlyPublicKey},
};
use chrono::{Datelike, Local, Timelike};
use clap::{ArgAction, ArgGroup, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    descriptor::{DescriptorType, WalletPolicy, checksum},
};
use serde::{Serialize, Serializer};

use crate::{
    Device, DeviceManager, DeviceType,
    config::DeviceSelector,
    get_descriptors::GetDescriptorOptions,
    management::{bitbox_restore_context, bitbox_setup_context},
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
    #[cfg(target_os = "linux")]
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
    TogglePassphrase,
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
    MissingArguments,
    UnknownDevice,
    BadArgument,
    UnsupportedCommand,
    DeviceFailure,
    DeviceConnectionError,
    NeedToBeRoot,
    DeviceNotInitialized,
}

impl HwiErrorCode {
    fn code(self) -> i32 {
        match self {
            HwiErrorCode::NoDeviceType => -1,
            HwiErrorCode::MissingArguments => -2,
            HwiErrorCode::UnknownDevice => -4,
            HwiErrorCode::BadArgument => -7,
            HwiErrorCode::UnsupportedCommand => -9,
            HwiErrorCode::DeviceFailure => -13,
            HwiErrorCode::DeviceConnectionError => -3,
            HwiErrorCode::NeedToBeRoot => -16,
            HwiErrorCode::DeviceNotInitialized => -18,
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
        HwiCommand::Setup {
            interactive,
            label,
            backup_passphrase,
        } => setup_device(request.selector, interactive, label, backup_passphrase).await,
        HwiCommand::Wipe => wipe_device(request.selector).await,
        HwiCommand::Restore {
            interactive,
            word_count,
            label,
        } => restore_device(request.selector, interactive, word_count, label).await,
        HwiCommand::TogglePassphrase => toggle_passphrase_device(request.selector).await,
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
    let outcome = cli_outcome(args);
    let status = ExitCode::from(exit_status(&outcome));
    match outcome {
        CliOutcome::Stdout(text) => {
            print!("{text}");
            status
        }
        CliOutcome::Usage(usage) => {
            println!(
                "{}",
                serde_json::to_string(&HwiError {
                    error: usage.message,
                    code: HwiErrorCode::MissingArguments.code(),
                })
                .expect("serialize HWI usage error")
            );
            eprintln!("{}", usage.usage);
            status
        }
        CliOutcome::Response(response) => print_response(response),
        CliOutcome::Request(request) => print_response(process_request(*request).await),
    }
}

/// Argparse-style usage failure: `message` goes to stdout as HWI JSON, `usage` to stderr.
#[derive(Debug, Clone, Eq, PartialEq)]
struct UsageError {
    message: String,
    usage: String,
}

#[derive(Debug)]
enum CliOutcome {
    Stdout(String),
    Usage(UsageError),
    Response(HwiResponse),
    Request(Box<HwiRequest>),
}

fn exit_status(outcome: &CliOutcome) -> u8 {
    match outcome {
        CliOutcome::Usage(_) => 2,
        _ => 0,
    }
}

fn cli_outcome(args: Vec<OsString>) -> CliOutcome {
    let prog = program_name(&args);
    let cli = match HwiCli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => return clap_outcome(&prog, err),
    };
    match request_from_cli(cli) {
        Ok(request) => {
            if let HwiCommand::Unsupported(command) = &request.command {
                CliOutcome::Usage(UsageError {
                    message: format!(
                        "{prog}: error: argument command: invalid choice: '{command}'"
                    ),
                    usage: top_level_usage(&prog),
                })
            } else {
                CliOutcome::Request(Box::new(request))
            }
        }
        Err(err) if err.code == HwiErrorCode::MissingArguments.code() => {
            CliOutcome::Usage(UsageError {
                message: format!("{prog}: error: {}", err.error),
                usage: top_level_usage(&prog),
            })
        }
        Err(err) => CliOutcome::Response(HwiResponse::Error(err)),
    }
}

fn clap_outcome(prog: &str, err: clap::Error) -> CliOutcome {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => CliOutcome::Stdout(err.to_string()),
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand | ErrorKind::MissingSubcommand => {
            CliOutcome::Usage(UsageError {
                message: format!("{prog}: error: the following arguments are required: command"),
                usage: top_level_usage(prog),
            })
        }
        ErrorKind::MissingRequiredArgument
        | ErrorKind::UnknownArgument
        | ErrorKind::InvalidValue
        | ErrorKind::InvalidSubcommand
        | ErrorKind::ArgumentConflict
        | ErrorKind::NoEquals
        | ErrorKind::WrongNumberOfValues
        | ErrorKind::TooManyValues
        | ErrorKind::TooFewValues => CliOutcome::Usage(clap_usage_error(prog, &err)),
        // Every other kind keeps the pre-existing runtime error JSON.
        _ => CliOutcome::Response(HwiResponse::Error(HwiError::new(
            HwiErrorCode::BadArgument,
            err.to_string(),
        ))),
    }
}

fn clap_usage_error(prog: &str, err: &clap::Error) -> UsageError {
    let rendered = err.render().to_string();
    let mut message = String::new();
    let mut usage = String::new();
    let mut in_usage = false;
    for line in rendered.lines() {
        if line.starts_with("Usage:") {
            in_usage = true;
        }
        if line.starts_with("For more information, try") {
            continue;
        }
        if in_usage {
            if !usage.is_empty() {
                usage.push('\n');
            }
            usage.push_str(line);
        } else {
            for word in line.split_whitespace() {
                if !message.is_empty() {
                    message.push(' ');
                }
                message.push_str(word);
            }
        }
    }
    let message = message
        .strip_prefix("error: ")
        .unwrap_or(&message)
        .to_owned();
    let usage = usage.trim();
    UsageError {
        message: format!("{prog}: error: {message}"),
        usage: if usage.is_empty() {
            top_level_usage(prog)
        } else {
            usage.to_owned()
        },
    }
}

fn program_name(args: &[OsString]) -> String {
    args.first()
        .map(PathBuf::from)
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "hwi".to_owned())
}

fn top_level_usage(prog: &str) -> String {
    let mut command = HwiCli::command().bin_name(prog);
    command.render_usage().to_string()
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
    let manager = DeviceManager::new(DeviceSelector {
        device_type: None,
        device_path: None,
        ..selector
    });
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
        let mut info = None;
        if error.is_none() && reports_device_info(device.device_type()) {
            match device.info().await {
                Ok(device_info) => info = Some(device_info),
                Err(err) => {
                    error = Some(err.to_string());
                    code = Some(HwiErrorCode::DeviceConnectionError.code());
                }
            }
        }
        let label = info.as_ref().and_then(|info| info.label.clone());
        let firmware = info.as_ref().and_then(|info| info.firmware.clone());
        response.push(HwiEnumeratedDevice {
            device_type: device.device_type().to_string(),
            model: hwi_enumerate_model(
                device.device_type(),
                device.model(),
                device.is_emulated(),
                firmware.as_deref(),
            ),
            path: hwi_enumerate_path(device.device_type(), device.path(), device.is_emulated()),
            label: label_for(device.device_type(), label),
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

async fn setup_device(
    selector: DeviceSelector,
    interactive: bool,
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

    if !interactive {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "setup requires interactive mode",
        ));
    }
    if device.device_type() != DeviceType::BitBox02 {
        let action = HwiUnsupportedDeviceAction::Setup {
            interactive,
            label,
            backup_passphrase,
        };
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            hwi_unavailable_action_message(device.device_type(), &action),
        ));
    }
    if !backup_passphrase.is_empty() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "Passphrase not needed when setting up a BitBox02.",
        ));
    }
    if device.info().await.ok().and_then(|info| info.initialized) == Some(true) {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "The BitBox02 must be wiped before setup.",
        ));
    }

    let context = match bitbox_setup_context(device.is_emulated()) {
        Ok(context) => context,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceFailure, err.to_string()));
        }
    };
    match device
        .device()
        .setup_device(
            SetupOptions {
                label,
                backup_passphrase,
            },
            Some(context),
        )
        .await
    {
        Ok(success) => HwiResponse::Success(HwiSuccessResponse { success }),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

async fn wipe_device(selector: DeviceSelector) -> HwiResponse {
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

    if !matches!(
        device.device_type(),
        DeviceType::BitBox02 | DeviceType::Trezor
    ) {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            hwi_unavailable_action_message(device.device_type(), &HwiUnsupportedDeviceAction::Wipe),
        ));
    }
    if device.device_type() == DeviceType::BitBox02
        && device.info().await.ok().and_then(|info| info.initialized) == Some(false)
    {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceNotInitialized,
            "The BitBox02 must be initialized first.",
        ));
    }

    match device.device().wipe_device().await {
        Ok(success) => HwiResponse::Success(HwiSuccessResponse { success }),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

async fn restore_device(
    selector: DeviceSelector,
    interactive: bool,
    word_count: i32,
    label: String,
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

    if !interactive {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "restore requires interactive mode",
        ));
    }
    if device.device_type() != DeviceType::BitBox02 {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            hwi_unavailable_action_message(
                device.device_type(),
                &HwiUnsupportedDeviceAction::Restore {
                    interactive,
                    word_count,
                    label,
                },
            ),
        ));
    }
    if device.info().await.ok().and_then(|info| info.initialized) == Some(true) {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "The BitBox02 must be wiped before setup.",
        ));
    }

    let context = match bitbox_restore_context() {
        Ok(context) => context,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceFailure, err.to_string()));
        }
    };
    match device
        .device()
        .restore_device(RestoreOptions { label, word_count }, Some(context))
        .await
    {
        Ok(success) => HwiResponse::Success(HwiSuccessResponse { success }),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

async fn toggle_passphrase_device(selector: DeviceSelector) -> HwiResponse {
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

    if !matches!(
        device.device_type(),
        DeviceType::BitBox02 | DeviceType::Trezor
    ) {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            hwi_unavailable_action_message(
                device.device_type(),
                &HwiUnsupportedDeviceAction::TogglePassphrase,
            ),
        ));
    }
    if device.device_type() == DeviceType::BitBox02
        && device.info().await.ok().and_then(|info| info.initialized) == Some(false)
    {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceNotInitialized,
            "The BitBox02 must be initialized first.",
        ));
    }

    match device.device().toggle_passphrase().await {
        Ok(success) => HwiResponse::Success(HwiSuccessResponse { success }),
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
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

    let device_type = device.device_type();
    match device_type {
        DeviceType::BitBox02 => {
            if !label.is_empty() || !backup_passphrase.is_empty() {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::UnsupportedCommand,
                    "Label/passphrase not needed when exporting mnemonic from the BitBox02.",
                ));
            }
        }
        DeviceType::Coldcard => {}
        DeviceType::Ledger | DeviceType::Jade | DeviceType::Trezor => {
            let unsupported = HwiUnsupportedDeviceAction::Backup {
                label,
                backup_passphrase,
            };
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::UnsupportedCommand,
                hwi_unavailable_action_message(device_type, &unsupported),
            ));
        }
    }

    let approval =
        coldcard_emulator_approval(coldcard_emulator_path(&device), ColdcardApproval::Backup);
    let (backup, approval) = tokio::join!(device.device().backup_device(), approval);
    if let Err(err) = approval {
        return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceConnectionError, err));
    }
    match backup {
        Ok(DeviceBackup::Complete) => HwiResponse::Success(HwiSuccessResponse { success: true }),
        Ok(DeviceBackup::File(bytes)) => match write_hwi_backup_file(&bytes) {
            Ok(()) => HwiResponse::Success(HwiSuccessResponse { success: true }),
            Err(err) => HwiResponse::Error(HwiError::new(
                HwiErrorCode::DeviceFailure,
                format!("backup failed: {err}"),
            )),
        },
        Err(err) => HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            err.to_string(),
        )),
    }
}

fn write_hwi_backup_file(bytes: &[u8]) -> io::Result<()> {
    fs::write(hwi_backup_filename(), bytes)
}

fn hwi_backup_filename() -> String {
    format_hwi_backup_filename(Local::now())
}

fn format_hwi_backup_filename<Tz: chrono::TimeZone>(time: chrono::DateTime<Tz>) -> String {
    format!(
        "backup-{:04}{:02}{:02}-{:02}{:02}.7z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute()
    )
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

    let network = selector.network;
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
    if device.device_type() == DeviceType::Ledger {
        let contexts = match ledger_signing_contexts(&mut device, &parsed, network).await {
            Ok(contexts) if contexts.is_empty() => {
                return HwiResponse::SignTx(HwiSignTxResponse {
                    psbt: original,
                    signed: false,
                });
            }
            Ok(contexts) => contexts,
            Err(LedgerSigningError::BadArgument(err)) => {
                return HwiResponse::Error(HwiError::new(HwiErrorCode::BadArgument, err));
            }
            Err(LedgerSigningError::Device(err)) => {
                return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceConnectionError, err));
            }
        };

        let mut signed_psbt = parsed;
        for signing in contexts {
            let mut signing_psbt = signed_psbt.clone();
            if signing.address_type == LedgerAddressType::Legacy {
                strip_legacy_witness_utxos(&mut signing_psbt);
            }
            let result = match device
                .device()
                .sign_tx(signing_psbt, Some(signing.context))
                .await
            {
                Ok(psbt) => psbt,
                Err(err) => {
                    return HwiResponse::Error(HwiError::new(
                        HwiErrorCode::DeviceConnectionError,
                        err.to_string(),
                    ));
                }
            };
            merge_psbt_signatures(&mut signed_psbt, result);
        }
        let signed = signed_psbt.to_string();
        return HwiResponse::SignTx(HwiSignTxResponse {
            signed: signed != original,
            psbt: signed,
        });
    }

    match device.device().sign_tx(parsed, None).await {
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
    let approval =
        coldcard_emulator_approval(coldcard_emulator_path(&device), ColdcardApproval::Once);
    let (signature, approval) = tokio::join!(
        device.device().sign_message(message.as_bytes(), path),
        approval
    );
    if let Err(err) = approval {
        return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceConnectionError, err));
    }
    match signature {
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
                    if matches!(
                        device.device_type(),
                        DeviceType::Coldcard | DeviceType::Jade
                    ) {
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

    let approval =
        coldcard_emulator_approval(coldcard_emulator_path(&device), ColdcardApproval::Once);
    let (address, approval) =
        tokio::join!(device.device().display_address(display, None), approval);
    if let Err(err) = approval {
        return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceConnectionError, err));
    }
    match address {
        Ok(address) => HwiResponse::DisplayAddress(HwiDisplayAddressResponse { address }),
        Err(err) => display_address_error(err.to_string()),
    }
}

#[derive(Clone, Copy)]
enum ColdcardApproval {
    Once,
    Backup,
}

fn coldcard_emulator_path(device: &Device) -> Option<String> {
    (device.device_type() == DeviceType::Coldcard && device.is_emulated())
        .then(|| device.path().to_string())
}

async fn coldcard_emulator_approval(
    socket_path: Option<String>,
    approval: ColdcardApproval,
) -> Result<(), String> {
    match socket_path {
        Some(socket_path) => coldcard_emulator_keypresses(&socket_path, approval).await,
        None => Ok(()),
    }
}

#[cfg(unix)]
async fn coldcard_emulator_keypresses(
    socket_path: &str,
    approval: ColdcardApproval,
) -> Result<(), String> {
    use tokio::net::UnixDatagram;

    let client_path = format!(
        "/tmp/bhwi-hwi-approval-{}-{}.sock",
        std::process::id(),
        generate_hwi_socket_id()
    );
    let _ = fs::remove_file(&client_path);
    let socket = UnixDatagram::bind(&client_path).map_err(|err| err.to_string())?;
    socket.connect(socket_path).map_err(|err| err.to_string())?;
    send_coldcard_simulator_keypress(&socket, b'y').await?;
    if matches!(approval, ColdcardApproval::Backup) {
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            send_coldcard_simulator_keypress(&socket, b'1').await?;
        }
    }
    drop(socket);
    let _ = fs::remove_file(client_path);
    Ok(())
}

#[cfg(unix)]
async fn send_coldcard_simulator_keypress(
    socket: &tokio::net::UnixDatagram,
    key: u8,
) -> Result<(), String> {
    let mut packet = [0u8; 64];
    packet[0] = 0x80 | 5;
    packet[1..5].copy_from_slice(b"XKEY");
    packet[5] = key;
    socket.send(&packet).await.map_err(|err| err.to_string())?;
    Ok(())
}

#[cfg(not(unix))]
async fn coldcard_emulator_keypresses(
    _socket_path: &str,
    _approval: ColdcardApproval,
) -> Result<(), String> {
    Ok(())
}

fn generate_hwi_socket_id() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SOCKET_COUNTER: AtomicUsize = AtomicUsize::new(0);
    SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
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

#[derive(Debug)]
enum LedgerSigningError {
    BadArgument(String),
    Device(String),
}

struct LedgerSigningContext {
    address_type: LedgerAddressType,
    context: DeviceContext,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LedgerAddressType {
    Tap,
    Wit,
    ShWit,
    Legacy,
}

impl LedgerAddressType {
    fn priority(self) -> u8 {
        match self {
            Self::Tap => 0,
            Self::Wit => 1,
            Self::ShWit => 2,
            Self::Legacy => 3,
        }
    }

    fn purpose(self) -> u32 {
        match self {
            Self::Legacy => 44,
            Self::ShWit => 49,
            Self::Wit => 84,
            Self::Tap => 86,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum LedgerSigningPlan {
    Default {
        address_type: LedgerAddressType,
        account_path: DerivationPath,
    },
    Registered {
        address_type: LedgerAddressType,
        name: String,
        policy: String,
    },
}

impl LedgerSigningPlan {
    fn priority(&self) -> u8 {
        match self {
            Self::Default { address_type, .. } | Self::Registered { address_type, .. } => {
                address_type.priority()
            }
        }
    }
}

async fn ledger_signing_contexts(
    device: &mut Device,
    psbt: &Psbt,
    network: Network,
) -> Result<Vec<LedgerSigningContext>, LedgerSigningError> {
    let fingerprint = device
        .fingerprint()
        .await
        .map_err(|err| LedgerSigningError::Device(err.to_string()))?;
    let plans = ledger_signing_plans(psbt, fingerprint, network)
        .map_err(LedgerSigningError::BadArgument)?;
    let mut contexts = Vec::with_capacity(plans.len());

    for plan in plans {
        match plan {
            LedgerSigningPlan::Default {
                address_type,
                account_path,
            } => {
                let xpub = device
                    .device()
                    .get_extended_pubkey(account_path.clone(), false)
                    .await
                    .map_err(|err| LedgerSigningError::Device(err.to_string()))?;
                let policy = singlesig_wallet_policy(
                    &extend_account_path_for_policy(&account_path),
                    fingerprint,
                    xpub,
                )
                .map_err(|err| LedgerSigningError::BadArgument(err.to_string()))?;
                contexts.push(LedgerSigningContext {
                    address_type,
                    context: DeviceContext::Ledger {
                        wallet_policy: LedgerWalletPolicy::new(String::new(), Version::V2, policy),
                        wallet_hmac: None,
                    },
                });
            }
            LedgerSigningPlan::Registered {
                address_type,
                name,
                policy,
            } => {
                let registration = device
                    .device()
                    .register_wallet(&name, &policy)
                    .await
                    .map_err(|err| LedgerSigningError::Device(err.to_string()))?;
                let hmac = registration.hmac().ok_or_else(|| {
                    LedgerSigningError::Device(
                        "Ledger wallet registration returned no HMAC".to_string(),
                    )
                })?;
                if hmac.len() != 32 {
                    return Err(LedgerSigningError::Device(format!(
                        "Ledger wallet registration returned a {}-byte HMAC instead of 32 bytes",
                        hmac.len()
                    )));
                }
                let wallet_policy = WalletPolicy::from_str(&policy)
                    .map_err(|err| LedgerSigningError::BadArgument(err.to_string()))?;
                contexts.push(LedgerSigningContext {
                    address_type,
                    context: DeviceContext::Ledger {
                        wallet_policy: LedgerWalletPolicy::new(name, Version::V2, wallet_policy),
                        wallet_hmac: Some(hmac),
                    },
                });
            }
        }
    }

    Ok(contexts)
}

fn strip_legacy_witness_utxos(psbt: &mut Psbt) {
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let Some(utxo) = input.non_witness_utxo.as_ref().and_then(|tx| {
            tx.output
                .get(psbt.unsigned_tx.input[index].previous_output.vout as usize)
        }) else {
            continue;
        };
        if !utxo.script_pubkey.is_witness_program() {
            input.witness_utxo = None;
        }
    }
}

fn merge_psbt_signatures(target: &mut Psbt, signed: Psbt) {
    for (target, signed) in target.inputs.iter_mut().zip(signed.inputs) {
        target.partial_sigs.extend(signed.partial_sigs);
        target.tap_script_sigs.extend(signed.tap_script_sigs);
        if signed.tap_key_sig.is_some() {
            target.tap_key_sig = signed.tap_key_sig;
        }
    }
}

fn ledger_signing_plans(
    psbt: &Psbt,
    fingerprint: Fingerprint,
    network: Network,
) -> Result<Vec<LedgerSigningPlan>, String> {
    let mut plans = Vec::new();

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let Some(utxo) = input_utxo(psbt, input_index)? else {
            continue;
        };
        let owns_input = input_has_fingerprint(input, fingerprint);
        let envelope = match multisig_script(input, &utxo, input_index) {
            Ok(envelope) => envelope,
            Err(err) if owns_input => return Err(err),
            Err(_) => None,
        };

        if let Some((address_type, script)) = envelope.as_ref()
            && let Some((threshold, pubkeys)) = parse_multisig_script(script)?
        {
            let owns_multisig = pubkeys.iter().any(|pubkey| {
                input
                    .bip32_derivation
                    .get(&pubkey.inner)
                    .is_some_and(|(key_fingerprint, _)| *key_fingerprint == fingerprint)
            });
            if owns_multisig {
                let plan = ledger_multisig_plan(
                    psbt,
                    input,
                    input_index,
                    *address_type,
                    threshold,
                    &pubkeys,
                )?;
                if !plans.contains(&plan) {
                    plans.push(plan);
                }
                continue;
            }
        }

        if let Some(plan) = ledger_singlesig_plan(input, &utxo, input_index, fingerprint, network)?
        {
            if !plans.contains(&plan) {
                plans.push(plan);
            }
            continue;
        }

        if owns_input {
            let policy = if utxo.script_pubkey.is_p2tr() {
                "taproot script-path"
            } else if envelope.is_some() {
                "non-sorted-multisig or miniscript"
            } else {
                "non-default"
            };
            return Err(format!(
                "input {input_index}: Ledger HWI signtx cannot infer {policy} wallet policy; use explicit descriptor and HMAC signing"
            ));
        }
    }

    plans.sort_by_key(LedgerSigningPlan::priority);
    Ok(plans)
}

fn ledger_singlesig_plan(
    input: &Input,
    utxo: &TxOut,
    input_index: usize,
    fingerprint: Fingerprint,
    network: Network,
) -> Result<Option<LedgerSigningPlan>, String> {
    let Some(address_type) = singlesig_address_type(input, utxo) else {
        return Ok(None);
    };

    if address_type == LedgerAddressType::Tap {
        let owned: Vec<_> = input
            .tap_key_origins
            .iter()
            .filter(|(_, (_, (key_fingerprint, _)))| *key_fingerprint == fingerprint)
            .collect();
        if owned.is_empty() {
            return Ok(None);
        }
        let Some(internal_key) = input.tap_internal_key else {
            return Err(format!(
                "input {input_index}: Ledger BIP86 input is missing tap_internal_key; use explicit descriptor and HMAC signing for non-default taproot policies"
            ));
        };
        let candidates: Vec<_> = owned
            .into_iter()
            .filter(|(key, (leaf_hashes, _))| **key == internal_key && leaf_hashes.is_empty())
            .collect();
        if candidates.len() != 1 || input.tap_merkle_root.is_some() {
            return Err(format!(
                "input {input_index}: Ledger HWI signtx supports only unambiguous BIP86 key-path inputs; use explicit descriptor and HMAC signing for taproot script paths"
            ));
        }
        let (_, (_, (_, path))) = candidates[0];
        let account_path =
            validate_standard_singlesig_path(path, address_type, network, input_index)?;
        let secp = Secp256k1::verification_only();
        let expected = Address::p2tr(&secp, internal_key, None, network).script_pubkey();
        if expected != utxo.script_pubkey {
            return Err(format!(
                "input {input_index}: BIP86 internal key does not match the prevout script; use explicit descriptor and HMAC signing for non-default taproot policies"
            ));
        }
        return Ok(Some(LedgerSigningPlan::Default {
            address_type,
            account_path,
        }));
    }

    let owned: Vec<_> = input
        .bip32_derivation
        .iter()
        .filter(|(_, (key_fingerprint, _))| *key_fingerprint == fingerprint)
        .collect();
    if owned.is_empty() {
        return Ok(None);
    }
    let candidates: Vec<_> = owned
        .into_iter()
        .filter(|(key, _)| singlesig_key_matches(**key, address_type, input, utxo, network))
        .collect();
    if candidates.len() != 1 {
        return Err(format!(
            "input {input_index}: Ledger single-sig key metadata is missing or ambiguous"
        ));
    }
    let (_, (_, path)) = candidates[0];
    let account_path = validate_standard_singlesig_path(path, address_type, network, input_index)?;
    Ok(Some(LedgerSigningPlan::Default {
        address_type,
        account_path,
    }))
}

fn singlesig_address_type(input: &Input, utxo: &TxOut) -> Option<LedgerAddressType> {
    if utxo.script_pubkey.is_p2pkh() {
        Some(LedgerAddressType::Legacy)
    } else if utxo.script_pubkey.is_p2wpkh() {
        Some(LedgerAddressType::Wit)
    } else if utxo.script_pubkey.is_p2tr() {
        Some(LedgerAddressType::Tap)
    } else if utxo.script_pubkey.is_p2sh()
        && input
            .redeem_script
            .as_ref()
            .is_some_and(|script| script.is_p2wpkh() && script.to_p2sh() == utxo.script_pubkey)
    {
        Some(LedgerAddressType::ShWit)
    } else {
        None
    }
}

fn singlesig_key_matches(
    key: bitcoin::secp256k1::PublicKey,
    address_type: LedgerAddressType,
    input: &Input,
    utxo: &TxOut,
    network: Network,
) -> bool {
    let key = PublicKey::new(key);
    match address_type {
        LedgerAddressType::Legacy => {
            Address::p2pkh(key, network).script_pubkey() == utxo.script_pubkey
        }
        LedgerAddressType::Wit => CompressedPublicKey::try_from(key)
            .is_ok_and(|key| Address::p2wpkh(&key, network).script_pubkey() == utxo.script_pubkey),
        LedgerAddressType::ShWit => CompressedPublicKey::try_from(key).is_ok_and(|key| {
            input.redeem_script.as_ref().is_some_and(|script| {
                Address::p2wpkh(&key, network).script_pubkey() == *script
                    && script.to_p2sh() == utxo.script_pubkey
            })
        }),
        LedgerAddressType::Tap => false,
    }
}

fn validate_standard_singlesig_path(
    path: &DerivationPath,
    address_type: LedgerAddressType,
    network: Network,
    input_index: usize,
) -> Result<DerivationPath, String> {
    let children = path.as_ref();
    if children.len() != 5 {
        return Err(format!(
            "input {input_index}: Ledger default wallet requires an exact five-level derivation path"
        ));
    }
    let purpose = hardened_index(children[0]);
    let coin_type = hardened_index(children[1]);
    let account = hardened_index(children[2]);
    let branch = normal_index(children[3]);
    let index = normal_index(children[4]);
    let expected_coin_type = if network == Network::Bitcoin { 0 } else { 1 };
    if purpose != Some(address_type.purpose())
        || coin_type != Some(expected_coin_type)
        || account.is_none()
        || !matches!(branch, Some(0 | 1))
        || index.is_none()
    {
        return Err(format!(
            "input {input_index}: derivation path {path} is not a standard Ledger {:?} wallet path",
            address_type
        ));
    }
    Ok(DerivationPath::from(children[..3].to_vec()))
}

fn hardened_index(child: ChildNumber) -> Option<u32> {
    match child {
        ChildNumber::Hardened { index } => Some(index),
        ChildNumber::Normal { .. } => None,
    }
}

fn normal_index(child: ChildNumber) -> Option<u32> {
    match child {
        ChildNumber::Normal { index } => Some(index),
        ChildNumber::Hardened { .. } => None,
    }
}

fn ledger_multisig_plan(
    psbt: &Psbt,
    input: &Input,
    input_index: usize,
    address_type: LedgerAddressType,
    threshold: usize,
    pubkeys: &[PublicKey],
) -> Result<LedgerSigningPlan, String> {
    if !pubkeys
        .windows(2)
        .all(|keys| keys[0].inner.serialize() < keys[1].inner.serialize())
    {
        return Err(format!(
            "input {input_index}: Ledger HWI signtx supports only sorted multisig scripts"
        ));
    }

    let mut keys = Vec::with_capacity(pubkeys.len());
    let mut expected_suffix = None;
    for pubkey in pubkeys {
        let key_source = input.bip32_derivation.get(&pubkey.inner).ok_or_else(|| {
            format!("input {input_index}: multisig public key is missing BIP32 derivation metadata")
        })?;
        let resolved = global_xpub_key_expression(psbt, key_source, pubkey, input_index)?;
        match expected_suffix {
            Some(suffix) if suffix != resolved.suffix => {
                return Err(format!(
                    "input {input_index}: multisig keys do not share one receive/change derivation"
                ));
            }
            None => expected_suffix = Some(resolved.suffix),
            Some(_) => {}
        }
        keys.push(format!("{}/<0;1>/*", resolved.expression));
    }
    // sortedmulti semantics do not depend on the key-info order. Canonicalize it so
    // inputs at different indexes reconstruct one stable registered wallet.
    keys.sort();
    let policy = multisig_policy_descriptor(address_type, threshold, &keys);
    Ok(LedgerSigningPlan::Registered {
        address_type,
        name: format!("{threshold} of {} Multisig", pubkeys.len()),
        policy,
    })
}

struct ResolvedMultisigKey {
    expression: String,
    suffix: (u32, u32),
}

fn global_xpub_key_expression(
    psbt: &Psbt,
    key_source: &KeySource,
    pubkey: &PublicKey,
    input_index: usize,
) -> Result<ResolvedMultisigKey, String> {
    let (fingerprint, key_path) = key_source;
    let children = key_path.as_ref();
    if children.len() < 2 {
        return Err(format!(
            "input {input_index}: multisig derivation path is too short"
        ));
    }
    let branch = normal_index(children[children.len() - 2]);
    let index = normal_index(children[children.len() - 1]);
    if !matches!(branch, Some(0 | 1)) || index.is_none() {
        return Err(format!(
            "input {input_index}: Ledger multisig derivation must end in /0/index or /1/index"
        ));
    }
    let suffix = (
        branch.expect("branch checked"),
        index.expect("index checked"),
    );
    let xpub_path = DerivationPath::from(children[..children.len() - 2].to_vec());
    let matches: Vec<_> = psbt
        .xpub
        .iter()
        .filter(|(_, (xpub_fingerprint, path))| {
            *xpub_fingerprint == *fingerprint && *path == xpub_path
        })
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "input {input_index}: expected one account-level global xpub for {fingerprint}, found {}",
            matches.len()
        ));
    }
    let (xpub, (_, origin_path)) = matches[0];
    let secp = Secp256k1::verification_only();
    let derived = xpub
        .derive_pub(
            &secp,
            &[
                ChildNumber::from_normal_idx(suffix.0).expect("branch checked"),
                ChildNumber::from_normal_idx(suffix.1).expect("index checked"),
            ],
        )
        .map_err(|err| format!("input {input_index}: failed to derive global xpub: {err}"))?;
    if derived.public_key != pubkey.inner {
        return Err(format!(
            "input {input_index}: global xpub derivation does not match multisig public key"
        ));
    }
    let origin = origin_path.to_string();
    let origin = origin.trim_start_matches('m').trim_start_matches('/');
    let expression = if origin.is_empty() {
        format!("[{fingerprint}]{xpub}")
    } else {
        format!("[{fingerprint}/{origin}]{xpub}")
    };
    Ok(ResolvedMultisigKey { expression, suffix })
}

fn input_has_fingerprint(input: &Input, fingerprint: Fingerprint) -> bool {
    input
        .bip32_derivation
        .values()
        .any(|(key_fingerprint, _)| *key_fingerprint == fingerprint)
        || input
            .tap_key_origins
            .values()
            .any(|(_, (key_fingerprint, _))| *key_fingerprint == fingerprint)
}

fn input_utxo(psbt: &Psbt, input_index: usize) -> Result<Option<TxOut>, String> {
    let input = &psbt.inputs[input_index];
    let txin = &psbt.unsigned_tx.input[input_index];
    let non_witness = if let Some(tx) = &input.non_witness_utxo {
        if tx.compute_txid() != txin.previous_output.txid {
            return Err(format!(
                "input {input_index}: non_witness_utxo transaction id does not match prevout"
            ));
        }
        Some(
            tx.output
                .get(txin.previous_output.vout as usize)
                .cloned()
                .ok_or_else(|| format!("input {input_index}: prevout index is out of range"))?,
        )
    } else {
        None
    };
    if let (Some(witness), Some(non_witness)) = (&input.witness_utxo, &non_witness)
        && witness != non_witness
    {
        return Err(format!(
            "input {input_index}: witness_utxo and non_witness_utxo disagree"
        ));
    }
    Ok(input.witness_utxo.clone().or(non_witness))
}

fn extend_account_path_for_policy(path: &DerivationPath) -> DerivationPath {
    let mut children = path.as_ref().to_vec();
    children.push(ChildNumber::from_normal_idx(0).expect("valid receive branch"));
    children.push(ChildNumber::from_normal_idx(0).expect("valid address index"));
    DerivationPath::from(children)
}

fn multisig_script(
    input: &Input,
    utxo: &TxOut,
    input_index: usize,
) -> Result<Option<(LedgerAddressType, ScriptBuf)>, String> {
    if utxo.script_pubkey.is_p2wsh() {
        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or_else(|| format!("input {input_index}: P2WSH input is missing witness_script"))?;
        if witness_script.to_p2wsh() != utxo.script_pubkey {
            return Err(format!(
                "input {input_index}: witness_script does not match P2WSH prevout"
            ));
        }
        return Ok(Some((LedgerAddressType::Wit, witness_script.clone())));
    }
    if !utxo.script_pubkey.is_p2sh() {
        return Ok(None);
    }
    let redeem_script = input
        .redeem_script
        .as_ref()
        .ok_or_else(|| format!("input {input_index}: P2SH input is missing redeem_script"))?;
    if redeem_script.to_p2sh() != utxo.script_pubkey {
        return Err(format!(
            "input {input_index}: redeem_script does not match P2SH prevout"
        ));
    }
    if redeem_script.is_p2wsh() {
        let witness_script = input.witness_script.as_ref().ok_or_else(|| {
            format!("input {input_index}: nested P2WSH input is missing witness_script")
        })?;
        if witness_script.to_p2wsh() != *redeem_script {
            return Err(format!(
                "input {input_index}: witness_script does not match nested P2WSH redeem_script"
            ));
        }
        Ok(Some((LedgerAddressType::ShWit, witness_script.clone())))
    } else {
        Ok(Some((LedgerAddressType::Legacy, redeem_script.clone())))
    }
}

fn parse_multisig_script(script: &ScriptBuf) -> Result<Option<(usize, Vec<PublicKey>)>, String> {
    let mut instructions = script.instructions();
    let Some(first) = instructions.next() else {
        return Ok(None);
    };
    let threshold = match first.map_err(|err| err.to_string())? {
        Instruction::Op(op) => pushnum(op).filter(|n| *n <= 16),
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

fn multisig_policy_descriptor(
    address_type: LedgerAddressType,
    threshold: usize,
    keys: &[String],
) -> String {
    let body = format!("sortedmulti({threshold},{})", keys.join(","));
    match address_type {
        LedgerAddressType::Legacy => format!("sh({body})"),
        LedgerAddressType::ShWit => format!("sh(wsh({body}))"),
        LedgerAddressType::Wit => format!("wsh({body})"),
        LedgerAddressType::Tap => unreachable!("taproot is not classic multisig"),
    }
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
    let (address_type, sorted, inner) =
        parse_multisig_descriptor_envelope(descriptor).ok_or_else(|| {
            HwiError::new(
                HwiErrorCode::BadArgument,
                format!("Unsupported displayaddress descriptor: {descriptor}"),
            )
        })?;

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
    let keys = parts
        .map(|key| {
            DescriptorPublicKey::from_str(key)
                .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() || threshold == 0 || usize::from(threshold) > keys.len() {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "Either the redeem script provided is invalid or the keypaths provided are insufficient",
        ));
    }
    Ok(MultisigDisplayAddress {
        threshold,
        address_type,
        sorted,
        keys,
    })
}

fn parse_multisig_descriptor_envelope(
    descriptor: &str,
) -> Option<(MultisigAddressType, bool, &str)> {
    let wrappers = [
        ("sh(wsh(", "))", MultisigAddressType::ShWit),
        ("wsh(", ")", MultisigAddressType::Wit),
        ("sh(", ")", MultisigAddressType::Legacy),
    ];
    for (prefix, suffix, address_type) in wrappers {
        let Some(inner) = descriptor
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
        else {
            continue;
        };
        if let Some(inner) = inner
            .strip_prefix("sortedmulti(")
            .and_then(|value| value.strip_suffix(')'))
        {
            return Some((address_type, true, inner));
        }
        if let Some(inner) = inner
            .strip_prefix("multi(")
            .and_then(|value| value.strip_suffix(')'))
        {
            return Some((address_type, false, inner));
        }
    }
    None
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
        || error.contains("does not support this address format")
    {
        HwiErrorCode::UnsupportedCommand
    } else if error.contains("Coldcard Error:") || error.starts_with("invalid input:") {
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
        DeviceType::Trezor => model != "trezor_one",
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

fn reports_device_info(device_type: DeviceType) -> bool {
    matches!(device_type, DeviceType::Trezor)
}

fn label_for(device_type: DeviceType, label: Option<String>) -> Option<Option<String>> {
    match device_type {
        DeviceType::Coldcard | DeviceType::Ledger | DeviceType::Trezor => Some(label),
        DeviceType::BitBox02 | DeviceType::Jade => None,
    }
}

fn hwi_enumerate_model(
    device_type: DeviceType,
    model: &str,
    is_emulated: bool,
    firmware: Option<&str>,
) -> String {
    match (device_type, is_emulated) {
        (DeviceType::BitBox02, true) => "bitbox02_nova_multi".to_owned(),
        (DeviceType::Trezor, emulated) => match firmware {
            Some(reported) => {
                let suffix = if emulated { "_simulator" } else { "" };
                format!("trezor_{}{suffix}", reported.to_lowercase())
            }
            None => model.to_owned(),
        },
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
        (DeviceType::Trezor, HwiUnsupportedDeviceAction::Setup { .. }) => {
            "Trezor setup is not yet supported"
        }
        (DeviceType::Trezor, HwiUnsupportedDeviceAction::Wipe) => {
            "Trezor wipe is not yet supported"
        }
        (DeviceType::Trezor, HwiUnsupportedDeviceAction::Restore { .. }) => {
            "Trezor restore is not yet supported"
        }
        (DeviceType::Trezor, HwiUnsupportedDeviceAction::Backup { .. }) => {
            "Trezor does not support creating a backup via software"
        }
        (DeviceType::Trezor, HwiUnsupportedDeviceAction::PromptPin) => {
            "Trezor PIN entry is not yet supported"
        }
        (DeviceType::Trezor, HwiUnsupportedDeviceAction::SendPin { .. }) => {
            "Trezor PIN entry is not yet supported"
        }
        (DeviceType::Trezor, HwiUnsupportedDeviceAction::TogglePassphrase) => {
            "Trezor passphrase toggling is not yet supported"
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
    println!(
        "{}",
        serde_json::to_string(&response).expect("serialize HWI response")
    );
    // Runtime error JSON exits 0 to match Python HWI 3.2.0 (hwilib/_cli.py main).
    ExitCode::SUCCESS
}

fn parse_device_type(value: &str) -> HwiResult<DeviceType> {
    let family = value.split('_').next().unwrap_or(value);
    match family.to_ascii_lowercase().as_str() {
        "bitbox02" => Ok(DeviceType::BitBox02),
        "coldcard" => Ok(DeviceType::Coldcard),
        "jade" => Ok(DeviceType::Jade),
        "ledger" => Ok(DeviceType::Ledger),
        "trezor" => Ok(DeviceType::Trezor),
        _ => Err(HwiError::new(
            HwiErrorCode::UnknownDevice,
            "Unknown device type specified",
        )),
    }
}

fn is_known_emulator_path(device_type: Option<DeviceType>, path: Option<&str>) -> bool {
    matches!(
        (device_type, path),
        (
            Some(DeviceType::BitBox02),
            Some("127.0.0.1:15423" | "tcp:127.0.0.1:15423")
        ) | (Some(DeviceType::Coldcard), Some("/tmp/ckcc-simulator.sock"))
            | (
                Some(DeviceType::Jade),
                Some("127.0.0.1:30121" | "tcp:127.0.0.1:30121")
            )
            | (
                Some(DeviceType::Ledger),
                Some("127.0.0.1:9999" | "tcp:127.0.0.1:9999")
            )
            | (
                Some(DeviceType::Trezor),
                Some("127.0.0.1:21324" | "udp:127.0.0.1:21324")
            )
    )
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
    let include_emulators =
        args.emulators || is_known_emulator_path(device_type, args.device_path.as_deref());
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
        } => HwiCommand::Setup {
            interactive: args.interactive,
            label,
            backup_passphrase,
        },
        HwiCliCommand::Wipe => HwiCommand::Wipe,
        HwiCliCommand::Restore { word_count, label } => HwiCommand::Restore {
            interactive: args.interactive,
            word_count,
            label,
        },
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
        HwiCliCommand::Togglepassphrase => HwiCommand::TogglePassphrase,
        #[cfg(target_os = "linux")]
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
            include_emulators,
        },
        command,
    })
}

fn parse_chain(value: &str) -> HwiResult<Network> {
    match value {
        "main" | "mainnet" => Ok(Network::Bitcoin),
        "test" | "testnet" => Ok(Network::Testnet),
        _ => Network::from_str(value).map_err(|_| {
            HwiError::new(
                HwiErrorCode::MissingArguments,
                format!("argument --chain: invalid choice: '{value}'"),
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
        bip32::Xpriv,
        blockdata::{opcodes::all::OP_CHECKMULTISIG, script::Builder},
        secp256k1::Secp256k1,
        transaction::Version as TxVersion,
    };
    use chrono::{FixedOffset, TimeZone};

    #[test]
    fn device_type_accepts_model_qualified_names() {
        for value in ["trezor", "trezor_1", "trezor_t", "trezor_1_simulator"] {
            assert_eq!(parse_device_type(value).unwrap(), DeviceType::Trezor);
        }
        assert_eq!(parse_device_type("bitbox02").unwrap(), DeviceType::BitBox02);
        assert_eq!(
            parse_device_type("coldcard_simulator").unwrap(),
            DeviceType::Coldcard
        );
        assert!(parse_device_type("notadevice").is_err());
    }

    #[test]
    fn backup_filename_matches_python_hwi_local_time_format() {
        let time = FixedOffset::east_opt(3 * 60 * 60)
            .unwrap()
            .with_ymd_and_hms(2026, 7, 21, 9, 5, 0)
            .single()
            .unwrap();

        assert_eq!(format_hwi_backup_filename(time), "backup-20260721-0905.7z");
    }

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
        let error = parse_args(["hwi", "--device-type", "nonexistent", "enumerate"])
            .expect_err("unsupported device type");

        assert_eq!(error.code, HwiErrorCode::UnknownDevice.code());
        assert_eq!(error.error, "Unknown device type specified");
    }

    #[test]
    fn accepts_bitbox02_device_type() {
        let request =
            parse_args(["hwi", "--device-type", "bitbox02", "enumerate"]).expect("bitbox02 parses");

        assert_eq!(request.selector.device_type, Some(DeviceType::BitBox02));
    }

    #[test]
    fn trezor_enumerate_model_follows_python_hwi() {
        let model = |firmware, emulated| {
            hwi_enumerate_model(DeviceType::Trezor, "trezor_t", emulated, firmware)
        };
        assert_eq!(model(Some("T"), false), "trezor_t");
        assert_eq!(model(Some("1"), false), "trezor_1");
        assert_eq!(model(Some("Safe 3"), false), "trezor_safe 3");
        assert_eq!(model(Some("1"), true), "trezor_1_simulator");
        assert_eq!(model(Some("T"), true), "trezor_t_simulator");
        assert_eq!(model(None, false), "trezor_t");
    }

    #[test]
    fn accepts_trezor_device_type() {
        let request =
            parse_args(["hwi", "--device-type", "trezor", "enumerate"]).expect("trezor parses");

        assert_eq!(request.selector.device_type, Some(DeviceType::Trezor));
    }

    #[test]
    fn parses_setup_action() {
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
        .expect("setup request");

        assert_eq!(request.selector.network, Network::Testnet);
        assert_eq!(request.selector.device_type, Some(DeviceType::Ledger));
        assert_eq!(
            request.command,
            HwiCommand::Setup {
                interactive: true,
                label: "HWI Ledger".to_owned(),
                backup_passphrase: "backup passphrase".to_owned(),
            }
        );
    }

    #[test]
    fn parses_wipe_action() {
        let request =
            parse_args(["hwi", "--device-type", "bitbox02", "wipe"]).expect("wipe request");

        assert_eq!(request.selector.device_type, Some(DeviceType::BitBox02));
        assert_eq!(request.command, HwiCommand::Wipe);
    }

    #[test]
    fn parses_restore_action() {
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
        .expect("restore request");

        assert_eq!(
            request.command,
            HwiCommand::Restore {
                interactive: true,
                word_count: 12,
                label: "HWI Jade".to_owned(),
            }
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
    fn parses_pin_actions_and_toggle_passphrase() {
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
            .expect("togglepassphrase request");
        assert_eq!(togglepassphrase.command, HwiCommand::TogglePassphrase);
    }

    #[cfg(target_os = "linux")]
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

    fn outcome_of(args: &[&str]) -> CliOutcome {
        cli_outcome(args.iter().map(OsString::from).collect())
    }

    fn usage_of(args: &[&str]) -> UsageError {
        match outcome_of(args) {
            CliOutcome::Usage(usage) => usage,
            other => panic!("expected usage error for {args:?}, got {other:?}"),
        }
    }

    fn runtime_error_of(args: &[&str]) -> HwiError {
        match outcome_of(args) {
            CliOutcome::Response(HwiResponse::Error(error)) => error,
            other => panic!("expected runtime error for {args:?}, got {other:?}"),
        }
    }

    #[test]
    fn missing_command_is_a_usage_error() {
        let args = ["hwi"];
        let usage = usage_of(&args);

        assert_eq!(
            usage.message,
            "hwi: error: the following arguments are required: command"
        );
        assert!(usage.usage.contains("Usage:"), "{}", usage.usage);
        assert!(usage.usage.contains("hwi"), "{}", usage.usage);
        assert_eq!(exit_status(&outcome_of(&args)), 2);
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        let args = ["hwi", "boguscmd"];
        let usage = usage_of(&args);

        assert_eq!(
            usage.message,
            "hwi: error: argument command: invalid choice: 'boguscmd'"
        );
        assert_eq!(exit_status(&outcome_of(&args)), 2);
    }

    #[test]
    fn missing_required_argument_is_a_usage_error() {
        let usage = usage_of(&["hwi", "getxpub"]);

        assert!(usage.message.contains("required"), "{}", usage.message);
        assert!(usage.message.contains("<PATH>"), "{}", usage.message);
        assert!(usage.usage.contains("getxpub"), "{}", usage.usage);
    }

    #[test]
    fn invalid_flag_choice_is_a_usage_error() {
        let usage = usage_of(&["hwi", "getmasterxpub", "--addr-type", "bogus"]);

        assert!(
            usage.message.contains("invalid value 'bogus'"),
            "{}",
            usage.message
        );
        assert!(usage.usage.contains("Usage:"), "{}", usage.usage);
    }

    #[test]
    fn invalid_chain_choice_is_a_usage_error() {
        let usage = usage_of(&["hwi", "--chain", "foo", "enumerate"]);

        assert_eq!(
            usage.message,
            "hwi: error: argument --chain: invalid choice: 'foo'"
        );
    }

    #[test]
    fn usage_errors_serialize_python_hwi_json() {
        let usage = usage_of(&["hwi", "boguscmd"]);
        let json = serde_json::to_string(&HwiError {
            error: usage.message,
            code: HwiErrorCode::MissingArguments.code(),
        })
        .expect("serialize usage error");

        assert_eq!(
            json,
            r#"{"error":"hwi: error: argument command: invalid choice: 'boguscmd'","code":-2}"#
        );
    }

    #[test]
    fn runtime_errors_keep_their_code_and_exit_zero() {
        let bad_path = ["hwi", "getxpub", "not_a_path"];
        assert_eq!(
            runtime_error_of(&bad_path).code,
            HwiErrorCode::BadArgument.code()
        );
        assert_eq!(exit_status(&outcome_of(&bad_path)), 0);

        let bad_device = ["hwi", "--device-type", "keepkey", "enumerate"];
        assert_eq!(
            runtime_error_of(&bad_device).code,
            HwiErrorCode::UnknownDevice.code()
        );
        assert_eq!(exit_status(&outcome_of(&bad_device)), 0);
    }

    #[test]
    fn help_and_version_print_to_stdout_and_exit_zero() {
        for args in [["hwi", "--help"], ["hwi", "--version"]] {
            let outcome = outcome_of(&args);
            let CliOutcome::Stdout(text) = &outcome else {
                panic!("expected stdout outcome for {args:?}, got {outcome:?}");
            };
            assert!(!text.is_empty());
            assert_eq!(exit_status(&outcome), 0);
        }
    }

    #[test]
    fn successful_parse_yields_a_request_and_exits_zero() {
        let args = ["hwi", "--device-type", "ledger", "enumerate"];
        let outcome = outcome_of(&args);

        assert!(matches!(outcome, CliOutcome::Request(_)));
        assert_eq!(exit_status(&outcome), 0);
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
                label: label_for(DeviceType::Ledger, None),
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
                label: label_for(DeviceType::Coldcard, None),
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
            label: label_for(DeviceType::Jade, None),
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
            model: hwi_enumerate_model(DeviceType::BitBox02, "bitbox02_simulator", true, None),
            path: hwi_enumerate_path(DeviceType::BitBox02, "tcp:127.0.0.1:15423", true),
            label: label_for(DeviceType::BitBox02, None),
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
    fn unsupported_bitbox_address_format_uses_hwi_unsupported_code() {
        let response = display_address_error(
            "invalid input: BitBox does not support this address format".into(),
        );
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::UnsupportedCommand.code());
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
        assert!(parsed.sorted);
        assert_eq!(parsed.keys.len(), 2);
        let origins = parsed
            .keys
            .iter()
            .map(|key| match key {
                DescriptorPublicKey::Single(key) => key.origin.clone().unwrap().1,
                _ => panic!("expected concrete public key"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            origins,
            vec![
                DerivationPath::from_str("m/48h/1h/0h/0h/0").unwrap(),
                DerivationPath::from_str("m/48h/1h/1h/0h/0").unwrap(),
            ]
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
    fn ledger_signing_plans_cover_all_default_wallets() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let pubkey = sample_child_pubkey(0);
        for (address_type, path, input) in [
            (
                LedgerAddressType::Legacy,
                "m/44'/1'/0'/0/0",
                Input {
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: Address::p2pkh(pubkey, Network::Testnet).script_pubkey(),
                    }),
                    ..Default::default()
                },
            ),
            (LedgerAddressType::ShWit, "m/49'/1'/0'/0/0", {
                let redeem_script = Address::p2wpkh(
                    &CompressedPublicKey::try_from(pubkey).unwrap(),
                    Network::Testnet,
                )
                .script_pubkey();
                Input {
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: redeem_script.to_p2sh(),
                    }),
                    redeem_script: Some(redeem_script),
                    ..Default::default()
                }
            }),
            (
                LedgerAddressType::Wit,
                "m/84'/1'/0'/0/0",
                Input {
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: Address::p2wpkh(
                            &CompressedPublicKey::try_from(pubkey).unwrap(),
                            Network::Testnet,
                        )
                        .script_pubkey(),
                    }),
                    ..Default::default()
                },
            ),
        ] {
            let path = DerivationPath::from_str(path).unwrap();
            let mut input = input;
            input
                .bip32_derivation
                .insert(pubkey.inner, (fingerprint, path));
            assert_eq!(
                ledger_signing_plans(&psbt_with_input(input), fingerprint, Network::Testnet)
                    .unwrap(),
                vec![LedgerSigningPlan::Default {
                    address_type,
                    account_path: DerivationPath::from_str(&format!(
                        "m/{}'/1'/0'",
                        address_type.purpose()
                    ))
                    .unwrap(),
                }]
            );
        }

        let internal_key = pubkey.inner.x_only_public_key().0;
        let path = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
        let psbt = psbt_with_input(Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Address::p2tr(
                    &Secp256k1::verification_only(),
                    internal_key,
                    None,
                    Network::Testnet,
                )
                .script_pubkey(),
            }),
            tap_internal_key: Some(internal_key),
            tap_key_origins: [(internal_key, (Vec::new(), (fingerprint, path)))].into(),
            ..Default::default()
        });
        assert_eq!(
            ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap(),
            vec![LedgerSigningPlan::Default {
                address_type: LedgerAddressType::Tap,
                account_path: DerivationPath::from_str("m/86'/1'/0'").unwrap(),
            }]
        );
    }

    #[test]
    fn ledger_signing_plans_support_multiple_singlesig_accounts() {
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);
        let pubkey_a = sample_child_pubkey(0);
        let pubkey_b = sample_child_pubkey(1);
        let psbt = psbt_with_inputs(vec![
            Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Address::p2wpkh(
                        &CompressedPublicKey::try_from(pubkey_a).unwrap(),
                        Network::Testnet,
                    )
                    .script_pubkey(),
                }),
                bip32_derivation: [(
                    pubkey_a.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                    ),
                )]
                .into(),
                ..Default::default()
            },
            Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Address::p2wpkh(
                        &CompressedPublicKey::try_from(pubkey_b).unwrap(),
                        Network::Testnet,
                    )
                    .script_pubkey(),
                }),
                bip32_derivation: [(
                    pubkey_b.inner,
                    (
                        fingerprint,
                        DerivationPath::from_str("m/84'/1'/1'/0/0").unwrap(),
                    ),
                )]
                .into(),
                ..Default::default()
            },
        ]);

        let plans = ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap();
        assert_eq!(plans.len(), 2);
        assert!(plans.iter().all(|plan| matches!(
            plan,
            LedgerSigningPlan::Default {
                address_type: LedgerAddressType::Wit,
                ..
            }
        )));
    }

    #[test]
    fn ledger_signing_plans_support_mixed_default_and_registered_policies() {
        let (multisig, fingerprint) = sample_multisig_psbt(LedgerAddressType::Wit, true);
        let pubkey = sample_child_pubkey(0);
        let singlesig = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Address::p2wpkh(
                    &CompressedPublicKey::try_from(pubkey).unwrap(),
                    Network::Testnet,
                )
                .script_pubkey(),
            }),
            bip32_derivation: [(
                pubkey.inner,
                (
                    fingerprint,
                    DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                ),
            )]
            .into(),
            ..Default::default()
        };
        let mut psbt = psbt_with_inputs(vec![singlesig, multisig.inputs[0].clone()]);
        psbt.xpub = multisig.xpub;

        let plans = ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap();
        assert_eq!(plans.len(), 2);
        assert!(matches!(plans[0], LedgerSigningPlan::Default { .. }));
        assert!(matches!(plans[1], LedgerSigningPlan::Registered { .. }));
    }

    #[test]
    fn ledger_multisig_plans_cover_all_hwi_wrappers() {
        for address_type in [
            LedgerAddressType::Legacy,
            LedgerAddressType::ShWit,
            LedgerAddressType::Wit,
        ] {
            let (psbt, fingerprint) = sample_multisig_psbt(address_type, true);
            let plans = ledger_signing_plans(&psbt, fingerprint, Network::Testnet).unwrap();
            let LedgerSigningPlan::Registered { policy, name, .. } = &plans[0] else {
                panic!("registered policy");
            };
            assert_eq!(name, "2 of 2 Multisig");
            assert_eq!(policy.matches("/<0;1>/*").count(), 2);
            match address_type {
                LedgerAddressType::Legacy => assert!(policy.starts_with("sh(sortedmulti(2,")),
                LedgerAddressType::ShWit => {
                    assert!(policy.starts_with("sh(wsh(sortedmulti(2,"))
                }
                LedgerAddressType::Wit => assert!(policy.starts_with("wsh(sortedmulti(2,")),
                LedgerAddressType::Tap => unreachable!(),
            }
        }
    }

    #[test]
    fn ledger_multisig_plan_rejects_missing_global_xpub() {
        let (mut psbt, fingerprint) = sample_multisig_psbt(LedgerAddressType::Wit, true);
        psbt.xpub.clear();

        let err =
            ledger_signing_plans(&psbt, fingerprint, Network::Testnet).expect_err("missing xpub");
        assert!(err.contains("expected one account-level global xpub"));
    }

    #[test]
    fn ledger_multisig_plan_rejects_unsorted_script() {
        let (psbt, fingerprint) = sample_multisig_psbt(LedgerAddressType::Wit, false);

        let err = ledger_signing_plans(&psbt, fingerprint, Network::Testnet)
            .expect_err("unsorted multisig");
        assert!(err.contains("supports only sorted multisig"));
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

    fn sample_multisig_psbt(address_type: LedgerAddressType, sorted: bool) -> (Psbt, Fingerprint) {
        let secp = Secp256k1::new();
        let account_path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
        let suffix = [
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ];
        let mut sources = Vec::new();
        for seed in [1_u8, 2] {
            let master = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap();
            let fingerprint = master.fingerprint(&secp);
            let account = master.derive_priv(&secp, &account_path).unwrap();
            let xpub = Xpub::from_priv(&secp, &account);
            let child = xpub.derive_pub(&secp, &suffix).unwrap();
            sources.push((fingerprint, xpub, PublicKey::new(child.public_key)));
        }
        sources.sort_by_key(|(_, _, pubkey)| pubkey.inner.serialize());
        if !sorted {
            sources.reverse();
        }
        let pubkeys: Vec<_> = sources.iter().map(|(_, _, pubkey)| *pubkey).collect();
        let script = multisig_script_buf(2, &pubkeys);
        let mut input = Input {
            bip32_derivation: sources
                .iter()
                .map(|(fingerprint, _, pubkey)| {
                    let mut path = account_path.as_ref().to_vec();
                    path.extend_from_slice(&suffix);
                    (pubkey.inner, (*fingerprint, DerivationPath::from(path)))
                })
                .collect(),
            ..Default::default()
        };
        let script_pubkey = match address_type {
            LedgerAddressType::Legacy => {
                input.redeem_script = Some(script.clone());
                script.to_p2sh()
            }
            LedgerAddressType::ShWit => {
                let redeem_script = script.to_p2wsh();
                input.redeem_script = Some(redeem_script.clone());
                input.witness_script = Some(script);
                redeem_script.to_p2sh()
            }
            LedgerAddressType::Wit => {
                input.witness_script = Some(script.clone());
                script.to_p2wsh()
            }
            LedgerAddressType::Tap => unreachable!(),
        };
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        });
        let mut psbt = psbt_with_input(input);
        for (fingerprint, xpub, _) in &sources {
            psbt.xpub
                .insert(*xpub, (*fingerprint, account_path.clone()));
        }
        (psbt, sources[0].0)
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
