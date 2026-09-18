#[cfg(feature = "keepkey")]
use bhwi::keepkey::{DEFAULT_KEEPKEY_EMULATOR, KEEPKEY_LOCKED};
use bhwi::{bitcoin::psbt::Psbt, passphrase::HostPassphrase};
use bhwi_async::display_address::{
    DisplayAddressError, multisig_display_address_from_descriptor,
    singlesig_display_address_from_descriptor,
};
#[cfg(feature = "ledger")]
use bhwi_async::psbt::{merge_psbt_signatures, strip_legacy_witness_utxos};
#[cfg(feature = "ledger")]
use bhwi_async::signing::ledger::{
    LedgerAddressType, LedgerSigningError, ledger_multisig_display_address, ledger_signing_contexts,
};
use bhwi_async::signing::message_signature;
use bhwi_async::{DeviceBackup, DisplayAddress, RestoreOptions, SetupOptions};
use bitcoin::{
    Network, NetworkKind,
    base64::prelude::{BASE64_STANDARD, Engine as _},
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
};
use chrono::{Datelike, Local, Timelike};
use clap::{ArgAction, ArgGroup, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    descriptor::{DescriptorType, checksum},
};
use serde::{Serialize, Serializer};
use std::{
    ffi::OsString,
    fs,
    io::{self, BufRead},
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
};

#[cfg(feature = "bitbox")]
use crate::management::{bitbox_restore_context, bitbox_setup_context};
#[cfg(feature = "keepkey")]
use crate::management::{keepkey_restore_context, keepkey_setup_context};
#[cfg(feature = "trezor")]
use crate::management::{trezor_restore_context, trezor_setup_context};
#[cfg(target_os = "linux")]
use crate::udev::{UdevRuleSelection, install_udev_rules};
use crate::{
    Device, DeviceManager, DeviceSelector, DeviceType, can_sign_taproot, device_manager,
    get_descriptors::{GetDescriptorOptions, get_descriptor},
    reports_device_info,
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
        path: String,
    },
    #[command(group(
        ArgGroup::new("address_target")
            .required(true)
            .args(["path", "desc"])
    ))]
    Displayaddress {
        #[arg(long, conflicts_with = "desc")]
        path: Option<String>,
        #[arg(long, conflicts_with = "path")]
        desc: Option<String>,
        #[arg(long = "addr-type", value_enum, default_value = "wit")]
        addr_type: HwiAddressType,
    },
    Getxpub {
        path: String,
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
    pub selector: HwiSelector,
    pub command: HwiCommand,
}

/// Device selection as parsed from argv. The device type stays a raw string
/// until device lookup, matching upstream where an unknown type is a lookup
/// failure (`-3`), or `-4` only when `get_client` is reached via `-d`.
#[derive(Debug, Clone)]
pub struct HwiSelector {
    pub network: Network,
    pub fingerprint: Option<Fingerprint>,
    pub device_type: Option<String>,
    pub device_path: Option<String>,
    pub include_emulators: bool,
    pub passphrase: Option<HostPassphrase>,
}

impl HwiSelector {
    fn device_selector(&self, device_type: Option<DeviceType>) -> DeviceSelector {
        DeviceSelector {
            network: self.network,
            fingerprint: self.fingerprint,
            device_type,
            device_path: self.device_path.clone(),
            include_emulators: self.include_emulators,
            passphrase: self.passphrase.clone(),
        }
    }
}
fn hwi_selector_matches_device(
    raw: Option<&str>,
    device_type: DeviceType,
    model: &str,
    is_emulated: bool,
) -> bool {
    let Some(raw) = raw else {
        return true;
    };
    let Ok(selected_type) = parse_device_type(raw) else {
        return false;
    };
    selected_type == device_type
        && (!raw.eq_ignore_ascii_case("keepkey_simulator")
            || (model == "keepkey_simulator" && is_emulated))
}

/// Resolves the raw device type, reproducing upstream's error precedence:
/// `-1` without type/fingerprint, `-4` for an unknown type with a path, then
/// `-3` when an unknown type cannot match an enumerated device.
fn hwi_device_manager(selector: &HwiSelector) -> Result<DeviceManager, HwiError> {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return Err(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }
    let device_type = match selector.device_type.as_deref() {
        None => None,
        Some(raw) => match parse_device_type(raw) {
            Ok(device_type) => Some(device_type),
            Err(err) if selector.device_path.is_some() && selector.fingerprint.is_none() => {
                return Err(err);
            }
            Err(_) => {
                return Err(HwiError::new(
                    HwiErrorCode::DeviceConnectionError,
                    "Could not find device with specified fingerprint or type",
                ));
            }
        },
    };
    Ok(device_manager(selector.device_selector(device_type)))
}

async fn find_hwi_device(selector: &HwiSelector) -> Result<(DeviceManager, Device), HwiError> {
    let manager = hwi_device_manager(selector)?;
    match manager.get_device_with_fingerprint().await {
        Ok(Some(device))
            if hwi_selector_matches_device(
                selector.device_type.as_deref(),
                device.device_type(),
                device.model(),
                device.is_emulated(),
            ) =>
        {
            Ok((manager, device))
        }
        Ok(Some(_)) | Ok(None) => Err(HwiError::new(
            HwiErrorCode::DeviceConnectionError,
            "Could not find device with specified fingerprint or type",
        )),
        Err(err) => Err(classify_device_error(&err)),
    }
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
        path: String,
    },
    DisplayAddress(HwiDisplayAddressRequest),
    GetXpub {
        path: String,
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
    PromptPin,
    SendPin {
        pin: String,
    },
    UnsupportedDeviceAction(HwiUnsupportedDeviceAction),
    #[cfg(target_os = "linux")]
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
        path: String,
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
    DeviceAlreadyInitialized,
    DeviceAlreadyUnlocked,
    DeviceNotReady,
    DeviceNotInitialized,
    HelpText,
    ActionCanceled,
    InvalidTx,
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
            HwiErrorCode::DeviceAlreadyInitialized => -10,
            HwiErrorCode::DeviceAlreadyUnlocked => -11,
            HwiErrorCode::DeviceNotReady => -12,
            HwiErrorCode::DeviceNotInitialized => -18,
            HwiErrorCode::HelpText => -17,
            HwiErrorCode::ActionCanceled => -14,
            HwiErrorCode::InvalidTx => -5,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Vec<String>>,
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
        HwiCommand::PromptPin => prompt_pin_device(request.selector).await,
        HwiCommand::SendPin { pin } => send_pin_device(request.selector, pin).await,
        HwiCommand::UnsupportedDeviceAction(action) => {
            unsupported_device_action(request.selector, action).await
        }
        #[cfg(target_os = "linux")]
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
        CliOutcome::Help(help) => {
            // Python HWI 3.2.0 prints a `-17` JSON object on stdout and the
            // help text on stderr (hwilib/_cli.py HWIHelpAction).
            println!(
                "{}",
                serde_json::to_string(&HwiError::new(
                    HwiErrorCode::HelpText,
                    "Help text requested",
                ))
                .expect("serialize HWI help error")
            );
            eprint!("{help}");
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
    Help(String),
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
    let mut cli = match HwiCli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => return clap_outcome(&prog, err),
    };
    if let Err(err) = read_stdin_password(&mut cli) {
        return CliOutcome::Response(HwiResponse::Error(err));
    }
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
        // Upstream shares one HWIArgumentParser across subparsers, so every
        // `--help` takes the `-17` JSON path; `--version` stays plain stdout.
        ErrorKind::DisplayHelp => CliOutcome::Help(err.to_string()),
        ErrorKind::DisplayVersion => CliOutcome::Stdout(err.to_string()),
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand | ErrorKind::MissingSubcommand => {
            CliOutcome::Usage(UsageError {
                message: format!("{prog}: error: the following arguments are required: command"),
                usage: top_level_usage(prog),
            })
        }
        ErrorKind::MissingRequiredArgument
        | ErrorKind::UnknownArgument
        | ErrorKind::InvalidValue
        | ErrorKind::ValueValidation
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

const EMPTY_PASSPHRASE_WARNING: &str = "Passphrase protection enabled but passphrase was not provided. Using default passphrase of the empty string (\"\")";
const KEEPKEY_PASSPHRASE_REQUIRED: &str =
    "Passphrase needs to be specified before the fingerprint information can be retrieved";

async fn enumerate(selector: HwiSelector) -> HwiResponse {
    // Upstream enumerate ignores an unrecognized -t entirely; drop the filter
    // rather than failing so the exit stays 0 with a JSON array.
    let device_type = selector
        .device_type
        .as_deref()
        .and_then(|raw| parse_device_type(raw).ok());
    let raw_device_type = device_type.and(selector.device_type.as_deref());
    let manager = device_manager(selector.device_selector(device_type));
    let scan = match manager.enumerate().await {
        Ok(scan) => scan,
        Err(err) => {
            return HwiResponse::Error(device_error(err));
        }
    };
    let mut response = Vec::with_capacity(scan.devices.len() + scan.skipped.len());
    for mut device in scan.devices {
        if !hwi_selector_matches_device(
            raw_device_type,
            device.device_type(),
            device.model(),
            device.is_emulated(),
        ) {
            continue;
        }
        let mut error = None;
        let mut code = None;
        let mut info = None;
        let mut fingerprint = None;
        let mut needs_pin_sent = false;
        let mut needs_passphrase_sent = false;
        let mut warnings = Vec::new();
        match device.device().unlock(manager.selector.network).await {
            Ok(()) => {
                // A device waiting for a PIN stops answering every other request, and the
                // fingerprint request is what makes it start waiting.
                if reports_device_info(device.device_type()) {
                    match device.info().await {
                        Ok(device_info) => info = Some(device_info),
                        Err(err) => {
                            error = Some(err.to_string());
                            code = Some(HwiErrorCode::DeviceConnectionError.code());
                        }
                    }
                }
                needs_pin_sent = info
                    .as_ref()
                    .and_then(|info| info.needs_pin_sent)
                    .unwrap_or(false);
                needs_passphrase_sent = info
                    .as_ref()
                    .and_then(|info| info.needs_passphrase_sent)
                    .unwrap_or(false);
                if needs_pin_sent {
                    #[cfg(feature = "keepkey")]
                    if device.device_type() == DeviceType::KeepKey {
                        error = Some(KEEPKEY_LOCKED.to_owned());
                    }
                    #[cfg(feature = "trezor")]
                    if device.device_type() == DeviceType::Trezor {
                        error = Some(bhwi::trezor::TrezorError::LOCKED.to_owned());
                    }
                    code = Some(HwiErrorCode::DeviceNotReady.code());
                } else if error.is_none() {
                    if needs_passphrase_sent && manager.selector.passphrase.is_none() {
                        if device.device_type() == DeviceType::KeepKey {
                            error = Some(KEEPKEY_PASSPHRASE_REQUIRED.to_owned());
                            code = Some(HwiErrorCode::DeviceNotReady.code());
                        } else {
                            warnings.push(vec![EMPTY_PASSPHRASE_WARNING.to_owned()]);
                        }
                    }
                    if error.is_none()
                        && info.as_ref().and_then(|info| info.initialized) == Some(false)
                    {
                        error = Some("Not initialized".to_owned());
                        code = Some(HwiErrorCode::DeviceNotInitialized.code());
                    }
                    if error.is_none() {
                        match device.fingerprint().await {
                            Ok(device_fingerprint) => {
                                fingerprint = Some(device_fingerprint);
                                // Deriving it required the passphrase, so it has been sent.
                                needs_passphrase_sent = false;
                            }
                            Err(err)
                                if is_uninitialized_bitbox_error(device.device_type(), &err) =>
                            {
                                error = Some("Not initialized".to_owned());
                                code = Some(HwiErrorCode::DeviceNotInitialized.code());
                            }
                            Err(err) => {
                                let classified = classify_device_error(&err);
                                error = Some(classified.error);
                                code = Some(classified.code);
                            }
                        }
                    }
                }
            }
            Err(err) if is_uninitialized_bitbox_error(device.device_type(), &err) => {
                error = Some("Not initialized".to_owned());
                code = Some(HwiErrorCode::DeviceNotInitialized.code());
            }
            Err(err) => {
                let classified = classify_device_error(&err);
                error = Some(classified.error);
                code = Some(classified.code);
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
            needs_pin_sent,
            needs_passphrase_sent,
            warnings,
            error,
            code,
        });
    }
    // Python HWI lists unopenable devices with an error rather than omitting them.
    for skipped in scan.skipped {
        response.push(HwiEnumeratedDevice {
            device_type: skipped.device_type.to_string(),
            model: skipped.model,
            path: skipped.path,
            label: None,
            fingerprint: None,
            needs_pin_sent: false,
            needs_passphrase_sent: false,
            warnings: Vec::new(),
            error: Some(skipped.error),
            code: Some(HwiErrorCode::DeviceConnectionError.code()),
        });
    }
    HwiResponse::Enumerate(response)
}

#[cfg(target_os = "linux")]
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
    selector: HwiSelector,
    action: HwiUnsupportedDeviceAction,
) -> HwiResponse {
    let (_manager, device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
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
    selector: HwiSelector,
    interactive: bool,
    label: String,
    backup_passphrase: String,
) -> HwiResponse {
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    if !interactive {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "setup requires interactive mode",
        ));
    }
    if matches!(
        device.device_type(),
        DeviceType::KeepKey | DeviceType::Trezor
    ) && device.info().await.ok().and_then(|info| info.initialized) == Some(true)
    {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceAlreadyInitialized,
            "Device is already initialized. Use wipe first and try again",
        ));
    }
    if !matches!(
        device.device_type(),
        DeviceType::BitBox02 | DeviceType::KeepKey | DeviceType::Trezor
    ) {
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
    if device.device_type() == DeviceType::BitBox02 && !backup_passphrase.is_empty() {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "Passphrase not needed when setting up a BitBox02.",
        ));
    }
    if device.device_type() == DeviceType::BitBox02
        && device.info().await.ok().and_then(|info| info.initialized) == Some(true)
    {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "The BitBox02 must be wiped before setup.",
        ));
    }

    let context = match device.device_type() {
        #[cfg(feature = "keepkey")]
        DeviceType::KeepKey => keepkey_setup_context(),
        #[cfg(feature = "trezor")]
        DeviceType::Trezor => trezor_setup_context(),
        #[cfg(feature = "bitbox")]
        DeviceType::BitBox02 => match bitbox_setup_context(device.is_emulated()) {
            Ok(context) => context,
            Err(err) => {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::DeviceFailure,
                    err.to_string(),
                ));
            }
        },
        #[allow(unreachable_patterns)]
        device_type => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::UnsupportedCommand,
                format!("{device_type} support is not compiled into this build"),
            ));
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
        Err(err) => HwiResponse::Error(classify_device_error(&err)),
    }
}

async fn wipe_device(selector: HwiSelector) -> HwiResponse {
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    if !matches!(
        device.device_type(),
        DeviceType::BitBox02 | DeviceType::KeepKey | DeviceType::Trezor
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
        Err(err) => HwiResponse::Error(classify_device_error(&err)),
    }
}

async fn restore_device(
    selector: HwiSelector,
    interactive: bool,
    word_count: i32,
    label: String,
) -> HwiResponse {
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    if !interactive {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "restore requires interactive mode",
        ));
    }
    if matches!(
        device.device_type(),
        DeviceType::KeepKey | DeviceType::Trezor
    ) && device.info().await.ok().and_then(|info| info.initialized) == Some(true)
    {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::DeviceFailure,
            "Device already initialized. Call device.wipe() and try again.",
        ));
    }
    if !matches!(
        device.device_type(),
        DeviceType::BitBox02 | DeviceType::KeepKey | DeviceType::Trezor
    ) {
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
    let context = match device.device_type() {
        #[cfg(feature = "bitbox")]
        DeviceType::BitBox02 => {
            if device.info().await.ok().and_then(|info| info.initialized) == Some(true) {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::UnsupportedCommand,
                    "The BitBox02 must be wiped before setup.",
                ));
            }
            match bitbox_restore_context() {
                Ok(context) => Some(context),
                Err(err) => {
                    return HwiResponse::Error(HwiError::new(
                        HwiErrorCode::DeviceFailure,
                        err.to_string(),
                    ));
                }
            }
        }
        #[cfg(feature = "keepkey")]
        DeviceType::KeepKey => match keepkey_restore_context() {
            Ok(context) => Some(context),
            Err(err) => {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::DeviceFailure,
                    err.to_string(),
                ));
            }
        },
        #[cfg(feature = "trezor")]
        DeviceType::Trezor => match trezor_restore_context() {
            Ok(context) => Some(context),
            Err(err) => {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::DeviceFailure,
                    err.to_string(),
                ));
            }
        },
        #[allow(unreachable_patterns)]
        device_type => {
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::UnsupportedCommand,
                format!("{device_type} support is not compiled into this build"),
            ));
        }
    };
    match device
        .device()
        .restore_device(RestoreOptions { label, word_count }, context)
        .await
    {
        Ok(success) => HwiResponse::Success(HwiSuccessResponse { success }),
        Err(err) => HwiResponse::Error(classify_device_error(&err)),
    }
}

async fn toggle_passphrase_device(selector: HwiSelector) -> HwiResponse {
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };
    let needs_pin_sent = device.device_type() == DeviceType::KeepKey
        && device
            .info()
            .await
            .ok()
            .and_then(|info| info.needs_pin_sent)
            == Some(true);

    if !matches!(
        device.device_type(),
        DeviceType::BitBox02 | DeviceType::KeepKey | DeviceType::Trezor
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
        Ok(success) => {
            if success && needs_pin_sent {
                eprintln!("Confirm the action by entering your PIN");
                eprintln!("{SEND_PIN_INSTRUCTION}");
                eprintln!("{PIN_MATRIX_DESCRIPTION}");
            }
            HwiResponse::Success(HwiSuccessResponse { success })
        }
        Err(err) => HwiResponse::Error(classify_device_error(&err)),
    }
}

pub const PIN_MATRIX_DESCRIPTION: &str =
    "Use the numeric keypad to describe number positions. The layout is:
    7 8 9
    4 5 6
    1 2 3";
pub const SEND_PIN_INSTRUCTION: &str = "Use 'sendpin' to provide the number positions for the PIN as displayed on your device's screen";

async fn device_for_pin_command(
    selector: HwiSelector,
    action: HwiUnsupportedDeviceAction,
    contact_device: bool,
) -> Result<crate::Device, HwiError> {
    if selector.device_type.is_none() && selector.fingerprint.is_none() {
        return Err(HwiError::new(
            HwiErrorCode::NoDeviceType,
            "You must specify a device type or fingerprint for all commands except enumerate",
        ));
    }
    // Reading a fingerprint means unlocking first, which is what the PIN is for.
    if !contact_device && selector.fingerprint.is_some() {
        return Err(HwiError::new(
            HwiErrorCode::BadArgument,
            "A locked device cannot be matched by fingerprint; use --device-type or --device-path",
        ));
    }

    let manager = hwi_device_manager(&selector)?;
    let found = if contact_device {
        manager.get_device_with_fingerprint().await
    } else {
        manager.get_device_without_contacting().await
    };
    let device = match found {
        Ok(Some(device)) => device,
        Ok(None) => {
            return Err(HwiError::new(
                HwiErrorCode::DeviceConnectionError,
                "Could not find device with specified fingerprint or type",
            ));
        }
        Err(err) => {
            return Err(classify_device_error(&err));
        }
    };

    if !matches!(
        device.device_type(),
        DeviceType::KeepKey | DeviceType::Trezor
    ) {
        return Err(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            hwi_unavailable_action_message(device.device_type(), &action),
        ));
    }
    Ok(device)
}

fn locked_device_error(message: &str) -> Option<HwiError> {
    #[cfg(feature = "trezor")]
    if message.contains(bhwi::trezor::TrezorError::LOCKED) {
        return Some(HwiError::new(
            HwiErrorCode::DeviceNotReady,
            bhwi::trezor::TrezorError::LOCKED,
        ));
    }
    #[cfg(feature = "keepkey")]
    if message.contains(KEEPKEY_LOCKED) {
        return Some(HwiError::new(HwiErrorCode::DeviceNotReady, KEEPKEY_LOCKED));
    }
    let _ = message;
    None
}

/// A device waiting for its PIN reports being locked rather than failing to connect.
fn device_error(err: impl std::fmt::Display) -> HwiError {
    let message = err.to_string();
    locked_device_error(&message)
        .unwrap_or_else(|| HwiError::new(HwiErrorCode::DeviceConnectionError, message))
}

/// Reports the bare device message rather than the wrapped transport error.
fn pin_error(err: &(dyn std::error::Error + 'static)) -> HwiError {
    let message = err.to_string();
    #[cfg(feature = "trezor")]
    for known in [
        bhwi::trezor::TrezorError::NO_PIN_NEEDED,
        bhwi::trezor::TrezorError::PIN_ALREADY_SENT,
    ] {
        if message.contains(known) {
            return HwiError::new(HwiErrorCode::DeviceAlreadyUnlocked, known);
        }
    }
    if let Some(bhwi::common::Error::Rpc(7, detail)) = common_device_error(err) {
        return HwiError::new(
            HwiErrorCode::BadArgument,
            detail.as_deref().unwrap_or("Invalid PIN"),
        );
    }
    HwiError::new(HwiErrorCode::DeviceConnectionError, message)
}

fn send_pin_error_response(err: &(dyn std::error::Error + 'static)) -> HwiResponse {
    let mut source = Some(err);
    while let Some(current) = source {
        #[cfg(feature = "trezor")]
        let action_cancelled = matches!(
            current.downcast_ref::<bhwi::trezor::TrezorError>(),
            Some(bhwi::trezor::TrezorError::ActionCancelled)
        );
        #[cfg(not(feature = "trezor"))]
        let action_cancelled = false;
        // The common KeepKey adapter converts the same protocol error before
        // the async HWI boundary sees it.
        let converted_action_cancelled = matches!(
            current.downcast_ref::<bhwi::common::Error>(),
            Some(bhwi::common::Error::AuthenticationRefused)
        );
        if action_cancelled || converted_action_cancelled {
            return HwiResponse::Success(HwiSuccessResponse { success: false });
        }
        source = current.source();
    }
    HwiResponse::Error(pin_error(err))
}

async fn prompt_pin_device(selector: HwiSelector) -> HwiResponse {
    let mut device =
        match device_for_pin_command(selector, HwiUnsupportedDeviceAction::PromptPin, true).await {
            Ok(device) => device,
            Err(error) => return HwiResponse::Error(error),
        };

    eprintln!("{SEND_PIN_INSTRUCTION}");
    eprintln!("{PIN_MATRIX_DESCRIPTION}");

    match device.device().prompt_pin().await {
        Ok(success) => HwiResponse::Success(HwiSuccessResponse { success }),
        Err(err) => HwiResponse::Error(pin_error(&err)),
    }
}

#[cfg(not(any(feature = "trezor", feature = "keepkey")))]
async fn send_pin_device(_selector: HwiSelector, _pin: String) -> HwiResponse {
    HwiResponse::Error(HwiError::new(
        HwiErrorCode::UnsupportedCommand,
        "no host-PIN device support is compiled into this build",
    ))
}

#[cfg(any(feature = "trezor", feature = "keepkey"))]
async fn send_pin_device(selector: HwiSelector, pin: String) -> HwiResponse {
    let mut device = match device_for_pin_command(
        selector,
        HwiUnsupportedDeviceAction::SendPin { pin: String::new() },
        false,
    )
    .await
    {
        Ok(device) => device,
        Err(error) => return HwiResponse::Error(error),
    };

    let context = match device.device_type() {
        #[cfg(feature = "keepkey")]
        DeviceType::KeepKey => bhwi_async::management::keepkey_pin_context_from_positions(pin),
        #[cfg(feature = "trezor")]
        DeviceType::Trezor => bhwi_async::management::trezor_pin_context_from_positions(pin),
        #[allow(unreachable_patterns)]
        device_type => {
            let _ = pin;
            return HwiResponse::Error(HwiError::new(
                HwiErrorCode::UnsupportedCommand,
                format!("{device_type} support is not compiled into this build"),
            ));
        }
    };
    let context = match context {
        Ok(context) => context,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::BadArgument, err.to_string()));
        }
    };
    match device.device().send_pin(Some(context)).await {
        Ok(success) => HwiResponse::Success(HwiSuccessResponse { success }),
        Err(err) => send_pin_error_response(&err),
    }
}

async fn backup_device(
    selector: HwiSelector,
    label: String,
    backup_passphrase: String,
) -> HwiResponse {
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
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
        DeviceType::KeepKey | DeviceType::Ledger | DeviceType::Jade | DeviceType::Trezor => {
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
        Err(err) => HwiResponse::Error(classify_device_error(&err)),
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
    selector: HwiSelector,
    addr_type: HwiAddressType,
    account: u32,
) -> HwiResponse {
    let path = match master_xpub_path(addr_type, selector.network, account) {
        Ok(path) => path,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::BadArgument, err.to_string()));
        }
    };
    get_xpub(selector, format!("m/{path}"), false).await
}

async fn sign_tx(selector: HwiSelector, psbt: String) -> HwiResponse {
    let network = selector.network;
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    // Upstream parses the PSBT only once a client exists, then reports an
    // invalid transaction rather than a generic bad argument.
    let parsed = match Psbt::from_str(psbt.trim()) {
        Ok(psbt) => psbt,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::InvalidTx, err.to_string()));
        }
    };

    let original = parsed.to_string();
    #[cfg(feature = "ledger")]
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
                return HwiResponse::Error(classify_device_error_for(DeviceType::Ledger, &err));
            }
            Err(err @ (LedgerSigningError::MissingHmac | LedgerSigningError::HmacLength(_))) => {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::DeviceConnectionError,
                    err.to_string(),
                ));
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
                    return HwiResponse::Error(classify_device_error_for(DeviceType::Ledger, &err));
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

    let device_type = device.device_type();
    match device.device().sign_tx(parsed, None).await {
        Ok(signed_psbt) => {
            let signed = signed_psbt.to_string();
            HwiResponse::SignTx(HwiSignTxResponse {
                signed: signed != original,
                psbt: signed,
            })
        }
        Err(err) => HwiResponse::Error(classify_device_error_for(device_type, &err)),
    }
}

async fn sign_message(selector: HwiSelector, message: String, path: String) -> HwiResponse {
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    // Argument validation happens after device lookup, like upstream.
    let path = match DerivationPath::from_str(&path) {
        Ok(path) => path,
        Err(err) => {
            return HwiResponse::Error(HwiError::new(HwiErrorCode::BadArgument, err.to_string()));
        }
    };

    let device_type = device.device_type();
    let approval = coldcard_emulator_approval(
        coldcard_emulator_path(&device),
        coldcard_emulator_action(ColdcardApproval::Once),
    );
    let (signature, approval) = tokio::join!(
        device.device().sign_message(message.as_bytes(), path),
        approval
    );
    if let Err(err) = approval {
        return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceConnectionError, err));
    }
    match signature {
        Ok((header, signature)) => HwiResponse::SignMessage(HwiSignMessageResponse {
            signature: BASE64_STANDARD.encode(message_signature(device_type, header, &signature)),
        }),
        Err(err) => HwiResponse::Error(classify_device_error_for(device_type, &err)),
    }
}

async fn display_address(selector: HwiSelector, request: HwiDisplayAddressRequest) -> HwiResponse {
    if matches!(
        &request,
        HwiDisplayAddressRequest::Path {
            addr_type: HwiAddressType::Tap,
            ..
        }
    ) && selector.device_type.as_deref().is_some_and(|raw| {
        raw.eq_ignore_ascii_case("keepkey") || raw.eq_ignore_ascii_case("keepkey_simulator")
    }) {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "This device does not support displaying Taproot addresses",
        ));
    }

    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    let display = match request {
        HwiDisplayAddressRequest::Path { path, addr_type } => {
            let path = match DerivationPath::from_str(&path) {
                Ok(path) => path,
                Err(err) => {
                    return HwiResponse::Error(HwiError::new(
                        HwiErrorCode::BadArgument,
                        err.to_string(),
                    ));
                }
            };
            if device.device_type() == DeviceType::Coldcard && addr_type == HwiAddressType::Tap {
                return HwiResponse::Error(HwiError::new(
                    HwiErrorCode::UnsupportedCommand,
                    "Coldcard does not support displaying Taproot addresses yet",
                ));
            }
            if device.device_type() == DeviceType::Jade && addr_type == HwiAddressType::Tap {
                return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceFailure, "tap"));
            }
            Ok((
                DisplayAddress::ByPath {
                    path,
                    display: true,
                    address_format: Some(address_type_for(addr_type)),
                },
                None,
            ))
        }
        HwiDisplayAddressRequest::Descriptor { descriptor } => {
            match singlesig_display_address_from_descriptor(&mut device, &descriptor)
                .await
                .map_err(display_address_error)
            {
                Ok(address) => Ok((address, None)),
                Err(single_sig_error) => {
                    if device.device_type() == DeviceType::Ledger {
                        #[cfg(not(feature = "ledger"))]
                        {
                            return HwiResponse::Error(single_sig_error);
                        }
                        #[cfg(feature = "ledger")]
                        if multisig_display_address_from_descriptor(&descriptor).is_err() {
                            return HwiResponse::Error(single_sig_error);
                        }
                        #[cfg(feature = "ledger")]
                        match ledger_multisig_display_address(&mut device, &descriptor).await {
                            Ok((address, context)) => Ok((address, Some(context))),
                            Err(LedgerSigningError::BadArgument(err)) => {
                                return HwiResponse::Error(HwiError::new(
                                    HwiErrorCode::BadArgument,
                                    err,
                                ));
                            }
                            Err(LedgerSigningError::Device(err)) => {
                                return HwiResponse::Error(classify_device_error_for(
                                    DeviceType::Ledger,
                                    &err,
                                ));
                            }
                            Err(err) => {
                                return HwiResponse::Error(HwiError::new(
                                    HwiErrorCode::DeviceConnectionError,
                                    err.to_string(),
                                ));
                            }
                        }
                    } else if matches!(
                        device.device_type(),
                        DeviceType::Coldcard
                            | DeviceType::Jade
                            | DeviceType::KeepKey
                            | DeviceType::Trezor
                    ) {
                        match multisig_display_address_from_descriptor(&descriptor) {
                            Ok(address) => Ok((DisplayAddress::ByMultisig(address), None)),
                            Err(_) => return HwiResponse::Error(single_sig_error),
                        }
                    } else {
                        return HwiResponse::Error(single_sig_error);
                    }
                }
            }
        }
    };

    let (display, context) = match display {
        Ok(display) => display,
        Err(error) => return HwiResponse::Error(error),
    };

    let approval = coldcard_emulator_approval(
        coldcard_emulator_path(&device),
        coldcard_emulator_action(ColdcardApproval::Once),
    );
    let (address, approval) =
        tokio::join!(device.device().display_address(display, context), approval);
    if let Err(err) = approval {
        return HwiResponse::Error(HwiError::new(HwiErrorCode::DeviceConnectionError, err));
    }
    match address {
        Ok(address) => HwiResponse::DisplayAddress(HwiDisplayAddressResponse { address }),
        Err(err) => HwiResponse::Error(classify_device_error_for(device.device_type(), &err)),
    }
}

#[derive(Clone, Copy)]
enum ColdcardApproval {
    Once,
    Backup,
    Refuse,
}

/// Undocumented test hook: `HWI_COLDCARD_EMULATOR_REFUSE` swaps the built-in
/// emulator auto-approval for a refusal so cancel parity cases can exercise
/// the device's `refu` path through the CLI.
fn coldcard_emulator_action(default: ColdcardApproval) -> ColdcardApproval {
    if std::env::var_os("HWI_COLDCARD_EMULATOR_REFUSE").is_some() {
        ColdcardApproval::Refuse
    } else {
        default
    }
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
    let key = match approval {
        ColdcardApproval::Refuse => b'x',
        ColdcardApproval::Once | ColdcardApproval::Backup => b'y',
    };
    send_coldcard_simulator_keypress(&socket, key).await?;
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

async fn get_xpub(selector: HwiSelector, path: String, expert: bool) -> HwiResponse {
    let (_manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    // Argument validation happens after device lookup, like upstream. The
    // BitBox backend's get_pubkey_at_path is undecorated upstream, so its
    // invalid-path failure surfaces as -13 instead of -7.
    let path = match DerivationPath::from_str(&path) {
        Ok(path) => path,
        Err(err) => {
            let code = if device.device_type() == DeviceType::BitBox02 {
                HwiErrorCode::DeviceFailure
            } else {
                HwiErrorCode::BadArgument
            };
            return HwiResponse::Error(HwiError::new(code, err.to_string()));
        }
    };

    match device.device().get_extended_pubkey(path, false).await {
        Ok(xpub) => HwiResponse::GetXpub(get_xpub_response(xpub, expert)),
        Err(err) => HwiResponse::Error(classify_anyhow_device_error(&anyhow::Error::new(err))),
    }
}

async fn get_descriptors(selector: HwiSelector, account: u32) -> HwiResponse {
    let (manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    let fingerprint = match device.fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(err) => {
            return HwiResponse::Error(classify_device_error(&err));
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
            let descriptor = match get_descriptor(device.device().as_mut(), options).await {
                Ok(descriptor) => descriptor,
                Err(err) => {
                    return HwiResponse::Error(classify_device_error(&err));
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

async fn get_keypool(selector: HwiSelector, request: HwiGetKeypoolRequest) -> HwiResponse {
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
    if !request.all
        && request.addr_type == HwiAddressType::Tap
        && selector.device_type.as_deref().is_some_and(|raw| {
            raw.eq_ignore_ascii_case("keepkey") || raw.eq_ignore_ascii_case("keepkey_simulator")
        })
    {
        return HwiResponse::Error(HwiError::new(
            HwiErrorCode::UnsupportedCommand,
            "Device does not support Taproot",
        ));
    }

    let (manager, mut device) = match find_hwi_device(&selector).await {
        Ok(found) => found,
        Err(err) => return HwiResponse::Error(err),
    };

    let fingerprint = match device.fingerprint().await {
        Ok(fingerprint) => fingerprint,
        Err(err) => {
            return HwiResponse::Error(classify_device_error(&err));
        }
    };
    let device_type = device.device_type();
    let model = device.model().to_owned();
    let network = manager.selector.network;
    let addr_types = if request.all {
        hwi_descriptor_addr_types(device_type, &model)
    } else if request.addr_type == HwiAddressType::Tap && !can_sign_taproot(device_type, &model) {
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
            let descriptor = match get_descriptor(device.device().as_mut(), options).await {
                Ok(descriptor) => descriptor,
                Err(err) => {
                    return HwiResponse::Error(classify_device_error(&err));
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

fn display_address_error(err: DisplayAddressError) -> HwiError {
    match err {
        DisplayAddressError::Device(err) => classify_device_error(&err),
        err => HwiError::new(HwiErrorCode::BadArgument, err.to_string()),
    }
}

/// Maps typed device errors from the async stack onto Python HWI's error
/// codes. Walks the `source()` chain for a `bhwi::common::Error` so cancels
/// and argument refusals stop flattening to `-3`; unclassified failures keep
/// the full message with `-3`.
fn common_device_error<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a bhwi::common::Error> {
    let mut source = Some(err);
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<bhwi::common::Error>() {
            return Some(error);
        }
        source = current.source();
    }
    None
}

fn classify_anyhow_device_error(err: &anyhow::Error) -> HwiError {
    let source: &(dyn std::error::Error + 'static) = err.as_ref();
    classify_device_error(source)
}

fn classify_device_error(err: &(dyn std::error::Error + 'static)) -> HwiError {
    let mut source = Some(err);
    while let Some(current) = source {
        if let Some(error) = locked_device_error(&current.to_string()) {
            return error;
        }
        source = current.source();
    }

    if let Some(error) = common_device_error(err) {
        use bhwi::common::Error as CommonError;
        if let CommonError::InvalidInput(message) = error
            && message == "Passphrase too long"
        {
            return HwiError::new(HwiErrorCode::BadArgument, message);
        }
        let code = match error {
            CommonError::AuthenticationRefused | CommonError::UserCancelled => {
                HwiErrorCode::ActionCanceled
            }
            CommonError::MissingCommandInfo(_) | CommonError::UnsupportedDisplayAddress(_) => {
                HwiErrorCode::UnsupportedCommand
            }
            // Device-refused input keeps upstream's bad-argument class,
            // e.g. `Coldcard Error: ...` for an unknown multisig wallet.
            CommonError::InvalidInput(_) | CommonError::Device(_) => HwiErrorCode::BadArgument,
            _ => return device_error(err),
        };
        return HwiError::new(code, error.to_string());
    }
    device_error(err)
}

/// Device-aware classification. Upstream's Ledger backend uses the new
/// `ledger_bitcoin` client whose `DenyError` bypasses the `ledger_exception`
/// cancel mapping, so Ledger cancellations surface as `-13` there instead of
/// `-14`. Mirror that for parity; every other device keeps `-14`.
fn classify_device_error_for(
    device_type: DeviceType,
    err: &(dyn std::error::Error + 'static),
) -> HwiError {
    let classified = classify_device_error(err);
    if device_type == DeviceType::Ledger && classified.code == HwiErrorCode::ActionCanceled.code() {
        return HwiError::new(HwiErrorCode::DeviceFailure, classified.error);
    }
    classified
}

fn hwi_descriptor_addr_types(device_type: DeviceType, model: &str) -> Vec<HwiAddressType> {
    let mut types = vec![
        HwiAddressType::Legacy,
        HwiAddressType::Wit,
        HwiAddressType::ShWit,
    ];
    if can_sign_taproot(device_type, model) {
        types.push(HwiAddressType::Tap);
    }
    types
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

fn is_uninitialized_bitbox_error(device_type: DeviceType, error: &impl std::fmt::Display) -> bool {
    device_type == DeviceType::BitBox02
        && error
            .to_string()
            .ends_with("can't call this endpoint: wrong state")
}

fn label_for(device_type: DeviceType, label: Option<String>) -> Option<Option<String>> {
    match device_type {
        DeviceType::Coldcard | DeviceType::KeepKey | DeviceType::Ledger | DeviceType::Trezor => {
            Some(label)
        }
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
        (DeviceType::KeepKey, true) => "keepkey_simulator".to_owned(),
        (DeviceType::KeepKey, false) => "keepkey".to_owned(),
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
            "The Trezor does not support creating a backup via software"
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
        (DeviceType::KeepKey, HwiUnsupportedDeviceAction::Setup { .. }) => {
            "KeepKey setup is unavailable"
        }
        (DeviceType::KeepKey, HwiUnsupportedDeviceAction::Wipe) => "KeepKey wipe is unavailable",
        (DeviceType::KeepKey, HwiUnsupportedDeviceAction::Restore { .. }) => {
            "KeepKey restore is unavailable"
        }
        (DeviceType::KeepKey, HwiUnsupportedDeviceAction::Backup { .. }) => {
            "The Keepkey does not support creating a backup via software"
        }
        (DeviceType::KeepKey, HwiUnsupportedDeviceAction::PromptPin) => {
            "KeepKey PIN entry is unavailable"
        }
        (DeviceType::KeepKey, HwiUnsupportedDeviceAction::SendPin { .. }) => {
            "KeepKey PIN entry is unavailable"
        }
        (DeviceType::KeepKey, HwiUnsupportedDeviceAction::TogglePassphrase) => {
            "KeepKey passphrase toggling is unavailable"
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
    let unknown = || HwiError::new(HwiErrorCode::UnknownDevice, "Unknown device type specified");
    let family = value.split('_').next().unwrap_or(value);
    if family.eq_ignore_ascii_case("keepkey")
        && !value.eq_ignore_ascii_case("keepkey")
        && !value.eq_ignore_ascii_case("keepkey_simulator")
    {
        return Err(unknown());
    }
    [
        ("bitbox02", DeviceType::BitBox02),
        ("coldcard", DeviceType::Coldcard),
        ("jade", DeviceType::Jade),
        ("ledger", DeviceType::Ledger),
        ("keepkey", DeviceType::KeepKey),
        ("trezor", DeviceType::Trezor),
    ]
    .into_iter()
    .find_map(|(name, device_type)| family.eq_ignore_ascii_case(name).then_some(device_type))
    .ok_or_else(unknown)
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
                Some(DeviceType::KeepKey),
                Some("127.0.0.1:11044" | "udp:127.0.0.1:11044")
            )
            | (
                Some(DeviceType::Trezor),
                Some("127.0.0.1:21324" | "udp:127.0.0.1:21324")
            )
    )
}

fn read_stdin_password(args: &mut HwiCli) -> HwiResult<()> {
    if args.stdinpass {
        let password = match rpassword::prompt_password("Enter your device password: ") {
            Ok(password) => password,
            Err(_) => {
                eprintln!("Warning: Password input may be echoed.");
                eprint!("Enter your device password: ");
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|err| HwiError::new(HwiErrorCode::BadArgument, err.to_string()))?;
                line.trim_end_matches(['\r', '\n']).to_owned()
            }
        };
        args.password = Some(password);
    }
    Ok(())
}

fn request_from_cli(args: HwiCli) -> HwiResult<HwiRequest> {
    let _accepted_python_hwi_globals = (args.debug, args.stdin, args.interactive, args.stdinpass);
    let passphrase = args.password.map(HostPassphrase::new);
    let expert = args.expert;
    // The raw device type stays unparsed until device lookup; upstream only
    // rejects an unknown type once `get_client` is reached.
    let device_type = args.device_type;
    let mut device_path = args.device_path;
    #[cfg(feature = "keepkey")]
    if matches!(&args.command, HwiCliCommand::Enumerate)
        && device_path.is_none()
        && device_type
            .as_deref()
            .is_some_and(|raw| raw.eq_ignore_ascii_case("keepkey_simulator"))
    {
        device_path = Some(DEFAULT_KEEPKEY_EMULATOR.to_owned());
    }
    let include_emulators = args.emulators
        || is_known_emulator_path(
            device_type
                .as_deref()
                .and_then(|raw| parse_device_type(raw).ok()),
            device_path.as_deref(),
        );
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
        HwiCliCommand::Promptpin => HwiCommand::PromptPin,
        HwiCliCommand::Sendpin { pin } => HwiCommand::SendPin { pin },
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
        selector: HwiSelector {
            network,
            fingerprint: args.fingerprint,
            device_type,
            device_path,
            include_emulators,
            passphrase,
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
    use chrono::{FixedOffset, TimeZone};

    #[test]
    fn display_address_errors_keep_python_hwi_codes() {
        let parse = display_address_error(DisplayAddressError::UnsupportedDescriptor(
            "wsh(x)".to_owned(),
        ));
        assert_eq!(parse.code, HwiErrorCode::BadArgument.code());
        assert_eq!(parse.error, "Unsupported displayaddress descriptor: wsh(x)");

        let device = display_address_error(DisplayAddressError::Device(
            bhwi_async::HWIDeviceError::new(std::io::Error::other("boom")),
        ));
        assert_eq!(device.code, HwiErrorCode::DeviceConnectionError.code());
        assert_eq!(device.error, "boom");
    }

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
    fn keepkey_selector_accepts_models_and_both_emulator_path_forms() {
        for model in ["keepkey", "keepkey_simulator"] {
            assert_eq!(parse_device_type(model).unwrap(), DeviceType::KeepKey);
        }
        assert!(hwi_selector_matches_device(
            Some("keepkey"),
            DeviceType::KeepKey,
            "keepkey",
            false,
        ));
        assert!(hwi_selector_matches_device(
            Some("keepkey"),
            DeviceType::KeepKey,
            "keepkey_simulator",
            true,
        ));
        for path in ["127.0.0.1:11044", "udp:127.0.0.1:11044"] {
            let request = parse_args([
                "hwi",
                "--device-type",
                "keepkey_simulator",
                "--device-path",
                path,
                "enumerate",
            ])
            .unwrap();
            assert_eq!(
                request.selector.device_type.as_deref(),
                Some("keepkey_simulator")
            );
            assert_eq!(request.selector.device_path.as_deref(), Some(path));
            assert!(request.selector.include_emulators);
        }
        assert!(!is_known_emulator_path(
            Some(DeviceType::KeepKey),
            Some("tcp:127.0.0.1:11044"),
        ));
    }

    #[test]
    fn keepkey_selector_rejects_unknown_model_suffix() {
        let raw = "keepkey_not_a_model";
        let error = parse_device_type(raw).expect_err("unknown KeepKey model");
        assert_eq!(error.code, HwiErrorCode::UnknownDevice.code());
        assert_eq!(error.error, "Unknown device type specified");

        // Enumerate drops unknown filters, while command lookup rejects them.
        let enumerate_filter = parse_device_type(raw).ok().map(|_| raw);
        assert!(enumerate_filter.is_none());
        assert!(hwi_selector_matches_device(
            enumerate_filter,
            DeviceType::Trezor,
            "trezor_t",
            false,
        ));

        let request = parse_args(["hwi", "-t", raw, "getxpub", "m/44h/1h/0h"]).unwrap();
        let response = futures::executor::block_on(process_request(request));
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::DeviceConnectionError.code());
        assert_eq!(
            error.error,
            "Could not find device with specified fingerprint or type"
        );

        let request = parse_args([
            "hwi",
            "-t",
            raw,
            "-d",
            "/dev/null",
            "getxpub",
            "m/44h/1h/0h",
        ])
        .unwrap();
        let response = futures::executor::block_on(process_request(request));
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::UnknownDevice.code());
        assert_eq!(error.error, "Unknown device type specified");
    }

    #[test]
    #[cfg(feature = "keepkey")]
    fn keepkey_selector_pathless_simulator_matches_only_emulated_model() {
        let request =
            parse_args(["hwi", "--device-type", "keepkey_simulator", "enumerate"]).unwrap();
        assert_eq!(
            request.selector.device_path.as_deref(),
            Some(DEFAULT_KEEPKEY_EMULATOR)
        );
        assert!(request.selector.include_emulators);

        let raw = request.selector.device_type.as_deref();
        assert!(hwi_selector_matches_device(
            raw,
            DeviceType::KeepKey,
            "keepkey_simulator",
            true,
        ));
        assert!(!hwi_selector_matches_device(
            raw,
            DeviceType::KeepKey,
            "keepkey",
            false,
        ));
        assert!(!hwi_selector_matches_device(
            raw,
            DeviceType::KeepKey,
            "keepkey",
            true,
        ));
        assert!(!hwi_selector_matches_device(
            raw,
            DeviceType::Trezor,
            "keepkey_simulator",
            true,
        ));
    }

    #[test]
    fn keepkey_simulator_non_enumerate_requires_emulator_flag() {
        let request =
            parse_args(["hwi", "--device-type", "keepkey_simulator", "getmasterxpub"]).unwrap();
        assert_eq!(request.selector.device_path, None);
        assert!(!request.selector.include_emulators);

        let request = parse_args([
            "hwi",
            "--device-type",
            "keepkey_simulator",
            "--emulators",
            "getmasterxpub",
        ])
        .unwrap();
        assert!(request.selector.include_emulators);
    }

    #[test]
    fn keepkey_selector_for_destructive_command_cannot_select_physical_device() {
        let request = parse_args([
            "hwi",
            "--device-type",
            "keepkey_simulator",
            "--device-path",
            "hid:physical-keepkey",
            "wipe",
        ])
        .unwrap();
        assert_eq!(request.command, HwiCommand::Wipe);
        assert!(!request.selector.include_emulators);
        assert!(!hwi_selector_matches_device(
            request.selector.device_type.as_deref(),
            DeviceType::KeepKey,
            "keepkey",
            false,
        ));
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
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

        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
        assert!(request.selector.include_emulators);
        assert_eq!(
            request.command,
            HwiCommand::GetXpub {
                path: "m/44h/1h/0h/0/3".to_owned(),
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
        assert_eq!(
            request.command,
            HwiCommand::SignMessage {
                message: "hello".to_owned(),
                path: "m/44'/1'/0'/0".to_owned(),
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
        assert_eq!(
            request.command,
            HwiCommand::DisplayAddress(HwiDisplayAddressRequest::Path {
                path: "m/49h/1h/0h/0/0".to_owned(),
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
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
    fn unknown_device_type_without_path_reports_no_device_found() {
        // Upstream find_device never matches an unknown type: -3, not -4.
        let request = parse_args(["hwi", "-t", "nonexistent", "getxpub", "m/44h/1h/0h"])
            .expect("unknown type parses");
        let response = futures::executor::block_on(process_request(request));
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::DeviceConnectionError.code());
        assert_eq!(
            error.error,
            "Could not find device with specified fingerprint or type"
        );
    }

    #[test]
    fn unknown_device_type_with_path_reports_unknown_device() {
        // Upstream get_client raises UnknownDeviceError (-4) when -d is given.
        let request = parse_args([
            "hwi",
            "-t",
            "nonexistent",
            "-d",
            "/dev/null",
            "getxpub",
            "m/44h/1h/0h",
        ])
        .expect("unknown type parses");
        let response = futures::executor::block_on(process_request(request));
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::UnknownDevice.code());
        assert_eq!(error.error, "Unknown device type specified");
    }

    #[tokio::test]
    async fn keepkey_taproot_display_is_rejected_before_lookup_and_path_parsing() {
        let request = parse_args([
            "hwi",
            "-t",
            "keepkey",
            "displayaddress",
            "--path",
            "not_a_derivation_path",
            "--addr-type",
            "tap",
        ])
        .unwrap();
        let response = process_request(request).await;
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::UnsupportedCommand.code());
        assert_eq!(
            error.error,
            "This device does not support displaying Taproot addresses"
        );
    }

    #[tokio::test]
    async fn keepkey_taproot_keypool_is_rejected_before_device_lookup() {
        let request = parse_args([
            "hwi",
            "-t",
            "keepkey",
            "getkeypool",
            "0",
            "1",
            "--addr-type",
            "tap",
        ])
        .unwrap();
        let response = process_request(request).await;
        let HwiResponse::Error(error) = response else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::UnsupportedCommand.code());
        assert_eq!(error.error, "Device does not support Taproot");
    }

    #[tokio::test]
    async fn invalid_arguments_without_device_report_no_device_found() {
        // Argument validation is deferred until after device lookup; with no
        // matching device every case collapses to -3 like upstream.
        for args in [
            ["hwi", "-t", "trezor", "signtx", "notapsbt"].as_slice(),
            ["hwi", "-t", "trezor", "getxpub", "not_a_path"].as_slice(),
            ["hwi", "-t", "trezor", "signmessage", "hello", "bad/path"].as_slice(),
            [
                "hwi",
                "-t",
                "trezor",
                "displayaddress",
                "--path",
                "bad/path",
            ]
            .as_slice(),
        ] {
            let request = parse_args(args.iter().copied()).expect("request parses");
            let response = process_request(request).await;
            let HwiResponse::Error(error) = response else {
                panic!("expected HWI error for {args:?}");
            };
            assert_eq!(
                error.code,
                HwiErrorCode::DeviceConnectionError.code(),
                "{args:?}: {}",
                error.error
            );
        }
    }

    #[test]
    fn accepts_bitbox02_device_type() {
        let request =
            parse_args(["hwi", "--device-type", "bitbox02", "enumerate"]).expect("bitbox02 parses");

        assert_eq!(request.selector.device_type.as_deref(), Some("bitbox02"));
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
    fn keepkey_enumerate_model_is_canonical() {
        assert_eq!(
            hwi_enumerate_model(DeviceType::KeepKey, "ignored", false, Some("K1-14AM")),
            "keepkey"
        );
        assert_eq!(
            hwi_enumerate_model(DeviceType::KeepKey, "ignored", true, Some("K1-14AM")),
            "keepkey_simulator"
        );
    }

    #[test]
    fn accepts_trezor_device_type() {
        let request =
            parse_args(["hwi", "--device-type", "trezor", "enumerate"]).expect("trezor parses");

        assert_eq!(request.selector.device_type.as_deref(), Some("trezor"));
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
        assert_eq!(request.selector.device_type.as_deref(), Some("ledger"));
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

        assert_eq!(request.selector.device_type.as_deref(), Some("bitbox02"));
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
        // Device support is decided when the device is found, not while parsing.
        let promptpin =
            parse_args(["hwi", "--device-type", "ledger", "promptpin"]).expect("promptpin request");
        assert_eq!(promptpin.command, HwiCommand::PromptPin);

        let sendpin = parse_args(["hwi", "--device-type", "trezor", "sendpin", "1234"])
            .expect("sendpin request");
        assert_eq!(
            sendpin.command,
            HwiCommand::SendPin {
                pin: "1234".to_owned()
            }
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
    fn numeric_value_parse_failure_is_a_usage_error() {
        let args = ["hwi", "getkeypool", "notanum", "5"];
        let error = HwiCli::try_parse_from(args).expect_err("invalid numeric value");

        assert_eq!(error.kind(), ErrorKind::ValueValidation);
        assert!(!usage_of(&args).usage.is_empty());
        assert_eq!(exit_status(&outcome_of(&args)), 2);
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
        let outcome = CliOutcome::Response(HwiResponse::Error(HwiError::new(
            HwiErrorCode::BadArgument,
            "bad argument",
        )));

        let CliOutcome::Response(HwiResponse::Error(error)) = &outcome else {
            panic!("expected runtime error, got {outcome:?}");
        };
        assert_eq!(error.code, HwiErrorCode::BadArgument.code());
        assert_eq!(exit_status(&outcome), 0);
    }

    #[test]
    fn version_prints_to_stdout_and_exits_zero() {
        let args = ["hwi", "--version"];
        let outcome = outcome_of(&args);
        let CliOutcome::Stdout(text) = &outcome else {
            panic!("expected stdout outcome for {args:?}, got {outcome:?}");
        };
        assert!(!text.is_empty());
        assert_eq!(exit_status(&outcome), 0);
    }

    #[test]
    fn help_yields_json_error_and_help_text_for_top_level_and_subcommand() {
        for args in [
            ["hwi", "--help"].as_slice(),
            ["hwi", "getxpub", "--help"].as_slice(),
        ] {
            let outcome = outcome_of(args);
            let CliOutcome::Help(help) = &outcome else {
                panic!("expected help outcome for {args:?}, got {outcome:?}");
            };
            assert!(!help.is_empty());
            assert_eq!(exit_status(&outcome), 0);
        }

        let json = serde_json::to_string(&HwiError::new(
            HwiErrorCode::HelpText,
            "Help text requested",
        ))
        .expect("serialize help error");
        assert_eq!(json, r#"{"error":"Help text requested","code":-17}"#);
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
    fn keepkey_backup_error_matches_python_hwi() {
        assert_eq!(
            hwi_unavailable_action_message(
                DeviceType::KeepKey,
                &HwiUnsupportedDeviceAction::Backup {
                    label: String::new(),
                    backup_passphrase: String::new(),
                },
            ),
            "The Keepkey does not support creating a backup via software"
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
                warnings: Vec::new(),
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
                warnings: Vec::new(),
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
            warnings: Vec::new(),
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
            warnings: Vec::new(),
            error: None,
            code: None,
        })
        .expect("json");

        assert_eq!(json["model"], "bitbox02_nova_multi");
        assert_eq!(json["path"], "127.0.0.1:15423");
        assert!(json.get("label").is_none());
    }

    #[test]
    fn keepkey_emulator_enumerate_shape_reports_required_passphrase() {
        let json = serde_json::to_value(HwiEnumeratedDevice {
            device_type: DeviceType::KeepKey.to_string(),
            model: hwi_enumerate_model(DeviceType::KeepKey, "keepkey", true, None),
            path: hwi_enumerate_path(DeviceType::KeepKey, "udp:127.0.0.1:11044", true),
            label: label_for(DeviceType::KeepKey, None),
            fingerprint: None,
            needs_pin_sent: false,
            needs_passphrase_sent: true,
            warnings: Vec::new(),
            error: Some(KEEPKEY_PASSPHRASE_REQUIRED.to_owned()),
            code: Some(HwiErrorCode::DeviceNotReady.code()),
        })
        .unwrap();

        assert_eq!(
            json,
            serde_json::json!({
                "type": "keepkey",
                "model": "keepkey_simulator",
                "path": "udp:127.0.0.1:11044",
                "label": null,
                "needs_pin_sent": false,
                "needs_passphrase_sent": true,
                "error": KEEPKEY_PASSPHRASE_REQUIRED,
                "code": -12,
            })
        );
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

    fn wrapped_device_error(error: bhwi::common::Error) -> bhwi_async::HWIDeviceError {
        bhwi_async::HWIDeviceError::new(
            bhwi_async::Error::<std::io::Error, std::io::Error>::Interpreter(error),
        )
    }

    #[test]
    #[cfg(feature = "trezor")]
    fn send_pin_action_cancelled_matches_hwi_false_contract() {
        for error in [
            bhwi_async::HWIDeviceError::new(bhwi::trezor::TrezorError::ActionCancelled),
            wrapped_device_error(bhwi::common::Error::AuthenticationRefused),
        ] {
            assert_eq!(
                serde_json::to_value(send_pin_error_response(&error)).unwrap(),
                serde_json::json!({ "success": false })
            );
        }

        let bad_pin = wrapped_device_error(bhwi::common::Error::Rpc(7, Some("bad pin".to_owned())));
        let HwiResponse::Error(error) = send_pin_error_response(&bad_pin) else {
            panic!("expected HWI error");
        };
        assert_eq!(error.code, HwiErrorCode::BadArgument.code());
        assert_eq!(error.error, "bad pin");
    }

    #[test]
    fn classify_device_error_maps_typed_common_errors() {
        use bhwi::common::Error as CommonError;

        let cancelled = classify_device_error(&wrapped_device_error(CommonError::UserCancelled));
        assert_eq!(cancelled.code, HwiErrorCode::ActionCanceled.code());
        assert_eq!(cancelled.error, "action canceled by the user");

        let refused =
            classify_device_error(&wrapped_device_error(CommonError::AuthenticationRefused));
        assert_eq!(refused.code, HwiErrorCode::ActionCanceled.code());

        let unavailable = classify_device_error(&wrapped_device_error(
            CommonError::MissingCommandInfo("unsupported command"),
        ));
        assert_eq!(unavailable.code, HwiErrorCode::UnsupportedCommand.code());

        let unsupported = classify_device_error(&wrapped_device_error(
            CommonError::UnsupportedDisplayAddress(
                "BitBox does not support this address format".into(),
            ),
        ));
        assert_eq!(unsupported.code, HwiErrorCode::UnsupportedCommand.code());

        let invalid = classify_device_error(&wrapped_device_error(CommonError::InvalidInput(
            "bad argument".into(),
        )));
        assert_eq!(invalid.code, HwiErrorCode::BadArgument.code());

        let device = classify_device_error(&wrapped_device_error(CommonError::Device(
            "Coldcard Error: Unknown multisig wallet".into(),
        )));
        assert_eq!(device.code, HwiErrorCode::BadArgument.code());
        assert_eq!(device.error, "Coldcard Error: Unknown multisig wallet");

        let fallback = classify_device_error(&wrapped_device_error(CommonError::Serialization(
            "boom".into(),
        )));
        assert_eq!(fallback.code, HwiErrorCode::DeviceConnectionError.code());
        assert!(fallback.error.contains("boom"), "{}", fallback.error);
    }

    #[test]
    #[cfg(all(feature = "keepkey", feature = "trezor"))]
    fn keepkey_locked_and_bad_pin_errors_use_python_hwi_codes() {
        let locked = device_error(format!("transport failed: {KEEPKEY_LOCKED}"));
        assert_eq!(locked.code, HwiErrorCode::DeviceNotReady.code());
        assert_eq!(locked.error, KEEPKEY_LOCKED);

        let bad_pin = wrapped_device_error(bhwi::common::Error::Rpc(7, Some("bad pin".to_owned())));
        let bad_pin = pin_error(&bad_pin);
        assert_eq!(bad_pin.code, HwiErrorCode::BadArgument.code());
        assert_eq!(bad_pin.error, "bad pin");

        for message in [
            bhwi::trezor::TrezorError::NO_PIN_NEEDED,
            bhwi::trezor::TrezorError::PIN_ALREADY_SENT,
        ] {
            let error = wrapped_device_error(bhwi::common::Error::DeviceAlreadyUnlocked(message));
            assert_eq!(
                pin_error(&error).code,
                HwiErrorCode::DeviceAlreadyUnlocked.code()
            );
        }
    }

    #[test]
    fn ledger_cancellations_downgrade_to_unknown_error_code() {
        let err = wrapped_device_error(bhwi::common::Error::UserCancelled);
        let ledger = classify_device_error_for(DeviceType::Ledger, &err);
        assert_eq!(ledger.code, HwiErrorCode::DeviceFailure.code());
        let coldcard = classify_device_error_for(DeviceType::Coldcard, &err);
        assert_eq!(coldcard.code, HwiErrorCode::ActionCanceled.code());
    }

    #[test]
    fn classify_anyhow_device_error_walks_the_chain() {
        let err = anyhow::Error::new(wrapped_device_error(bhwi::common::Error::UserCancelled))
            .context("getting master fingerprint");
        let classified = classify_anyhow_device_error(&err);
        assert_eq!(classified.code, HwiErrorCode::ActionCanceled.code());
        assert_eq!(classified.error, "action canceled by the user");
    }

    #[test]
    fn classify_anyhow_device_error_maps_wrapped_missing_command() {
        let err = anyhow::Error::new(wrapped_device_error(
            bhwi::common::Error::MissingCommandInfo("host interaction required"),
        ))
        .context("displaying descriptor address");
        let classified = classify_anyhow_device_error(&err);
        assert_eq!(classified.code, HwiErrorCode::UnsupportedCommand.code());
        assert_eq!(
            classified.error,
            "missing command info: host interaction required"
        );
    }

    #[test]
    fn classify_anyhow_device_error_maps_wrapped_overlong_passphrase() {
        let err = anyhow::Error::new(wrapped_device_error(bhwi::common::Error::InvalidInput(
            "Passphrase too long".to_owned(),
        )))
        .context("getting master fingerprint");
        let classified = classify_anyhow_device_error(&err);
        assert_eq!(classified.code, HwiErrorCode::BadArgument.code());
        assert_eq!(classified.error, "Passphrase too long");
    }

    #[test]
    #[cfg(feature = "keepkey")]
    fn classify_anyhow_device_error_preserves_locked_descriptor_lookup() {
        let err = anyhow::Error::new(std::io::Error::other(KEEPKEY_LOCKED))
            .context("getting descriptor fingerprint");
        let classified = classify_anyhow_device_error(&err);
        assert_eq!(classified.code, HwiErrorCode::DeviceNotReady.code());
        assert_eq!(classified.error, KEEPKEY_LOCKED);
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
        assert_eq!(
            hwi_descriptor_addr_types(DeviceType::KeepKey, "keepkey_simulator"),
            vec![
                HwiAddressType::Legacy,
                HwiAddressType::Wit,
                HwiAddressType::ShWit,
            ]
        );
        assert!(can_sign_taproot(
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

    fn sample_xpub() -> Xpub {
        Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT")
            .expect("sample xpub")
    }
}
