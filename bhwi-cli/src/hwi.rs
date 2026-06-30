use std::{
    ffi::OsString,
    io::{self, BufRead},
    process::ExitCode,
    str::FromStr,
};

use bitcoin::{
    Network, NetworkKind,
    bip32::{DerivationPath, Fingerprint, Xpub},
};
use clap::{Parser, Subcommand, error::ErrorKind};
use serde::{Serialize, Serializer};

use crate::{DeviceManager, DeviceType, config::DeviceSelector};

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
    Getxpub {
        #[arg(value_parser = clap::value_parser!(DerivationPath))]
        path: DerivationPath,
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
    GetXpub { path: DerivationPath, expert: bool },
    Unsupported(String),
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
    Error(HwiError),
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
        HwiCommand::GetXpub { path, expert } => get_xpub(request.selector, path, expert).await,
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
        HwiCliCommand::Getxpub { path } => HwiCommand::GetXpub { path, expert },
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
        let request = parse_args(["hwi", "getmasterxpub"]).expect("unsupported command request");

        assert_eq!(
            request.command,
            HwiCommand::Unsupported("getmasterxpub".to_owned())
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
    fn getxpub_non_expert_serializes_only_xpub() {
        let xpub = sample_xpub();

        let json = serde_json::to_value(HwiResponse::GetXpub(get_xpub_response(xpub, false)))
            .expect("json");

        assert_eq!(json, serde_json::json!({ "xpub": xpub.to_string() }));
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

    fn sample_xpub() -> Xpub {
        Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT")
            .expect("sample xpub")
    }
}
