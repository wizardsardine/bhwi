use std::{ffi::OsString, process::ExitCode, str::FromStr};

use bitcoin::{Network, bip32::Fingerprint};
use clap::{Parser, Subcommand, error::ErrorKind};
use serde::{Serialize, Serializer};

use crate::{DeviceManager, DeviceType, config::DeviceSelector};

type HwiResult<T> = std::result::Result<T, HwiError>;

#[derive(Debug, Clone, Parser)]
#[command(author, version, about = "Python HWI compatible interface")]
pub struct HwiCli {
    #[command(subcommand)]
    command: HwiCliCommand,
    #[arg(long = "device-type")]
    device_type: Option<String>,
    #[arg(long = "device-path")]
    device_path: Option<String>,
    #[arg(long, alias = "fingerprint")]
    fingerprint: Option<Fingerprint>,
    #[arg(long, default_value = "main")]
    chain: String,
    #[arg(long)]
    emulators: bool,
    #[arg(long, hide = true)]
    stdinpass: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum HwiCliCommand {
    Enumerate,
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
    Unsupported(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct HwiError {
    pub error: String,
    pub code: i32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HwiErrorCode {
    BadArgument,
    UnsupportedCommand,
    DeviceConnectionError,
}

impl HwiErrorCode {
    fn code(self) -> i32 {
        match self {
            HwiErrorCode::BadArgument => -7,
            HwiErrorCode::UnsupportedCommand => -9,
            HwiErrorCode::DeviceConnectionError => -10,
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
    #[serde(default, serialize_with = "option_fingerprint")]
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
    Error(HwiError),
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
            fingerprint,
            needs_pin_sent: false,
            needs_passphrase_sent: false,
            error,
            code,
        });
    }
    HwiResponse::Enumerate(response)
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
    let device_type = args
        .device_type
        .as_deref()
        .map(parse_device_type)
        .transpose()?;
    let network = parse_chain(&args.chain)?;
    let command = match args.command {
        HwiCliCommand::Enumerate => HwiCommand::Enumerate,
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
            "--fingerprint",
            "f5acc2fd",
            "--device-type",
            "ledger",
            "--device-path",
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
    fn rejects_unknown_device_type_as_hwi_error() {
        let error = parse_args(["hwi", "--device-type", "trezor", "enumerate"])
            .expect_err("unsupported device type");

        assert_eq!(error.code, HwiErrorCode::BadArgument.code());
        assert!(error.error.contains("Unsupported device type"));
    }

    #[test]
    fn captures_unsupported_commands() {
        let request =
            parse_args(["hwi", "getxpub", "m/84h/0h/0h"]).expect("unsupported command request");

        assert_eq!(
            request.command,
            HwiCommand::Unsupported("getxpub".to_owned())
        );
    }
}
