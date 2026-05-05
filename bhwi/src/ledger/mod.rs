pub mod command;
mod merkle;
pub mod store;

pub mod apdu;
pub mod error;
pub mod psbt;
pub mod wallet;

use std::str::FromStr;

use apdu::{ApduCommand, ApduError, ApduResponse, StatusWord};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::consensus::encode::deserialize_partial;
use bitcoin::secp256k1::ecdsa::Signature;
use store::{DelegatedStore, StoreError};
pub use wallet::{AddressType, LedgerWalletPolicy, Version, WalletError, singlesig_wallet_policy};

use crate::Interpreter;
use crate::common::{Command, DeviceContext, DisplayAddress, Error, Info, Response};
use crate::device::DeviceId;

pub const LEDGER_DEVICE_ID: DeviceId = DeviceId::new(0x2c97)
    .with_usage_page(0xffa0)
    .with_emulator_path("localhost:9999");

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("missing command info: {0}")]
    MissingCommandInfo(&'static str),

    #[error("no error or result returned")]
    NoErrorOrResult,

    #[error("APDU error")]
    Apdu(#[from] ApduError),

    #[error("store error")]
    Store(#[from] StoreError),

    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),

    #[error("operation interrupted")]
    Interrupted,

    #[error("unexpected result for {1}: {0:x?}")]
    UnexpectedResult(Vec<u8>, String),

    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(String),

    #[error("failed to open app: {0:x?}")]
    FailedToOpenApp(Vec<u8>),
}

impl LedgerError {
    pub fn unexpected_result(data: Vec<u8>, context: impl Into<String>) -> Self {
        LedgerError::UnexpectedResult(data, context.into())
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LedgerCommand {
    OpenApp(Network),
    GetAppInfo,
    GetMasterFingerprint,
    GetXpub {
        path: DerivationPath,
        display: bool,
    },
    GetWalletAddress {
        address: DisplayAddress,
        context: Option<DeviceContext>,
    },
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    RegisterWallet {
        policy: LedgerWalletPolicy,
    },
}

/// Parsed response from the `GetAppInfo` APDU command.
///
/// The raw response format from the device is:
/// - 1 byte: version tag (0x01)
/// - length-prefixed string: app name
/// - length-prefixed string: app version
/// - length-prefixed bytes: state flags
#[derive(Debug, Clone)]
pub struct GetAppInfoResponse {
    pub app_name: String,
    pub version: String,
    pub flags: Vec<u8>,
}

impl GetAppInfoResponse {
    pub fn network(&self) -> Network {
        if self.app_name == "Bitcoin" {
            Network::Bitcoin
        } else {
            Network::Testnet
        }
    }
}

impl TryFrom<Vec<u8>> for GetAppInfoResponse {
    type Error = String;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        if data.is_empty() || data[0] != 0x01 {
            return Err(format!(
                "invalid version response header: expected 0x01, got {:02x}",
                data.first().map_or(0, |b| *b)
            ));
        }
        let (app_name, i): (String, usize) = deserialize_partial(&data[1..])
            .map_err(|e| format!("failed to parse app name: {e}"))?;
        let (version, j): (String, usize) = deserialize_partial(&data[1 + i..])
            .map_err(|e| format!("failed to parse version: {e}"))?;
        let (flags, _): (Vec<u8>, usize) = deserialize_partial(&data[1 + i + j..])
            .map_err(|e| format!("failed to parse flags: {e}"))?;
        Ok(GetAppInfoResponse {
            app_name,
            version,
            flags,
        })
    }
}

pub enum LedgerResponse {
    AppInfo(GetAppInfoResponse),
    MasterFingerprint(Fingerprint),
    Signature(u8, Signature),
    TaskDone,
    Xpub(Xpub),
    Address(String),
    WalletHmac([u8; 32]),
}

#[derive(Default)]
#[allow(clippy::large_enum_variant)]
enum State {
    #[default]
    New,
    Running {
        command: LedgerCommand,
        store: Option<DelegatedStore>,
    },
    GetWalletAddress(GetWalletAddressStep),
    Finished(LedgerResponse),
}

enum GetWalletAddressStep {
    Fingerprint {
        address: DisplayAddress,
        context: Option<DeviceContext>,
    },
    Xpub {
        address: DisplayAddress,
        fingerprint: Fingerprint,
        display: bool,
        context: Option<DeviceContext>,
    },
    WalletAddress {
        store: Option<DelegatedStore>,
    },
}

pub struct LedgerInterpreter<C, T, R, E> {
    state: State,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for LedgerInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            state: State::default(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C, T, R, E> Interpreter for LedgerInterpreter<C, T, R, E>
where
    C: TryInto<LedgerCommand, Error = LedgerError>,
    T: From<ApduCommand>,
    R: From<LedgerResponse>,
    E: From<LedgerError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: LedgerCommand = command.try_into()?;
        let (transmit, store) = match command {
            LedgerCommand::GetAppInfo => (Self::Transmit::from(command::get_version()), None),
            LedgerCommand::GetMasterFingerprint => (
                Self::Transmit::from(command::get_master_fingerprint()),
                None,
            ),
            LedgerCommand::GetXpub { ref path, display } => (
                Self::Transmit::from(command::get_extended_pubkey(path, display)),
                None,
            ),
            LedgerCommand::OpenApp(network) => {
                (Self::Transmit::from(command::open_app(network)), None)
            }
            LedgerCommand::SignMessage {
                ref message,
                ref path,
            } => {
                let message_length = message.len();
                let chunks = message.chunks(64).collect::<Vec<&[u8]>>();
                let mut store = DelegatedStore::new();
                let message_commitment_root = store.add_known_list(&chunks);
                (
                    Self::Transmit::from(command::sign_message(
                        message_length,
                        &message_commitment_root,
                        path,
                    )),
                    Some(store),
                )
            }
            LedgerCommand::GetWalletAddress { address, context } => {
                self.state =
                    State::GetWalletAddress(GetWalletAddressStep::Fingerprint { address, context });
                return Ok(Self::Transmit::from(command::get_master_fingerprint()));
            }
            LedgerCommand::RegisterWallet { ref policy } => (
                Self::Transmit::from(command::register_wallet(policy).map_err(LedgerError::from)?),
                Some(policy.to_store().map_err(LedgerError::from)?),
            ),
        };
        self.state = State::Running { command, store };
        Ok(transmit)
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        let res = ApduResponse::try_from(data).map_err(LedgerError::from)?;
        let state = std::mem::take(&mut self.state);
        let (next_state, result) = match state {
            State::GetWalletAddress(GetWalletAddressStep::Fingerprint {
                mut address,
                context,
            }) => {
                if res.data.len() < 4 {
                    return Err(LedgerError::unexpected_result(
                        res.data,
                        "display address: master fingerprint",
                    )
                    .into());
                }
                let mut fg = [0x00; 4];
                fg.copy_from_slice(&res.data[0..4]);
                let fingerprint = Fingerprint::from(fg);
                match &mut address {
                    DisplayAddress::ByPath { path, display, .. } => {
                        let children: Vec<_> = path.as_ref().to_vec();
                        if children.len() < 5 {
                            return Err(LedgerError::UnsupportedDisplayAddress(
                                "Ledger requires a full 5-level derivation path (e.g. m/84'/0'/0'/0/0)".into(),
                            )
                            .into());
                        }
                        let account_path = DerivationPath::from(children[..3].to_vec());
                        let display = *display;
                        let cmd = Self::Transmit::from(command::get_extended_pubkey(
                            &account_path,
                            false,
                        ));
                        (
                            State::GetWalletAddress(GetWalletAddressStep::Xpub {
                                address,
                                fingerprint,
                                display,
                                context,
                            }),
                            Some(cmd),
                        )
                    }
                    DisplayAddress::ByDescriptor {
                        index,
                        change,
                        display,
                        ..
                    } => {
                        let (ledger_policy, wallet_hmac) = context
                            .as_ref()
                            .map(|ctx| match ctx {
                                DeviceContext::Ledger { wallet_policy, wallet_hmac } => {
                                    (wallet_policy.clone(), *wallet_hmac)
                                }
                            })
                            .ok_or(LedgerError::MissingCommandInfo(
                                "Ledger requires DeviceContext::Ledger for descriptor-based address display",
                            ))?;
                        let store = Some(ledger_policy.to_store().map_err(LedgerError::from)?);
                        let cmd = Self::Transmit::from(
                            command::get_wallet_address(
                                &ledger_policy,
                                wallet_hmac.as_ref(),
                                *change,
                                *index,
                                *display,
                            )
                            .map_err(LedgerError::from)?,
                        );
                        (
                            State::GetWalletAddress(GetWalletAddressStep::WalletAddress { store }),
                            Some(cmd),
                        )
                    }
                }
            }
            State::GetWalletAddress(GetWalletAddressStep::Xpub {
                address,
                fingerprint,
                display,
                context,
            }) => {
                let xpub = Xpub::from_str(&String::from_utf8_lossy(&res.data)).map_err(|_| {
                    LedgerError::unexpected_result(res.data, "display address: xpub")
                })?;
                let (ledger_policy, wallet_hmac, change, address_index) = match address {
                    DisplayAddress::ByPath { path, .. } => {
                        let children: Vec<_> = path.as_ref().to_vec();
                        let change =
                            children[3] == bitcoin::bip32::ChildNumber::from_normal_idx(1).unwrap();
                        let address_index = u32::from(children[4]);
                        let policy = singlesig_wallet_policy(&path, fingerprint, xpub)
                            .map_err(LedgerError::from)?;
                        (
                            LedgerWalletPolicy::new(String::new(), Version::V2, policy),
                            None,
                            change,
                            address_index,
                        )
                    }
                    DisplayAddress::ByDescriptor { index, change, .. } => {
                        let (wallet_policy, wallet_hmac) = context
                            .as_ref()
                            .map(|ctx| match ctx {
                                DeviceContext::Ledger { wallet_policy, wallet_hmac } => {
                                    (wallet_policy.clone(), *wallet_hmac)
                                }
                            })
                            .ok_or(LedgerError::MissingCommandInfo(
                                "Ledger requires DeviceContext::Ledger for descriptor-based address display",
                            ))?;
                        (wallet_policy, wallet_hmac, change, index)
                    }
                };
                let store = Some(ledger_policy.to_store().map_err(LedgerError::from)?);
                let cmd = Self::Transmit::from(
                    command::get_wallet_address(
                        &ledger_policy,
                        wallet_hmac.as_ref(),
                        change,
                        address_index,
                        display,
                    )
                    .map_err(LedgerError::from)?,
                );
                (
                    State::GetWalletAddress(GetWalletAddressStep::WalletAddress { store }),
                    Some(cmd),
                )
            }
            State::GetWalletAddress(GetWalletAddressStep::WalletAddress { mut store }) => {
                if res.status_word == StatusWord::Deny {
                    (State::Finished(LedgerResponse::TaskDone), None)
                } else if res.status_word == StatusWord::InterruptedExecution {
                    if let Some(ref mut s) = store {
                        let transmit = s.execute(res.data).map_err(LedgerError::from)?;
                        let cmd = Self::Transmit::from(command::continue_interrupted(transmit));
                        self.state =
                            State::GetWalletAddress(GetWalletAddressStep::WalletAddress { store });
                        return Ok(Some(cmd));
                    } else {
                        return Err(LedgerError::Interrupted.into());
                    }
                } else if res.status_word != StatusWord::OK {
                    return Err(
                        LedgerError::unexpected_result(res.data, "display address status").into(),
                    );
                } else {
                    let address = String::from_utf8(res.data)
                        .map_err(|e| LedgerError::unexpected_result(vec![], e.to_string()))?;
                    (State::Finished(LedgerResponse::Address(address)), None)
                }
            }
            State::Running { mut store, command } => {
                if res.status_word == StatusWord::InterruptedExecution {
                    if let Some(ref mut s) = store {
                        let transmit = s.execute(res.data).map_err(LedgerError::from)?;
                        let cmd = Self::Transmit::from(command::continue_interrupted(transmit));
                        self.state = State::Running { store, command };
                        return Ok(Some(cmd));
                    } else {
                        return Err(LedgerError::Interrupted.into());
                    }
                }
                match command {
                    LedgerCommand::GetAppInfo => {
                        if res.status_word != StatusWord::OK {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "get_version response",
                            )
                            .into());
                        }
                        let response = GetAppInfoResponse::try_from(res.data.clone())
                            .map_err(|e| LedgerError::unexpected_result(res.data, e))?;
                        (State::Finished(LedgerResponse::AppInfo(response)), None)
                    }
                    LedgerCommand::GetMasterFingerprint => {
                        if res.data.len() < 4 {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "master fingerprint response",
                            )
                            .into());
                        } else {
                            let mut fg = [0x00; 4];
                            fg.copy_from_slice(&res.data[0..4]);
                            (
                                State::Finished(LedgerResponse::MasterFingerprint(
                                    Fingerprint::from(fg),
                                )),
                                None,
                            )
                        }
                    }
                    LedgerCommand::GetXpub { .. } => {
                        let xpub = Xpub::from_str(&String::from_utf8_lossy(&res.data))
                            .map_err(|_| LedgerError::unexpected_result(res.data, "xpub string"))?;
                        (State::Finished(LedgerResponse::Xpub(xpub)), None)
                    }
                    LedgerCommand::OpenApp(..) => {
                        if matches!(
                            res.status_word,
                            StatusWord::OK | StatusWord::ClaNotSupported
                        ) {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        } else {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "open app response",
                            )
                            .into());
                        }
                    }
                    LedgerCommand::SignMessage { .. } => match res.status_word {
                        StatusWord::Deny
                        | StatusWord::ClaNotSupported
                        | StatusWord::SignatureFail => {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        }
                        StatusWord::OK => {
                            let header = res.data[0];
                            let sig = Signature::from_compact(&res.data[1..]).map_err(|_| {
                                LedgerError::unexpected_result(res.data, "signature compact data")
                            })?;
                            (
                                State::Finished(LedgerResponse::Signature(header, sig)),
                                None,
                            )
                        }
                        _ => {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "sign message status",
                            )
                            .into());
                        }
                    },
                    LedgerCommand::GetWalletAddress { .. } => {
                        if res.status_word == StatusWord::Deny {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        } else if res.status_word == StatusWord::OK {
                            let address = String::from_utf8(res.data).map_err(|e| {
                                LedgerError::unexpected_result(vec![], e.to_string())
                            })?;
                            (State::Finished(LedgerResponse::Address(address)), None)
                        } else {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "display address status",
                            )
                            .into());
                        }
                    }
                    LedgerCommand::RegisterWallet { .. } => {
                        if res.status_word != StatusWord::OK {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "register wallet status",
                            )
                            .into());
                        }
                        if res.data.len() < 64 {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "register wallet: response too short",
                            )
                            .into());
                        }
                        let mut hmac = [0u8; 32];
                        hmac.copy_from_slice(&res.data[32..64]);
                        (State::Finished(LedgerResponse::WalletHmac(hmac)), None)
                    }
                }
            }
            State::New => (State::New, None),
            State::Finished(_) => (state, None),
        };
        self.state = next_state;
        Ok(result)
    }

    fn end(self) -> Result<Self::Response, Self::Error> {
        if let State::Finished(res) = self.state {
            Ok(Self::Response::from(res))
        } else {
            Err(LedgerError::NoErrorOrResult.into())
        }
    }
}

impl TryFrom<Command> for LedgerCommand {
    type Error = LedgerError;
    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Unlock { options } => options
                .network
                .map(Self::OpenApp)
                .ok_or(LedgerError::MissingCommandInfo("network")),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, display } => Ok(Self::GetXpub { path, display }),
            Command::DisplayAddress(addr, ctx) => Ok(Self::GetWalletAddress {
                address: addr,
                context: ctx,
            }),
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetAppInfo),
            Command::RegisterWallet { name, policy } => Ok(Self::RegisterWallet {
                policy: LedgerWalletPolicy::new(name, Version::V2, policy),
            }),
        }
    }
}

impl From<LedgerResponse> for Response {
    fn from(res: LedgerResponse) -> Response {
        match res {
            LedgerResponse::AppInfo(res) => Response::Info(Info {
                version: res.version.to_string(),
                networks: vec![res.network()],
                firmware: Some(res.app_name),
            }),
            LedgerResponse::Signature(header, signature) => Response::Signature(header, signature),
            LedgerResponse::TaskDone => Response::TaskDone,
            LedgerResponse::Xpub(xpub) => Response::Xpub(xpub),
            LedgerResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            LedgerResponse::Address(address) => Response::Address(address),
            LedgerResponse::WalletHmac(hmac) => Response::WalletHmac(hmac),
        }
    }
}

impl From<LedgerError> for Error {
    fn from(error: LedgerError) -> Error {
        match error {
            LedgerError::MissingCommandInfo(e) => Error::MissingCommandInfo(e),
            LedgerError::NoErrorOrResult => Error::NoErrorOrResult,
            LedgerError::Apdu(e) => Error::Serialization(format!("{:?}", e)),
            LedgerError::Store(_) => Error::Request("Store operation failed"),
            LedgerError::Wallet(_) => Error::Request("Wallet operation failed"),
            LedgerError::Interrupted => Error::Request("Operation interrupted"),
            LedgerError::UnexpectedResult(data, ctx) => Error::unexpected_result(data, ctx),
            LedgerError::UnsupportedDisplayAddress(ctx) => Error::UnsupportedDisplayAddress(ctx),
            LedgerError::FailedToOpenApp(_) => Error::AuthenticationRefused,
        }
    }
}
