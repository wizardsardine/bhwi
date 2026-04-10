mod command;
mod merkle;
mod store;

pub mod apdu;
pub mod error;
pub mod psbt;
pub mod wallet;

use std::str::FromStr;

use apdu::{ApduCommand, ApduError, ApduResponse, StatusWord};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::ecdsa::Signature;
use store::{DelegatedStore, StoreError};
pub use wallet::{WalletPolicy, WalletPubKey};

use crate::Interpreter;
use crate::common::{Command, Error, Response};
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

    #[error("operation interrupted")]
    Interrupted,

    #[error("unexpected result for {1}: {0:x?}")]
    UnexpectedResult(Vec<u8>, String),

    #[error("failed to open app: {0:x?}")]
    FailedToOpenApp(Vec<u8>),
}

impl LedgerError {
    pub fn unexpected_result(data: Vec<u8>, context: impl Into<String>) -> Self {
        LedgerError::UnexpectedResult(data, context.into())
    }
}

#[derive(Clone, Debug)]
pub enum LedgerCommand {
    OpenApp(Network),
    GetMasterFingerprint,
    GetXpub {
        path: DerivationPath,
        display: bool,
    },
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
}

pub enum LedgerResponse {
    TaskDone,
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    Signature(u8, Signature),
}

#[derive(Default)]
enum State {
    #[default]
    New,
    Running {
        command: LedgerCommand,
        store: Option<DelegatedStore>,
    },
    Finished(LedgerResponse),
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
        };
        self.state = State::Running { command, store };
        Ok(transmit)
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        if let State::Running { store, command } = &mut self.state {
            let res = ApduResponse::try_from(data).map_err(LedgerError::from)?;
            if res.status_word == StatusWord::InterruptedExecution {
                if let Some(store) = store {
                    let transmit = store.execute(res.data).map_err(LedgerError::from)?;
                    return Ok(Some(Self::Transmit::from(command::continue_interrupted(
                        transmit,
                    ))));
                } else {
                    return Err(LedgerError::Interrupted.into());
                }
            }
            // FIXME: cleaner handling of res.status_word before processingn
            // command results
            match command {
                LedgerCommand::GetMasterFingerprint => {
                    if res.data.len() < 4 {
                        return Err(LedgerError::unexpected_result(res.data, "master fingerprint response").into());
                    } else {
                        let mut fg = [0x00; 4];
                        fg.copy_from_slice(&res.data[0..4]);
                        self.state = State::Finished(LedgerResponse::MasterFingerprint(
                            Fingerprint::from(fg),
                        ));
                    }
                }
                LedgerCommand::GetXpub { .. } => {
                    let xpub = Xpub::from_str(&String::from_utf8_lossy(&res.data))
                        .map_err(|_| LedgerError::unexpected_result(res.data, "xpub string"))?;
                    self.state = State::Finished(LedgerResponse::Xpub(xpub));
                }
                LedgerCommand::OpenApp(..) => {
                    if matches!(
                        res.status_word,
                        StatusWord::OK |
                        // An app is already open and the cla cannot be supported
                        StatusWord::ClaNotSupported
                    ) {
                        self.state = State::Finished(LedgerResponse::TaskDone);
                    } else {
                        return Err(LedgerError::unexpected_result(res.data, "open app status").into());
                    }
                }
                LedgerCommand::SignMessage { .. } => match res.status_word {
                    // FIXME: figure out if these are correctly handled
                    StatusWord::Deny | StatusWord::ClaNotSupported | StatusWord::SignatureFail => {
                        self.state = State::Finished(LedgerResponse::TaskDone)
                    }
                    StatusWord::OK => {
                        let header = res.data[0];
                        let sig = Signature::from_compact(&res.data[1..])
                            .map_err(|_| LedgerError::unexpected_result(res.data, "signature compact data"))?;
                        self.state = State::Finished(LedgerResponse::Signature(header, sig));
                    }
                    _ => return Err(LedgerError::unexpected_result(res.data, "sign message status").into()),
                },
            }
        }
        Ok(None)
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
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => todo!(),
        }
    }
}

impl From<LedgerResponse> for Response {
    fn from(res: LedgerResponse) -> Response {
        match res {
            LedgerResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            LedgerResponse::TaskDone => Response::TaskDone,
            LedgerResponse::Xpub(xpub) => Response::Xpub(xpub),
            LedgerResponse::Signature(header, signature) => Response::Signature(header, signature),
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
            LedgerError::Interrupted => Error::Request("Operation interrupted"),
            LedgerError::UnexpectedResult(data, ctx) => Error::unexpected_result(data, ctx),
            LedgerError::FailedToOpenApp(_) => Error::AuthenticationRefused,
        }
    }
}
