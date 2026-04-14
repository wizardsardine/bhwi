pub mod api;
pub mod encrypt;

use std::string::FromUtf8Error;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::ecdsa::Signature;

use crate::Interpreter;
use crate::coldcard::api::response::ResponseMessage;
use crate::common::{Command, Error, Info, Recipient, Response, Transmit};
use crate::device::DeviceId;

pub const DEFAULT_CKCC_SOCKET: &str = "/tmp/ckcc-simulator.sock";
pub const COLDCARD_DEVICE_ID: DeviceId = DeviceId::new(0xd13e)
    .with_pid(0xcc10)
    .with_emulator_path(DEFAULT_CKCC_SOCKET);

#[derive(Debug, thiserror::Error)]
pub enum ColdcardError {
    /// Encryption error
    #[error("encryption error: {0}")]
    Encryption(&'static str),

    #[error("missing command info: {0}")]
    MissingCommandInfo(&'static str),

    #[error("no error or result returned")]
    NoErrorOrResult,

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Unexpected response message from device
    #[error("unexpected response message: got {got:?}, expected {expected:?}")]
    UnexpectedResponseMessage {
        got: ResponseMessage,
        expected: Vec<ResponseMessage>,
    },
}

impl ColdcardError {
    pub fn unexpected_response_message(
        got: ResponseMessage,
        expected: &[ResponseMessage],
    ) -> ColdcardError {
        ColdcardError::UnexpectedResponseMessage {
            got,
            expected: expected.to_vec(),
        }
    }
}

pub enum ColdcardCommand {
    StartEncryption,
    GetVersion,
    GetMasterFingerprint,
    GetXpub(DerivationPath),
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
}

pub enum ColdcardResponse {
    Ok,
    Busy,
    Version {
        version: String,
        device_model: String,
    },
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    MyPub {
        encryption_key: [u8; 64],
        xpub_fingerprint: Fingerprint,
        xpub: Option<Xpub>,
    },
    Signature(u8, Signature),
}

pub struct ColdcardTransmit {
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

enum State {
    New,
    Running(ColdcardCommand),
    Finished(ColdcardResponse),
}

pub struct ColdcardInterpreter<'a, C, T, R, E> {
    state: State,
    encryption: &'a mut encrypt::Engine,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<'a, C, T, R, E> ColdcardInterpreter<'a, C, T, R, E> {
    pub fn new(encryption: &'a mut encrypt::Engine) -> Self {
        Self {
            state: State::New,
            encryption,
            _marker: std::marker::PhantomData,
        }
    }
}

fn request(
    payload: Vec<u8>,
    encryption: &mut encrypt::Engine,
) -> Result<ColdcardTransmit, ColdcardError> {
    Ok(ColdcardTransmit {
        payload: encryption.encrypt(payload)?,
        encrypted: true,
    })
}

impl<'a, C, T, R, E> Interpreter for ColdcardInterpreter<'a, C, T, R, E>
where
    C: TryInto<ColdcardCommand, Error = ColdcardError>,
    T: From<ColdcardTransmit>,
    R: From<ColdcardResponse>,
    E: From<ColdcardError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: ColdcardCommand = command.try_into()?;
        let req = match &command {
            ColdcardCommand::StartEncryption => ColdcardTransmit {
                payload: api::request::start_encryption(None, &self.encryption.pub_key()?),
                encrypted: false,
            },
            ColdcardCommand::GetVersion => request(api::request::get_version(), self.encryption)?,
            ColdcardCommand::GetMasterFingerprint => request(
                api::request::get_xpub(&DerivationPath::master()),
                self.encryption,
            )?,
            ColdcardCommand::GetXpub(path) => {
                request(api::request::get_xpub(path), self.encryption)?
            }
            ColdcardCommand::SignMessage { message, path } => {
                request(api::request::sign_message(message, path), self.encryption)?
            }
        };

        self.state = State::Running(command);
        Ok(req.into())
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        match &self.state {
            State::New => Ok(None),
            State::Running(ColdcardCommand::GetVersion) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::version(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::GetMasterFingerprint) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::master_fingerprint(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::GetXpub(..)) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::get_xpub(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::SignMessage { .. }) => {
                let data = self.encryption.decrypt(data)?;
                let res = api::response::sign_message(&data)?;
                if let ColdcardResponse::Ok | ColdcardResponse::Busy = res {
                    return Ok(Some(
                        request(api::request::get_signed_message(), self.encryption)?.into(),
                    ));
                }
                self.state = State::Finished(res);
                Ok(None)
            }
            State::Running(ColdcardCommand::StartEncryption) => {
                let mypub = api::response::mypub(&data)?;
                self.state = State::Finished(mypub);
                Ok(None)
            }
            State::Finished(..) => Ok(None),
        }
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        if let State::Finished(res) = self.state {
            Ok(Self::Response::from(res))
        } else {
            Err(ColdcardError::NoErrorOrResult.into())
        }
    }
}

impl TryFrom<Command> for ColdcardCommand {
    type Error = ColdcardError;
    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Unlock { .. } => Ok(Self::StartEncryption),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, .. } => Ok(Self::GetXpub(path)),
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetVersion),
        }
    }
}

impl From<ColdcardResponse> for Response {
    fn from(res: ColdcardResponse) -> Response {
        match res {
            ColdcardResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            ColdcardResponse::Xpub(xpub) => Response::Xpub(xpub),
            ColdcardResponse::Version {
                version,
                device_model,
            } => Response::Info(Info {
                version: version.as_str().into(),
                networks: vec![],
                firmware: Some(device_model),
            }),
            ColdcardResponse::MyPub { encryption_key, .. } => {
                Response::EncryptionKey(encryption_key)
            }
            ColdcardResponse::Signature(header, signature) => {
                Response::Signature(header, signature)
            }
            ColdcardResponse::Ok => Response::TaskDone,
            ColdcardResponse::Busy => Response::TaskBusy,
        }
    }
}

impl From<ColdcardTransmit> for Transmit {
    fn from(transmit: ColdcardTransmit) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload: transmit.payload,
            encrypted: transmit.encrypted,
        }
    }
}

impl From<ColdcardError> for Error {
    fn from(error: ColdcardError) -> Error {
        match error {
            ColdcardError::Encryption(e) => Error::Encryption(e),
            ColdcardError::MissingCommandInfo(e) => Error::MissingCommandInfo(e),
            ColdcardError::NoErrorOrResult => Error::NoErrorOrResult,
            ColdcardError::Serialization(s) => Error::Serialization(s),
            ColdcardError::UnexpectedResponseMessage { got, expected } => Error::unexpected_result(
                format!("{got:?}").into_bytes(),
                format!("coldcard unexpected response: expected {expected:?}, got {got:?}"),
            ),
        }
    }
}

impl From<FromUtf8Error> for ColdcardError {
    fn from(error: FromUtf8Error) -> Self {
        ColdcardError::Serialization(error.to_string())
    }
}
