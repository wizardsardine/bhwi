pub mod api;

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64ct::{Base64, Encoding};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::ecdsa::Signature;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Interpreter;
use crate::common::{Command, Error, Recipient, Response, Transmit, Version};
use crate::device::DeviceId;
use crate::jade::api::GetInfoResponse;

pub const JADE_NETWORK_MAINNET: &str = "mainnet";
pub const JADE_NETWORK_TESTNET: &str = "testnet";

pub const JADE_DEVICE_IDS: [DeviceId; 6] = [
    DeviceId::new(0x10c4).with_pid(0xea60),
    DeviceId::new(0x1a86).with_pid(0x55d4),
    DeviceId::new(0x0403).with_pid(0x6001),
    DeviceId::new(0x1a86).with_pid(0x7523),
    DeviceId::new(0x303a).with_pid(0x4001),
    DeviceId::new(0x303a).with_pid(0x1001),
];

#[derive(Debug)]
pub enum JadeError {
    NoErrorOrResult,
    Rpc(api::Error),
    Cbor,
    Serialization(String),
    UnexpectedResult(String),
    HandshakeRefused,
}

pub enum JadeCommand {
    Auth,
    GetMasterFingerprint,
    GetInfo,
    GetXpub(DerivationPath),
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
}

pub enum JadeResponse {
    GetInfo(GetInfoResponse),
    MasterFingerprint(Fingerprint),
    Signature(u8, Signature),
    TaskDone,
    Xpub(Xpub),
}

pub enum JadeRecipient {
    Device,
    PinServer { url: String },
}

pub struct JadeTransmit {
    pub recipient: JadeRecipient,
    pub payload: Vec<u8>,
}

enum State {
    New,
    Running(JadeCommand),
    WaitingPinServer,
    WaitingFinalHandshake,
}

pub struct JadeInterpreter<C, T, R, E> {
    network: &'static str,
    state: State,
    response: Option<JadeResponse>,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for JadeInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            network: JADE_NETWORK_MAINNET,
            state: State::New,
            response: None,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C, T, R, E> JadeInterpreter<C, T, R, E> {
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = match network {
            Network::Bitcoin => JADE_NETWORK_MAINNET,
            _ => JADE_NETWORK_TESTNET,
        };
        self
    }
}

// Initialize a static atomic counter
static REQUEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

fn generate_request_id() -> usize {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn request<S, T, E>(method: &str, params: Option<S>) -> Result<T, E>
where
    S: Serialize + Unpin,
    T: From<JadeTransmit>,
    E: From<JadeError>,
{
    let id = generate_request_id();
    let payload = serde_cbor::to_vec(&api::Request {
        id: &id.to_string(),
        method,
        params,
    })
    .map_err(|_| JadeError::Serialization("failed to serialize".to_string()))?;

    Ok(JadeTransmit {
        payload,
        recipient: JadeRecipient::Device,
    }
    .into())
}

fn from_response<D: DeserializeOwned>(buffer: &[u8]) -> Result<api::Response<D>, JadeError> {
    serde_cbor::from_slice(buffer).map_err(|_| JadeError::Cbor)
}

impl<C, T, R, E> Interpreter for JadeInterpreter<C, T, R, E>
where
    C: Into<JadeCommand>,
    T: From<JadeTransmit>,
    R: From<JadeResponse>,
    E: From<JadeError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: JadeCommand = command.into();
        let req = match &command {
            JadeCommand::Auth => request(
                "auth_user",
                Some(api::AuthUserParams {
                    network: self.network,
                    epoch: None,
                }),
            ),
            JadeCommand::GetMasterFingerprint => request(
                "get_xpub",
                Some(api::GetXpubParams {
                    network: self.network,
                    path: DerivationPath::master().to_u32_vec(),
                }),
            ),
            JadeCommand::GetXpub(path) => request(
                "get_xpub",
                Some(api::GetXpubParams {
                    network: self.network,
                    path: path.to_u32_vec(),
                }),
            ),
            JadeCommand::SignMessage { message, path } => request(
                "sign_message",
                Some(api::SignMessageParams {
                    path: path.to_u32_vec(),
                    message: &String::from_utf8(message.to_vec())
                        .map_err(|e| JadeError::Serialization(e.to_string()))?,
                }),
            ),
            JadeCommand::GetInfo => request("get_version_info", None::<api::EmptyRequest>),
        };

        self.state = State::Running(command);
        req
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        match self.state {
            State::New => Ok(None),
            State::Running(JadeCommand::Auth) => {
                let res: api::AuthUserResponse = from_response(&data)?.into_result()?;
                match res {
                    api::AuthUserResponse::PinServerRequired { http_request } => {
                        self.state = State::WaitingPinServer;
                        let url = match &http_request.params.urls {
                            api::PinServerUrls::Array(urls) => urls.first().ok_or(
                                JadeError::UnexpectedResult("No url provided".to_string()),
                            )?,
                            api::PinServerUrls::Object { url, .. } => url,
                        };
                        Ok(Some(
                            JadeTransmit {
                                recipient: JadeRecipient::PinServer {
                                    url: url.to_string(),
                                },
                                payload: serde_json::to_vec(&http_request.params.data)
                                    .map_err(|e| JadeError::Serialization(e.to_string()))?,
                            }
                            .into(),
                        ))
                    }
                    api::AuthUserResponse::Authenticated(_) => {
                        self.response = Some(JadeResponse::TaskDone);
                        Ok(None)
                    }
                }
            }
            State::WaitingPinServer => {
                let pin_params: api::PinParams = serde_json::from_slice(&data).map_err(|_| {
                    JadeError::Serialization("Wrong response from pin server".to_string())
                })?;
                let transmit = request("pin", Some(pin_params))?;
                self.state = State::WaitingFinalHandshake;
                Ok(Some(transmit))
            }
            State::WaitingFinalHandshake => {
                let handshake_completed: bool = from_response(&data)?.into_result()?;
                if handshake_completed {
                    self.response = Some(JadeResponse::TaskDone);
                    Ok(None)
                } else {
                    Err(JadeError::HandshakeRefused.into())
                }
            }
            State::Running(JadeCommand::GetMasterFingerprint) => {
                let s: String = from_response(&data)?.into_result()?;
                let xpub =
                    Xpub::from_str(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                self.response = Some(JadeResponse::MasterFingerprint(xpub.fingerprint()));
                Ok(None)
            }
            State::Running(JadeCommand::GetXpub(..)) => {
                let s: String = from_response(&data)?.into_result()?;
                let xpub =
                    Xpub::from_str(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                self.response = Some(JadeResponse::Xpub(xpub));
                Ok(None)
            }
            State::Running(JadeCommand::SignMessage { .. }) => {
                let s: String = from_response(&data)?.into_result()?;
                let sig_bytes =
                    Base64::decode_vec(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                let sig = Signature::from_compact(&sig_bytes[1..])
                    .map_err(|e| JadeError::Serialization(e.to_string()))?;
                self.response = Some(JadeResponse::Signature(sig_bytes[0], sig));
                Ok(None)
            }
            State::Running(JadeCommand::GetInfo) => {
                let info: GetInfoResponse = from_response(&data)?.into_result()?;
                self.response = Some(JadeResponse::GetInfo(info));
                Ok(None)
            }
        }
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        self.response
            .map(Self::Response::from)
            .ok_or_else(|| JadeError::NoErrorOrResult.into())
    }
}

impl From<Command> for JadeCommand {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Unlock { .. } => Self::Auth,
            Command::GetMasterFingerprint => Self::GetMasterFingerprint,
            Command::GetXpub { path, .. } => Self::GetXpub(path),
            Command::SignMessage { message, path } => Self::SignMessage { message, path },
            Command::GetVersion => Self::GetInfo,
        }
    }
}

impl From<JadeResponse> for Response {
    fn from(res: JadeResponse) -> Response {
        match res {
            JadeResponse::TaskDone => Response::TaskDone,
            JadeResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            JadeResponse::Xpub(xpub) => Response::Xpub(xpub),
            JadeResponse::Signature(header, signature) => Response::Signature(header, signature),
            JadeResponse::GetInfo(info) => Response::Version(Version {
                version: info.jade_version.as_str().into(),
                network: Some(info.jade_networks.to_string()),
                firmware: None,
            }),
        }
    }
}

impl From<JadeRecipient> for Recipient {
    fn from(recipient: JadeRecipient) -> Recipient {
        match recipient {
            JadeRecipient::Device => Recipient::Device,
            JadeRecipient::PinServer { url } => Recipient::PinServer { url },
        }
    }
}

impl From<JadeTransmit> for Transmit {
    fn from(transmit: JadeTransmit) -> Transmit {
        Transmit {
            recipient: transmit.recipient.into(),
            payload: transmit.payload,
            encrypted: false,
        }
    }
}

impl From<JadeError> for Error {
    fn from(error: JadeError) -> Error {
        match error {
            JadeError::Cbor => Error::Serialization("cbor".to_string()),
            JadeError::NoErrorOrResult => Error::NoErrorOrResult,
            JadeError::Rpc(api_error) => Error::Rpc(api_error.code, api_error.message),
            JadeError::Serialization(s) => Error::Serialization(s),
            JadeError::UnexpectedResult(msg) => Error::unexpected_result(
                msg.clone().into_bytes(),
                format!("jade unexpected result: {msg}"),
            ),
            JadeError::HandshakeRefused => Error::AuthenticationRefused,
        }
    }
}
