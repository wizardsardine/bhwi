pub mod api;

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64ct::{Base64, Encoding};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Interpreter;
use crate::common::{Command, DisplayAddress, Error, Info, Recipient, Response, Transmit};
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
    UnsupportedDisplayAddress,
}

pub enum JadeCommand {
    Auth,
    GetMasterFingerprint,
    GetInfo,
    GetXpub(DerivationPath),
    GetReceiveAddress {
        index: u32,
        change: bool,
        descriptor_name: String,
    },
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    SignPsbt {
        psbt: Psbt,
    },
}

pub enum JadeResponse {
    GetInfo(GetInfoResponse),
    MasterFingerprint(Fingerprint),
    Signature(u8, Signature),
    TaskDone,
    Xpub(Xpub),
    Address(String),
    SignedPsbt(Psbt),
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
    GettingExtendedData {
        origid: String,
        orig: String,
        next_seqnum: u32,
        seqlen: u32,
        chunks: Vec<u8>,
    },
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

fn from_response_bytes(buffer: &[u8]) -> Result<api::ResponseBytes, JadeError> {
    serde_cbor::from_slice(buffer).map_err(|_| JadeError::Cbor)
}

fn parse_signed_psbt(bytes: &[u8]) -> Result<JadeResponse, JadeError> {
    Psbt::deserialize(bytes)
        .map(JadeResponse::SignedPsbt)
        .map_err(|e| JadeError::Serialization(e.to_string()))
}

impl<C, T, R, E> Interpreter for JadeInterpreter<C, T, R, E>
where
    C: TryInto<JadeCommand, Error = E>,
    T: From<JadeTransmit>,
    R: From<JadeResponse>,
    E: From<JadeError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: JadeCommand = command.try_into()?;
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
            JadeCommand::SignPsbt { psbt } => request(
                "sign_psbt",
                Some(api::SignPsbtParams {
                    network: self.network,
                    psbt: psbt.serialize(),
                }),
            ),
            JadeCommand::GetReceiveAddress {
                index,
                change,
                descriptor_name,
            } => request(
                "get_receive_address",
                Some(api::DescriptorAddressParams {
                    network: self.network,
                    branch: u32::from(*change),
                    pointer: *index,
                    descriptor_name,
                }),
            ),
            JadeCommand::GetInfo => request("get_version_info", None::<api::EmptyRequest>),
        };

        self.state = State::Running(command);
        req
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        if let State::GettingExtendedData {
            origid,
            orig,
            next_seqnum,
            seqlen,
            chunks,
        } = &mut self.state
        {
            let res = from_response_bytes(&data)?;
            if let Some(e) = res.error {
                return Err(JadeError::Rpc(e).into());
            }
            let chunk = res.result.ok_or(JadeError::NoErrorOrResult)?;
            let seqnum = res.seqnum.unwrap_or(*next_seqnum);
            if seqnum != *next_seqnum {
                return Err(JadeError::UnexpectedResult(format!(
                    "unexpected sign_psbt fragment {seqnum}, wanted {next_seqnum}"
                ))
                .into());
            }
            chunks.extend_from_slice(&chunk);
            if seqnum >= *seqlen {
                self.response = Some(parse_signed_psbt(chunks)?);
                return Ok(None);
            }

            *next_seqnum = seqnum + 1;
            return Ok(Some(request(
                "get_extended_data",
                Some(api::GetExtendedDataParams {
                    origid,
                    orig,
                    seqnum: *next_seqnum,
                    seqlen: *seqlen,
                }),
            )?));
        }

        let mut next_state = None;
        let mut response = None;

        let transmit = match &self.state {
            State::New => None,
            State::Running(JadeCommand::Auth) => {
                let res: api::AuthUserResponse = from_response(&data)?.into_result()?;
                match res {
                    api::AuthUserResponse::PinServerRequired { http_request } => {
                        next_state = Some(State::WaitingPinServer);
                        let url = match &http_request.params.urls {
                            api::PinServerUrls::Array(urls) => urls.first().ok_or(
                                JadeError::UnexpectedResult("No url provided".to_string()),
                            )?,
                            api::PinServerUrls::Object { url, .. } => url,
                        };
                        Some(
                            JadeTransmit {
                                recipient: JadeRecipient::PinServer {
                                    url: url.to_string(),
                                },
                                payload: serde_json::to_vec(&http_request.params.data)
                                    .map_err(|e| JadeError::Serialization(e.to_string()))?,
                            }
                            .into(),
                        )
                    }
                    api::AuthUserResponse::Authenticated(_) => {
                        response = Some(JadeResponse::TaskDone);
                        None
                    }
                }
            }
            State::WaitingPinServer => {
                let pin_params: api::PinParams = serde_json::from_slice(&data).map_err(|_| {
                    JadeError::Serialization("Wrong response from pin server".to_string())
                })?;
                next_state = Some(State::WaitingFinalHandshake);
                Some(request("pin", Some(pin_params))?)
            }
            State::WaitingFinalHandshake => {
                let handshake_completed: bool = from_response(&data)?.into_result()?;
                if !handshake_completed {
                    return Err(JadeError::HandshakeRefused.into());
                }
                response = Some(JadeResponse::TaskDone);
                None
            }
            State::Running(JadeCommand::GetMasterFingerprint) => {
                let s: String = from_response(&data)?.into_result()?;
                let xpub =
                    Xpub::from_str(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                response = Some(JadeResponse::MasterFingerprint(xpub.fingerprint()));
                None
            }
            State::Running(JadeCommand::GetXpub(..)) => {
                let s: String = from_response(&data)?.into_result()?;
                let xpub =
                    Xpub::from_str(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                response = Some(JadeResponse::Xpub(xpub));
                None
            }
            State::Running(JadeCommand::SignMessage { .. }) => {
                let s: String = from_response(&data)?.into_result()?;
                let sig_bytes =
                    Base64::decode_vec(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                let sig = Signature::from_compact(&sig_bytes[1..])
                    .map_err(|e| JadeError::Serialization(e.to_string()))?;
                response = Some(JadeResponse::Signature(sig_bytes[0], sig));
                None
            }
            State::Running(JadeCommand::SignPsbt { .. }) => {
                let res = from_response_bytes(&data)?;
                if let Some(e) = res.error {
                    return Err(JadeError::Rpc(e).into());
                }
                let chunk = res.result.ok_or(JadeError::NoErrorOrResult)?;
                let seqnum = res.seqnum.unwrap_or(1);
                let seqlen = res.seqlen.unwrap_or(1);
                if seqnum != 1 {
                    return Err(JadeError::UnexpectedResult(format!(
                        "unexpected first sign_psbt fragment {seqnum}"
                    ))
                    .into());
                }
                if seqlen <= 1 {
                    response = Some(parse_signed_psbt(&chunk)?);
                    None
                } else {
                    let next_seqnum = seqnum + 1;
                    next_state = Some(State::GettingExtendedData {
                        origid: res.id.clone(),
                        orig: "sign_psbt".to_string(),
                        next_seqnum,
                        seqlen,
                        chunks: chunk,
                    });
                    Some(request(
                        "get_extended_data",
                        Some(api::GetExtendedDataParams {
                            origid: &res.id,
                            orig: "sign_psbt",
                            seqnum: next_seqnum,
                            seqlen,
                        }),
                    )?)
                }
            }
            State::GettingExtendedData { .. } => unreachable!("handled before immutable match"),
            State::Running(JadeCommand::GetReceiveAddress { .. }) => {
                let address: String = from_response(&data)?.into_result()?;
                response = Some(JadeResponse::Address(address));
                None
            }
            State::Running(JadeCommand::GetInfo) => {
                let info: GetInfoResponse = from_response(&data)?.into_result()?;
                response = Some(JadeResponse::GetInfo(info));
                None
            }
        };

        if let Some(state) = next_state {
            self.state = state;
        }
        if response.is_some() {
            self.response = response;
        }
        Ok(transmit)
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        self.response
            .map(Self::Response::from)
            .ok_or_else(|| JadeError::NoErrorOrResult.into())
    }
}

impl TryFrom<Command> for JadeCommand {
    type Error = Error;

    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Backup => Err(Error::MissingCommandInfo("Backup not supported by Jade")),
            Command::Unlock { .. } => Ok(Self::Auth),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, .. } => Ok(Self::GetXpub(path)),
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    index,
                    change,
                    descriptor_name,
                    ..
                },
                _ctx,
            ) => Ok(Self::GetReceiveAddress {
                index,
                change,
                descriptor_name,
            }),
            Command::DisplayAddress(DisplayAddress::ByPath { .. }, _) => {
                Err(Error::UnsupportedDisplayAddress(
                    "Jade does not support path-based address display".into(),
                ))
            }
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetInfo),
            Command::RegisterWallet { .. } => Err(Error::MissingCommandInfo(
                "RegisterWallet not supported by Jade",
            )),
            Command::SignTx(psbt, _) => Ok(Self::SignPsbt { psbt }),
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
            JadeResponse::GetInfo(info) => Response::Info(Info {
                version: info.jade_version.as_str().into(),
                networks: info.jade_networks.into(),
                firmware: None,
            }),
            JadeResponse::Address(address) => Response::Address(address),
            JadeResponse::SignedPsbt(psbt) => Response::SignedPsbt(psbt),
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
            JadeError::UnsupportedDisplayAddress => {
                Error::UnsupportedDisplayAddress("unsupported display address on Jade".into())
            }
        }
    }
}
