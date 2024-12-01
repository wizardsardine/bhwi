pub mod api;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    Network,
};
use serde::{de::DeserializeOwned, Serialize};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Interpreter;

pub const JADE_NETWORK_MAINNET: &str = "mainnet";
pub const JADE_NETWORK_TESTNET: &str = "testnet";

pub enum JadeError {
    NoErrorOrResult,
    Rpc(api::Error),
    Request(&'static str),
    Unexpected(String),
    HandshakeRefused,
}

pub enum JadeCommand {
    Auth,
    GetMasterFingerprint,
}

pub enum JadeResponse {
    TaskDone,
    MasterFingerprint(Fingerprint),
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
    .map_err(|_| JadeError::Request("failed to serialize"))?;

    Ok(JadeTransmit {
        payload,
        recipient: JadeRecipient::Device,
    }
    .into())
}

fn from_response<D: DeserializeOwned>(buffer: &[u8]) -> Result<api::Response<D>, JadeError> {
    serde_cbor::from_slice(buffer).map_err(|_| JadeError::NoErrorOrResult)
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
                Some(api::GetXpubParams {
                    network: self.network,
                    path: DerivationPath::master().to_u32_vec(),
                }),
            ),
            JadeCommand::GetMasterFingerprint => request(
                "get_xpub",
                Some(api::GetXpubParams {
                    network: self.network,
                    path: DerivationPath::master().to_u32_vec(),
                }),
            ),
        };

        self.state = State::Running(command);
        req
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        match self.state {
            State::New => Ok(None),
            State::Running(JadeCommand::Auth) => {
                let res: api::AuthUserResponse = from_response(&data)?.into_result()?;
                if let api::AuthUserResponse::PinServerRequired { http_request } = res {
                    self.state = State::WaitingPinServer;
                    let url = match &http_request.params.urls {
                        api::PinServerUrls::Array(urls) => urls
                            .first()
                            .ok_or(JadeError::Unexpected("No url provided".to_string()))?,
                        api::PinServerUrls::Object { url, .. } => url,
                    };
                    Ok(Some(
                        JadeTransmit {
                            recipient: JadeRecipient::PinServer {
                                url: url.to_string(),
                            },
                            payload: serde_json::to_vec(&http_request.params.data)
                                .map_err(|e| JadeError::Unexpected(e.to_string()))?,
                        }
                        .into(),
                    ))
                } else {
                    Ok(None)
                }
            }
            State::WaitingPinServer => {
                let pin_params: api::PinParams = serde_json::from_slice(&data)
                    .map_err(|_| JadeError::Request("Wrong response from pin server"))?;
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
                let xpub = Xpub::from_str(&s).map_err(|e| JadeError::Unexpected(e.to_string()))?;
                self.response = Some(JadeResponse::MasterFingerprint(xpub.fingerprint()));
                Ok(None)
            }
        }
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        self.response
            .map(Self::Response::from)
            .ok_or(JadeError::NoErrorOrResult.into())
    }
}
