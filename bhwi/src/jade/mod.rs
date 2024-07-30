pub mod api;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    Network,
};
use serde::{de::DeserializeOwned, Serialize};
use std::str::FromStr;

use crate::Interpreter;

pub const JADE_NETWORK_MAINNET: &str = "mainnet";
pub const JADE_NETWORK_TESTNET: &str = "testnet";

pub enum JadeError {
    NoErrorOrResult,
    Rpc(api::Error),
    Request(&'static str),
    Unexpected(String),
}

pub enum JadeCommand {
    None,
    GetMasterFingerprint,
}

pub enum JadeResponse {
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

pub struct JadeInterpreter<C, T, R, E> {
    network: &'static str,
    command: JadeCommand,
    response: Option<JadeResponse>,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> JadeInterpreter<C, T, R, E> {
    pub fn new() -> Self {
        Self {
            network: JADE_NETWORK_MAINNET,
            command: JadeCommand::None,
            response: None,
            _marker: std::marker::PhantomData::default(),
        }
    }
}

fn request<S, T, E>(method: &str, params: Option<S>) -> Result<T, E>
where
    S: Serialize + Unpin,
    T: From<JadeTransmit>,
    E: From<JadeError>,
{
    let id = std::process::id();
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
        self.command = command.into();
        match self.command {
            JadeCommand::None => Err(JadeError::NoErrorOrResult.into()),
            JadeCommand::GetMasterFingerprint => request(
                "get_xpub",
                Some(api::GetXpubParams {
                    network: self.network,
                    path: DerivationPath::master().to_u32_vec(),
                }),
            ),
        }
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        match self.command {
            JadeCommand::None => Ok(None),
            JadeCommand::GetMasterFingerprint => {
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
