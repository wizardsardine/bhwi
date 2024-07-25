pub mod api;

use bitcoin::{bip32::Fingerprint, Network};

use crate::Interpreter;

pub enum JadeError {
    NoErrorOrResult,
    Rpc(api::Error),
}

pub enum JadeCommand {
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
    network: Network,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> JadeInterpreter<C, T, R, E> {
    pub fn new() -> Self {
        Self {
            network: Network::Bitcoin,
            _marker: std::marker::PhantomData::default(),
        }
    }
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
        Err(JadeError::NoErrorOrResult.into())
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        Err(JadeError::NoErrorOrResult.into())
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        Err(JadeError::NoErrorOrResult.into())
    }
}
