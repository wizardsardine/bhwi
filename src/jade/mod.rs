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

pub struct JadeInterpreter<C, T, R> {
    network: Network,
    _marker: std::marker::PhantomData<(C, T, R)>,
}

impl<C, T, R> JadeInterpreter<C, T, R> {
    pub fn new() -> Self {
        Self {
            network: Network::Bitcoin,
            _marker: std::marker::PhantomData::default(),
        }
    }
}

impl<C, T, R> Interpreter for JadeInterpreter<C, T, R>
where
    C: Into<JadeCommand>,
    T: From<JadeTransmit>,
    R: From<JadeResponse>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, ()> {
        Err(())
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, ()> {
        Err(())
    }
    fn end(self) -> Result<Self::Response, ()> {
        Err(())
    }
}
