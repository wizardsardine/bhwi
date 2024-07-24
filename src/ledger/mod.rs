use bitcoin::{bip32::Fingerprint, Network};

use crate::Interpreter;

pub enum LedgerError {
    NoErrorOrResult,
}

pub enum LedgerCommand {
    GetMasterFingerprint,
}

pub enum LedgerResponse {
    MasterFingerprint(Fingerprint),
}

pub struct LedgerInterpreter<C, T, R> {
    network: Network,
    _marker: std::marker::PhantomData<(C, T, R)>,
}

impl<C, T, R> LedgerInterpreter<C, T, R> {
    pub fn new() -> Self {
        Self {
            network: Network::Bitcoin,
            _marker: std::marker::PhantomData::default(),
        }
    }
}

impl<C, T, R> Interpreter for LedgerInterpreter<C, T, R>
where
    C: Into<LedgerCommand>,
    T: From<Vec<u8>>,
    R: From<LedgerResponse>,
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
