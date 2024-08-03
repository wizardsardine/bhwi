mod command;
mod interpreter;
mod merkle;

pub mod apdu;
pub mod error;
pub mod psbt;
pub mod wallet;

use bitcoin::{bip32::Fingerprint, Network};
pub use wallet::{WalletPolicy, WalletPubKey};

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

pub struct LedgerInterpreter<C, T, R, E> {
    network: Network,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> LedgerInterpreter<C, T, R, E> {
    pub fn new() -> Self {
        Self {
            network: Network::Bitcoin,
            _marker: std::marker::PhantomData::default(),
        }
    }
}

impl<C, T, R, E> Interpreter for LedgerInterpreter<C, T, R, E>
where
    C: Into<LedgerCommand>,
    T: From<Vec<u8>>,
    R: From<LedgerResponse>,
    E: From<LedgerError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        Err(LedgerError::NoErrorOrResult.into())
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        Err(LedgerError::NoErrorOrResult.into())
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        Err(LedgerError::NoErrorOrResult.into())
    }
}
