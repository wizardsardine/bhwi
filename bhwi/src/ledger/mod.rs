mod command;
mod merkle;
mod store;

pub mod apdu;
pub mod error;
pub mod psbt;
pub mod wallet;

use bitcoin::{bip32::Fingerprint, Network};
pub use wallet::{WalletPolicy, WalletPubKey};

use crate::Interpreter;

use apdu::{ApduError, ApduResponse, StatusWord};
use store::{DelegatedStore, StoreError};

pub enum LedgerError {
    NoErrorOrResult,
    Apdu(ApduError),
    Store(StoreError),
    Interrupted,
    UnexpectedResult(LedgerCommand, Vec<u8>),
}

impl From<ApduError> for LedgerError {
    fn from(value: ApduError) -> Self {
        LedgerError::Apdu(value)
    }
}

impl From<StoreError> for LedgerError {
    fn from(value: StoreError) -> Self {
        LedgerError::Store(value)
    }
}

#[derive(Clone)]
pub enum LedgerCommand {
    GetMasterFingerprint,
    GetXpub,
}

pub enum LedgerResponse {
    MasterFingerprint(Fingerprint),
}

enum State {
    New,
    Running {
        command: LedgerCommand,
        store: Option<DelegatedStore>,
    },
    Finished(LedgerResponse),
}

pub struct LedgerInterpreter<C, T, R, E> {
    network: Network,
    state: State,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> LedgerInterpreter<C, T, R, E> {
    pub fn new() -> Self {
        Self {
            network: Network::Bitcoin,
            state: State::New,
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
        let command: LedgerCommand = command.into();
        let (transmit, store) = match command {
            LedgerCommand::GetMasterFingerprint => (
                Self::Transmit::from(command::get_master_fingerprint().encode()),
                None,
            ),
            _ => unimplemented!(),
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
                    return Ok(Some(Self::Transmit::from(
                        command::continue_interrupted(transmit).encode(),
                    )));
                } else {
                    return Err(LedgerError::Interrupted.into());
                }
            }
            match command {
                LedgerCommand::GetMasterFingerprint => {
                    if res.data.len() < 4 {
                        return Err(LedgerError::UnexpectedResult(command.clone(), res.data).into());
                    } else {
                        let mut fg = [0x00; 4];
                        fg.copy_from_slice(&res.data[0..4]);
                        self.state = State::Finished(LedgerResponse::MasterFingerprint(
                            Fingerprint::from(fg),
                        ));
                    }
                }
                _ => unimplemented!(),
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
