use async_trait::async_trait;
use bhwi::{
    bitcoin::bip32::Fingerprint,
    ledger::{
        apdu::{ApduCommand, ApduError, ApduResponse},
        LedgerCommand, LedgerError as InterpreterError, LedgerInterpreter, LedgerResponse,
    },
    Interpreter,
};
use std::fmt::Debug;

#[async_trait]
pub trait LedgerTransport {
    type Error: Debug;
    async fn exchange(&self, command: &ApduCommand) -> Result<ApduResponse, Self::Error>;
}

#[derive(Debug)]
pub enum LedgerError<E> {
    Transport(E),
    Interpreter(InterpreterError),
}

impl<E> From<InterpreterError> for LedgerError<E> {
    fn from(value: InterpreterError) -> Self {
        Self::Interpreter(value)
    }
}

pub struct Ledger<T> {
    transport: T,
}

impl<T: LedgerTransport> Ledger<T> {
    async fn run_command<C, R>(&self, command: C) -> Result<R, LedgerError<T::Error>>
    where
        C: Into<LedgerCommand>,
        R: From<LedgerResponse>,
    {
        let mut intpr: LedgerInterpreter<C, ApduCommand, R, InterpreterError> =
            LedgerInterpreter::new();
        let transmit = intpr.start(command)?;
        let exchange = self
            .transport
            .exchange(&transmit)
            .await
            .map_err(LedgerError::Transport)?;
        let mut transmit = intpr.exchange(exchange.into())?;
        while let Some(t) = &transmit {
            let exchange = self
                .transport
                .exchange(t)
                .await
                .map_err(LedgerError::Transport)?;
            transmit = intpr.exchange(exchange.into())?;
        }
        let res = intpr.end().unwrap();
        Ok(res)
    }
}

impl<T: LedgerTransport> Ledger<T> {
    pub async fn get_master_fingerprint(&self) -> Result<Fingerprint, LedgerError<T::Error>> {
        if let LedgerResponse::MasterFingerprint(fg) = self
            .run_command::<LedgerCommand, LedgerResponse>(LedgerCommand::GetMasterFingerprint)
            .await?
        {
            Ok(fg)
        } else {
            Err(InterpreterError::NoErrorOrResult.into())
        }
    }
}
