use std::fmt::Debug;

use crate::{HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    ledger::{apdu::ApduCommand, LedgerCommand, LedgerError, LedgerInterpreter, LedgerResponse},
    Interpreter,
};

pub struct Ledger<T> {
    pub transport: T,
}

impl<T> Ledger<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<'a, F, C, T, R, E> crate::Device<'a, C, T, R, E> for Ledger<F>
where
    C: Into<LedgerCommand<'a>>,
    T: From<ApduCommand>,
    R: From<LedgerResponse>,
    E: From<LedgerError>,
{
    fn interpreter(&self) -> impl Interpreter<Command = C, Transmit = T, Response = R, Error = E> {
        LedgerInterpreter::default()
    }
}

#[async_trait(?Send)]
impl<T, E> Transport for Ledger<T>
where
    E: Debug,
    T: Transport<Error = E>,
{
    type Error = T::Error;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.transport.exchange(command).await
    }
}

#[async_trait(?Send)]
impl<T> HttpClient for Ledger<T> {
    type Error = LedgerError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("Ledger does not need http client")
    }
}
