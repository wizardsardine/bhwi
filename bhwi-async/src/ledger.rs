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

impl<C, T, R, E, F> crate::CommonInterface<C, T, R, E> for Ledger<F>
where
    C: TryInto<LedgerCommand, Error = LedgerError>,
    T: From<ApduCommand>,
    R: From<LedgerResponse>,
    E: From<LedgerError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = LedgerError;
    fn components(
        &mut self,
    ) -> (
        &mut dyn Transport<Error = Self::TransportError>,
        &dyn HttpClient<Error = Self::HttpClientError>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        (
            &mut self.transport,
            &DummyClient {},
            LedgerInterpreter::default(),
        )
    }
}

impl<T> crate::OnUnlock for Ledger<T> {
    fn on_unlock(&mut self, _response: bhwi::common::Response) -> Result<(), bhwi::common::Error> {
        Ok(())
    }
}

pub struct DummyClient;
#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = LedgerError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("Coldcard does not need http client")
    }
}
