use crate::{HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    Interpreter,
    ledger::{LedgerCommand, LedgerError, LedgerInterpreter, LedgerResponse, apdu::ApduCommand},
};

/// An asynchronous client for the Ledger Bitcoin application.
pub struct Ledger<T> {
    /// The transport used for device exchanges.
    pub transport: T,
}

impl<T> Ledger<T> {
    /// Creates a client without contacting or unlocking the device.
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
        &mut (dyn Transport<Error = Self::TransportError> + '_),
        &(dyn HttpClient<Error = Self::HttpClientError> + '_),
        Option<&mut (dyn crate::HostInteraction + 'static)>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        (
            &mut self.transport,
            &DummyClient {},
            None,
            LedgerInterpreter::default(),
        )
    }
}

impl<T> crate::OnUnlock for Ledger<T> {
    fn on_unlock(&mut self, _response: bhwi::common::Response) -> Result<(), bhwi::common::Error> {
        Ok(())
    }
}

/// An unused HTTP client whose [`HttpClient::request`] implementation always panics.
///
/// Ledger commands do not use HTTP; this is not a fallback HTTP implementation.
pub struct DummyClient;
#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = LedgerError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("Ledger does not need http client")
    }
}
