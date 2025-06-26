use crate::{HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    coldcard::{
        encrypt, ColdcardCommand, ColdcardError, ColdcardInterpreter, ColdcardResponse,
        ColdcardTransmit,
    },
    Interpreter,
};

pub struct Coldcard<T> {
    pub transport: T,
    encryption: Option<encrypt::Engine>,
}

impl<T> Coldcard<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            encryption: None,
        }
    }
}

impl<'a, C, T, R, E, F> crate::Device<'a, C, T, R, E> for Coldcard<F>
where
    C: Into<ColdcardCommand<'a>>,
    T: From<ColdcardTransmit>,
    R: From<ColdcardResponse>,
    E: From<ColdcardError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = ColdcardError;
    fn components(
        &'a mut self,
    ) -> (
        &'a dyn Transport<Error = Self::TransportError>,
        &'a dyn HttpClient<Error = Self::HttpClientError>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        (
            &self.transport,
            &DummyClient {},
            ColdcardInterpreter::new(self.encryption.as_mut()),
        )
    }
}

pub struct DummyClient;
#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = ColdcardError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("Coldcard does not need http client")
    }
}
