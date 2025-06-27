use crate::{HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    coldcard::{
        encrypt::{self, CryptoRngCore},
        ColdcardCommand, ColdcardError, ColdcardInterpreter, ColdcardResponse, ColdcardTransmit,
    },
    common, Interpreter,
};

pub struct Coldcard<T> {
    pub transport: T,
    encryption: encrypt::Engine,
}

impl<T> Coldcard<T> {
    pub fn new(transport: T, rng: &mut impl CryptoRngCore) -> Self {
        Self {
            transport,
            encryption: encrypt::Engine::new(rng),
        }
    }
}

impl<C, T, R, E, F> crate::Device<C, T, R, E> for Coldcard<F>
where
    C: TryInto<ColdcardCommand, Error = ColdcardError>,
    T: From<ColdcardTransmit>,
    R: From<ColdcardResponse>,
    E: From<ColdcardError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = ColdcardError;
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
            ColdcardInterpreter::new(&mut self.encryption),
        )
    }
}

impl<T> crate::OnUnlock for Coldcard<T> {
    fn on_unlock(&mut self, response: bhwi::common::Response) -> Result<(), common::Error> {
        if let bhwi::common::Response::EncryptionKey(key) = response {
            self.encryption.ready(key)?;
        }
        Ok(())
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
