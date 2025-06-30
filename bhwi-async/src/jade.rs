use crate::{HttpClient, Transport};
use bhwi::{
    bitcoin::Network,
    jade::{JadeCommand, JadeError, JadeInterpreter, JadeResponse, JadeTransmit},
    Interpreter,
};

pub struct Jade<T, S> {
    pub network: Network,
    pub transport: T,
    pub pinserver: S,
}

impl<T, S> Jade<T, S> {
    pub fn new(network: Network, transport: T, pinserver: S) -> Self {
        Self {
            network,
            transport,
            pinserver,
        }
    }
}

impl<C, T, R, E, F, H> crate::Device<C, T, R, E> for Jade<F, H>
where
    C: Into<JadeCommand>,
    T: From<JadeTransmit>,
    R: From<JadeResponse>,
    E: From<JadeError>,
    F: Transport,
    H: HttpClient,
{
    type TransportError = F::Error;
    type HttpClientError = H::Error;
    fn components(
        &mut self,
    ) -> (
        &mut dyn Transport<Error = Self::TransportError>,
        &dyn HttpClient<Error = Self::HttpClientError>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        (
            &mut self.transport,
            &self.pinserver,
            JadeInterpreter::default().with_network(self.network),
        )
    }
}

impl<T, S> crate::OnUnlock for Jade<T, S> {
    fn on_unlock(&mut self, _response: bhwi::common::Response) -> Result<(), bhwi::common::Error> {
        Ok(())
    }
}
