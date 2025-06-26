use std::fmt::Debug;

use crate::{HttpClient, Transport};
use async_trait::async_trait;
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

impl<'a, C, T, R, E, F, H> crate::Device<'a, C, T, R, E> for Jade<F, H>
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
        &'a mut self,
    ) -> (
        &'a dyn Transport<Error = Self::TransportError>,
        &'a dyn HttpClient<Error = Self::HttpClientError>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        (
            &self.transport,
            &self.pinserver,
            JadeInterpreter::default().with_network(self.network),
        )
    }
}
