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

impl<F, S, C, T, R, E> crate::Device<C, T, R, E> for Jade<F, S>
where
    C: Into<JadeCommand>,
    T: From<JadeTransmit>,
    R: From<JadeResponse>,
    E: From<JadeError>,
{
    fn interpreter(&self) -> impl Interpreter<Command = C, Transmit = T, Response = R, Error = E> {
        JadeInterpreter::default().with_network(self.network)
    }
}

#[async_trait(?Send)]
impl<T, S, E> Transport for Jade<T, S>
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
impl<T, S> HttpClient for Jade<T, S>
where
    S: HttpClient,
{
    type Error = S::Error;
    async fn request(&self, url: &str, req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.pinserver.request(url, req).await
    }
}
