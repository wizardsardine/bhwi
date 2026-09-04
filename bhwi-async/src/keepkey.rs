use crate::{HostInteraction, HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    Interpreter,
    bitcoin::Network,
    common,
    keepkey::{HostPassphrase, KeepKeyCommand, KeepKeyError, KeepKeyInterpreter, KeepKeyResponse},
};

pub struct KeepKey<T> {
    pub transport: T,
    network: Network,
    passphrase: Option<HostPassphrase>,
    host_interaction: Option<Box<dyn HostInteraction>>,
}

impl<T> KeepKey<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            network: Network::Bitcoin,
            passphrase: None,
            host_interaction: None,
        }
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn with_passphrase(mut self, passphrase: Option<HostPassphrase>) -> Self {
        self.passphrase = passphrase;
        self
    }

    pub fn with_host_interaction(mut self, interaction: Box<dyn HostInteraction>) -> Self {
        self.host_interaction = Some(interaction);
        self
    }
}

impl<C, T, R, E, F> crate::CommonInterface<C, T, R, E> for KeepKey<F>
where
    C: TryInto<KeepKeyCommand, Error = KeepKeyError>,
    T: From<Vec<u8>> + From<common::HostRequest>,
    R: From<KeepKeyResponse>,
    E: From<KeepKeyError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = KeepKeyError;

    fn components(
        &mut self,
    ) -> (
        &mut (dyn Transport<Error = Self::TransportError> + '_),
        &(dyn HttpClient<Error = Self::HttpClientError> + '_),
        Option<&mut (dyn HostInteraction + 'static)>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        (
            &mut self.transport,
            &DummyClient,
            self.host_interaction.as_deref_mut(),
            KeepKeyInterpreter::default()
                .with_network(self.network)
                .with_passphrase(self.passphrase.clone()),
        )
    }
}

impl<T> crate::OnUnlock for KeepKey<T> {
    fn on_unlock(&mut self, _response: common::Response) -> Result<(), common::Error> {
        Ok(())
    }
}

struct DummyClient;

#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = KeepKeyError;

    async fn request(&self, _url: &str, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("KeepKey does not need an HTTP client")
    }
}
