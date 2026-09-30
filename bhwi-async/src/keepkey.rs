use crate::{HostInteraction, HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    Interpreter,
    bitcoin::Network,
    common,
    keepkey::{KeepKeyCommand, KeepKeyError, KeepKeyInterpreter, KeepKeyResponse},
    passphrase::HostPassphrase,
};

/// An asynchronous KeepKey client with optional host passphrase and input handling.
pub struct KeepKey<T> {
    /// The transport used for device exchanges.
    pub transport: T,
    network: Network,
    passphrase: Option<HostPassphrase>,
    host_interaction: Option<Box<dyn HostInteraction>>,
}

impl<T> KeepKey<T> {
    /// Creates a mainnet client with no host passphrase or input handler.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            network: Network::Bitcoin,
            passphrase: None,
            host_interaction: None,
        }
    }

    /// Sets the network used for key encoding, addresses, and signing.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Sets the normalized host passphrase; `None` uses an empty host passphrase.
    ///
    /// KeepKey defaults to host entry and limits passphrases to 50 normalized UTF-8 bytes.
    pub fn with_passphrase(mut self, passphrase: Option<HostPassphrase>) -> Self {
        self.passphrase = passphrase;
        self
    }

    /// Attaches a handler for mid-command PIN and recovery input requests.
    pub fn with_host_interaction(mut self, interaction: Box<dyn HostInteraction>) -> Self {
        self.host_interaction = Some(interaction);
        self
    }
}

impl<C, T, R, E, F> crate::CommonInterface<C, T, R, E> for KeepKey<F>
where
    C: TryInto<KeepKeyCommand, Error = bhwi::trezor::TrezorError>,
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
