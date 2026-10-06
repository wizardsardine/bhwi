use crate::{HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    Interpreter,
    bitcoin::Network,
    common,
    passphrase::HostPassphrase,
    trezor::{TrezorCommand, TrezorError, TrezorInterpreter, TrezorResponse},
};

/// An asynchronous Trezor client with session-dependent passphrase entry.
pub struct Trezor<T> {
    /// The transport used for device exchanges.
    pub transport: T,
    network: Network,
    passphrase: Option<HostPassphrase>,
    on_device_passphrase: bool,
    is_emulated: bool,
}

impl<T> Trezor<T> {
    /// Creates a mainnet client defaulting to on-device passphrase entry.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            network: Network::Bitcoin,
            passphrase: None,
            on_device_passphrase: true,
            is_emulated: false,
        }
    }

    /// Sets the network used for key encoding, addresses, and signing.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Sets the normalized passphrase used when the session selects host entry.
    ///
    /// `None` uses an empty host passphrase. The limit is 50 normalized UTF-8 bytes.
    pub fn with_passphrase(mut self, passphrase: Option<HostPassphrase>) -> Self {
        self.passphrase = passphrase;
        self
    }

    /// Marks emulator sessions so unlock selects host passphrase entry.
    ///
    /// Emulators may advertise on-device entry without being able to collect input.
    pub fn with_emulator(mut self, is_emulated: bool) -> Self {
        self.is_emulated = is_emulated;
        self
    }
}

impl<C, T, R, E, F> crate::CommonInterface<C, T, R, E> for Trezor<F>
where
    C: TryInto<TrezorCommand, Error = TrezorError>,
    T: From<Vec<u8>>,
    R: From<TrezorResponse>,
    E: From<TrezorError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = TrezorError;
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
            TrezorInterpreter::default()
                .with_network(self.network)
                .with_passphrase(self.passphrase.clone())
                .with_on_device_passphrase(self.on_device_passphrase),
        )
    }
}

impl<T> crate::OnUnlock for Trezor<T> {
    fn on_unlock(&mut self, response: common::Response) -> Result<(), common::Error> {
        if let common::Response::Info(info) = response
            && let Some(on_device) = info.on_device_passphrase_entry
        {
            self.on_device_passphrase = on_device && !self.is_emulated;
        }
        Ok(())
    }
}

/// An unused HTTP client whose [`HttpClient::request`] implementation always panics.
///
/// Trezor commands do not use HTTP; this is not a fallback HTTP implementation.
pub struct DummyClient;
#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = TrezorError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("Trezor does not need http client")
    }
}
