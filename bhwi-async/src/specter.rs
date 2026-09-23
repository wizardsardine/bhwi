//! Async wrapper for the sans-I/O Specter-DIY interpreter.

use crate::{HttpClient, Transport};
use async_trait::async_trait;
use bhwi::{
    Interpreter,
    bitcoin::Network,
    common,
    specter::{SpecterCommand, SpecterError, SpecterInterpreter, SpecterResponse, SpecterTransmit},
};

/// Specter-DIY client with the network selected by its caller.
///
/// Specter-DIY selects its active network on-device. The network here is used
/// to validate responses whose encoding carries network information.
pub struct Specter<T> {
    pub transport: T,
    network: Network,
}

impl<T> Specter<T> {
    pub fn new(network: Network, transport: T) -> Self {
        Self { transport, network }
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }
}

impl<C, T, R, E, F> crate::CommonInterface<C, T, R, E> for Specter<F>
where
    C: TryInto<SpecterCommand, Error = SpecterError>,
    T: From<SpecterTransmit>,
    R: From<SpecterResponse>,
    E: From<SpecterError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = SpecterError;

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
            &DummyClient,
            None,
            SpecterInterpreter::default().with_network(self.network),
        )
    }
}

impl<T> crate::OnUnlock for Specter<T> {
    fn on_unlock(&mut self, _response: common::Response) -> Result<(), common::Error> {
        Ok(())
    }
}

struct DummyClient;

#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = SpecterError;

    async fn request(&self, _url: &str, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("Specter-DIY does not use HTTP")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HWI;
    use futures::executor::block_on;
    use std::convert::Infallible;

    struct ScriptedTransport {
        request: Option<Vec<u8>>,
        response: Vec<u8>,
    }

    #[async_trait(?Send)]
    impl Transport for ScriptedTransport {
        type Error = Infallible;

        async fn exchange(
            &mut self,
            request: &[u8],
            encrypted: bool,
        ) -> Result<Vec<u8>, Self::Error> {
            assert!(!encrypted);
            self.request = Some(request.to_vec());
            Ok(self.response.clone())
        }
    }

    #[test]
    fn wrapper_drives_the_common_specter_interpreter() {
        let transport = ScriptedTransport {
            request: None,
            response: b"ACK\r\ndeadbeef\r\n".to_vec(),
        };
        let mut specter = Specter::new(Network::Testnet, transport);

        let fingerprint = block_on(specter.get_master_fingerprint()).unwrap();

        assert_eq!(fingerprint.to_string(), "deadbeef");
        assert_eq!(
            specter.transport.request.as_deref(),
            Some(b"\r\n\r\nfingerprint\r\n".as_slice())
        );
    }

    #[test]
    fn wrapper_retains_the_selected_network() {
        let specter = Specter::new(
            Network::Bitcoin,
            ScriptedTransport {
                request: None,
                response: Vec::new(),
            },
        )
        .with_network(Network::Signet);

        assert_eq!(specter.network, Network::Signet);
    }
}
