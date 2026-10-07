use async_trait::async_trait;
use bhwi::{
    Interpreter,
    bitbox::{
        BitBoxCommand, BitBoxInterpreter, BitBoxResponse, BitBoxTransmit,
        error::BitBoxError,
        noise::{NoiseConfigData, NoiseState, PairingCodeHook},
    },
    bitcoin::Network,
    common,
};

use crate::{HttpClient, Transport};

/// The error message for a host passphrase supplied to a BitBox02.
pub const HOST_PASSPHRASE_REJECTED: &str = "The BitBox02 does not accept a passphrase from the host. Please enable the passphrase option and enter the passphrase on the device during unlock.";

/// An asynchronous BitBox02 client with persistent Noise-encryption state.
///
/// The caller is expected to:
///
/// 1. Construct with `BitBox::new(transport, load_persisted_config())`.
/// 2. Call `HWI::unlock(&mut bb, network).await?` to drive the handshake and pair.
///    While `pairing_code()` returns `Some`, the CLI/user must confirm the code on the
///    device; the `HWI::unlock` future resolves once the device replies.
/// 3. Persist `bb.noise_config_data()` externally for future sessions.
/// 4. Issue further HWI calls (`get_master_fingerprint`, ...).
pub struct BitBox<T> {
    /// The transport used for device exchanges.
    pub transport: T,
    /// The network used for key encoding, addresses, and signing.
    pub network: Network,
    noise: NoiseState,
}

impl<T> BitBox<T> {
    /// Creates a mainnet client with optional persisted Noise pairing data.
    ///
    /// Use `None` for first pairing and [`Self::with_network`] for other networks.
    pub fn new(transport: T, pairing_data: Option<NoiseConfigData>) -> Self {
        Self {
            transport,
            network: Network::Bitcoin,
            noise: NoiseState::new(pairing_data),
        }
    }

    /// Sets the network used for xpub encoding, address selection, and signing.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Returns the device's pairing code until confirmation, or `None` for cached pairing.
    pub fn pairing_code(&self) -> Option<&str> {
        self.noise.pairing_code()
    }

    /// Installs a hook called when a first-time pairing code becomes available.
    ///
    /// The hook runs synchronously inside `HWI::unlock` before waiting for device
    /// confirmation, so it must not block.
    ///
    /// If the device is already paired (matching `NoiseConfigData.device_static_pubkeys`),
    /// the hook is never called.
    pub fn set_pairing_code_hook(&mut self, hook: PairingCodeHook) {
        self.noise.set_pairing_code_hook(hook);
    }

    /// Returns a snapshot of the Noise pairing state for external persistence.
    pub fn noise_config_data(&self) -> NoiseConfigData {
        self.noise.data().clone()
    }

    /// Returns whether the current Noise session has completed pairing.
    pub fn is_paired(&self) -> bool {
        self.noise.is_paired()
    }
}

/// Feeds a `BitBoxCommand` straight into the interpreter, bypassing `common::Command`. Used
/// for BitBox-only operations that have no place in the shared HWI command surface.
struct RawCommand(BitBoxCommand);

impl TryFrom<RawCommand> for BitBoxCommand {
    type Error = BitBoxError;
    fn try_from(cmd: RawCommand) -> Result<Self, Self::Error> {
        Ok(cmd.0)
    }
}

impl<T: Transport> BitBox<T> {
    /// Restores from the mnemonic currently loaded on the device.
    ///
    /// This BitBox-specific operation seeds the simulator with its fixed test
    /// mnemonic. `timestamp` is Unix seconds; `timezone_offset` is seconds.
    pub async fn restore_from_mnemonic(
        &mut self,
        timestamp: u32,
        timezone_offset: i32,
    ) -> Result<(), BitBoxError> {
        self.run_bitbox(BitBoxCommand::RestoreFromMnemonic {
            timestamp,
            timezone_offset,
        })
        .await
        .map(|_| ())
    }

    /// Drive one BitBox-specific command through the interpreter and transport.
    async fn run_bitbox(&mut self, command: BitBoxCommand) -> Result<BitBoxResponse, BitBoxError> {
        use crate::CommonInterface;
        let (transport, _http, _host, mut interpreter) = <BitBox<T> as CommonInterface<
            RawCommand,
            BitBoxTransmit,
            BitBoxResponse,
            BitBoxError,
        >>::components(self);
        let transmit = interpreter.start(RawCommand(command))?;
        let exchange = transport
            .exchange(&transmit.payload, transmit.encrypted)
            .await
            .map_err(|e| transport_error(transport.error_kind(&e), format!("{e:?}")))?;
        let mut next = interpreter.exchange(exchange)?;
        while let Some(t) = next {
            // BitBox02 never talks to a pin server; every transmit targets the device.
            let exchange = transport
                .exchange(&t.payload, t.encrypted)
                .await
                .map_err(|e| transport_error(transport.error_kind(&e), format!("{e:?}")))?;
            next = interpreter.exchange(exchange)?;
        }
        interpreter.end()
    }
}

fn transport_error(kind: common::ErrorKind, message: String) -> BitBoxError {
    match kind {
        common::ErrorKind::Disconnected => BitBoxError::Disconnected(message),
        _ => BitBoxError::Transport(message),
    }
}

impl<C, T, R, E, F> crate::CommonInterface<C, T, R, E> for BitBox<F>
where
    C: TryInto<BitBoxCommand, Error = BitBoxError>,
    T: From<BitBoxTransmit>,
    R: From<BitBoxResponse>,
    E: From<BitBoxError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = BitBoxError;

    fn components(
        &mut self,
    ) -> (
        &mut (dyn Transport<Error = Self::TransportError> + '_),
        &(dyn HttpClient<Error = Self::HttpClientError> + '_),
        Option<&mut (dyn crate::HostInteraction + 'static)>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        let network = self.network;
        (
            &mut self.transport,
            &DummyClient,
            None,
            BitBoxInterpreter::new(&mut self.noise).with_network(network),
        )
    }
}

impl<T> crate::OnUnlock for BitBox<T> {
    fn on_unlock(&mut self, _response: common::Response) -> Result<(), common::Error> {
        Ok(())
    }
}

/// An unused HTTP client whose [`HttpClient::request`] implementation always panics.
///
/// BitBox02 commands do not use HTTP; this is not a fallback HTTP implementation.
pub struct DummyClient;

#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = BitBoxError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("BitBox02 does not use an HTTP client")
    }
}
