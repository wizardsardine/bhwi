use async_trait::async_trait;
use bhwi::{
    Interpreter,
    bitbox::{
        BitBoxCommand, BitBoxInterpreter, BitBoxResponse,
        error::BitBoxError,
        noise::{NoiseConfigData, NoiseState, PairingCodeHook},
    },
    bitcoin::Network,
    common,
};

use crate::{HttpClient, Transport};

/// Async BitBox02 client. Holds the noise-encryption state that persists across
/// interpreter invocations. The caller is expected to:
///
/// 1. Construct with `BitBox::new(transport, load_persisted_config())`.
/// 2. Call `HWI::unlock(&mut bb, network).await?` to drive the handshake and pair.
///    While `pairing_code()` returns `Some`, the CLI/user must confirm the code on the
///    device; the `HWI::unlock` future resolves once the device replies.
/// 3. Persist `bb.noise_config_data()` externally for future sessions.
/// 4. Issue further HWI calls (`get_master_fingerprint`, ...).
pub struct BitBox<T> {
    pub transport: T,
    pub network: Network,
    noise: NoiseState,
}

impl<T> BitBox<T> {
    /// `pairing_data` is `None` on first pair; on reconnect, pass the previously persisted
    /// noise config data back in. Defaults to mainnet; use [`BitBox::with_network`] for
    /// testnet/signet.
    pub fn new(transport: T, pairing_data: Option<NoiseConfigData>) -> Self {
        Self {
            transport,
            network: Network::Bitcoin,
            noise: NoiseState::new(pairing_data),
        }
    }

    /// Set the network used for xpub encoding, address/coin selection and signing.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Pairing code shown on the device screen. Returns `None` once pairing has been confirmed
    /// (or if the device was already paired from cached data).
    pub fn pairing_code(&self) -> Option<&str> {
        self.noise.pairing_code()
    }

    /// Install a hook that fires the moment the pairing code becomes available during a
    /// first-time pair — i.e. right before the interpreter blocks on the device's
    /// verification response. The hook runs synchronously inside `HWI::unlock`, so it must
    /// be non-blocking. Typical uses: `eprintln!`, `log::info!`, or sending on a channel.
    ///
    /// If the device is already paired (matching `NoiseConfigData.device_static_pubkeys`),
    /// the hook is never called.
    pub fn set_pairing_code_hook(&mut self, hook: PairingCodeHook) {
        self.noise.set_pairing_code_hook(hook);
    }

    /// Snapshot the noise-pairing state so the caller can persist it externally.
    pub fn noise_config_data(&self) -> NoiseConfigData {
        self.noise.data().clone()
    }

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
    /// Restore the device from the mnemonic currently loaded on it. This is BitBox-specific
    /// and intentionally not part of the shared `HWI` trait; its purpose here is to seed the
    /// BitBox02 simulator with its fixed test mnemonic so derived keys are deterministic.
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
        let (transport, _http, mut interpreter) = <BitBox<T> as CommonInterface<
            RawCommand,
            common::Transmit,
            BitBoxResponse,
            BitBoxError,
        >>::components(self);
        let transmit = interpreter.start(RawCommand(command))?;
        let exchange = transport
            .exchange(&transmit.payload, transmit.encrypted)
            .await
            .map_err(|e| BitBoxError::Transport(format!("{e:?}")))?;
        let mut next = interpreter.exchange(exchange)?;
        while let Some(t) = next {
            // BitBox02 never talks to a pin server; every transmit targets the device.
            let exchange = transport
                .exchange(&t.payload, t.encrypted)
                .await
                .map_err(|e| BitBoxError::Transport(format!("{e:?}")))?;
            next = interpreter.exchange(exchange)?;
        }
        interpreter.end()
    }
}

impl<C, T, R, E, F> crate::CommonInterface<C, T, R, E> for BitBox<F>
where
    C: TryInto<BitBoxCommand, Error = BitBoxError>,
    T: From<common::Transmit>,
    R: From<BitBoxResponse>,
    E: From<BitBoxError>,
    F: Transport,
{
    type TransportError = F::Error;
    type HttpClientError = BitBoxError;

    fn components(
        &mut self,
    ) -> (
        &mut dyn Transport<Error = Self::TransportError>,
        &dyn HttpClient<Error = Self::HttpClientError>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    ) {
        let network = self.network;
        (
            &mut self.transport,
            &DummyClient,
            BitBoxInterpreter::new(&mut self.noise).with_network(network),
        )
    }
}

impl<T> crate::OnUnlock for BitBox<T> {
    fn on_unlock(&mut self, _response: common::Response) -> Result<(), common::Error> {
        Ok(())
    }
}

pub struct DummyClient;

#[async_trait(?Send)]
impl HttpClient for DummyClient {
    type Error = BitBoxError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("BitBox02 does not use an HTTP client")
    }
}
