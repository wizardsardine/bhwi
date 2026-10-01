//! Asynchronous hardware-wallet operations over caller-provided transports.
//!
//! [`HWI`] preserves backend error types; [`HWIDevice`] provides an object-safe,
//! error-erased interface. The asynchronous traits use `async_trait(?Send)`:
//! their futures need not be `Send`, and no particular async runtime is required.
//!
//! Shared command types are reexported from `bhwi::common`, including typed
//! host requests and responses for [`HostInteraction`] implementations.

/// BitBox02 sessions and pairing.
#[cfg(feature = "bitbox")]
pub mod bitbox;
/// Coldcard sessions.
#[cfg(feature = "coldcard")]
pub mod coldcard;
/// Standard descriptor and keypool construction.
pub mod descriptors;
/// Device discovery, selection, and cached metadata.
pub mod device;
/// Address-display requests prepared from descriptors.
pub mod display_address;
/// Jade sessions and PIN-server integration.
#[cfg(feature = "jade")]
pub mod jade;
/// KeepKey sessions and host interaction.
#[cfg(feature = "keepkey")]
pub mod keepkey;
/// Ledger sessions.
#[cfg(feature = "ledger")]
pub mod ledger;
/// Device-specific setup, recovery, and PIN contexts.
#[cfg(any(feature = "bitbox", feature = "keepkey", feature = "trezor"))]
pub mod management;
/// PSBT input cleanup and signature accumulation.
pub mod psbt;
/// Message-signature encoding and device-specific signing preparation.
pub mod signing;
#[cfg(feature = "specter")]
pub mod specter;
/// Framing adapters over caller-provided I/O channels.
pub mod transport;
/// Trezor sessions and host interaction.
#[cfg(feature = "trezor")]
pub mod trezor;

use std::{error::Error as StdError, fmt::Debug, str::FromStr};

use async_trait::async_trait;
pub use bhwi::common::DeviceBackup;
pub use bhwi::common::DeviceContext;
pub use bhwi::common::DisplayAddress;
pub use bhwi::common::ErrorKind;
pub use bhwi::common::Info;
pub use bhwi::common::RestoreOptions;
pub use bhwi::common::SetupOptions;
pub use bhwi::common::WalletRegistration;
pub use bhwi::common::{Error as HostError, HostRequest, HostResponse, PinMatrixRequestKind};
pub use bhwi::common::{MultisigAddressType, MultisigDisplayAddress};
use bhwi::miniscript::descriptor::WalletPolicy;
#[cfg(any(feature = "trezor", feature = "keepkey"))]
pub use bhwi::passphrase::HostPassphrase;
use bhwi::{
    Interpreter,
    bitcoin::{
        Network,
        bip32::{DerivationPath, Fingerprint, Xpub},
        psbt::Psbt,
        secp256k1::ecdsa::Signature,
    },
    common::{self},
};
/// The asynchronous Jade client.
#[cfg(feature = "jade")]
pub use jade::Jade;
/// The asynchronous KeepKey client.
#[cfg(feature = "keepkey")]
pub use keepkey::KeepKey;
/// The asynchronous Ledger client.
#[cfg(feature = "ledger")]
pub use ledger::Ledger;
/// The asynchronous Specter-DIY client.
#[cfg(feature = "specter")]
pub use specter::Specter;
/// The asynchronous Trezor client.
#[cfg(feature = "trezor")]
pub use trezor::Trezor;

/// Exchanges already-encoded interpreter payloads with a device.
///
/// Implementations provide framing and I/O, not interpreter-level encryption.
/// Futures need not be `Send`; the trait does not select an async runtime.
#[async_trait(?Send)]
pub trait Transport {
    /// An I/O or framing failure.
    type Error: Debug;
    /// Sends a payload and returns the device response.
    ///
    /// `encrypted` identifies an already-encrypted payload for framing purposes;
    /// it is not a request to encrypt `command` again.
    async fn exchange(&mut self, command: &[u8], encrypted: bool) -> Result<Vec<u8>, Self::Error>;

    /// Returns whether the backend classifies `error` as a post-write read failure.
    ///
    /// Commands that allow a final disconnect may treat this classification as
    /// success. BitBox includes timeouts and short reports; `true` proves neither
    /// that the device disconnected nor that its action completed.
    fn is_post_write_disconnect(&self, _error: &Self::Error) -> bool {
        false
    }

    /// Returns the kind of `error`; defaults to [`ErrorKind::Transport`].
    fn error_kind(&self, _error: &Self::Error) -> ErrorKind {
        ErrorKind::Transport
    }
}

/// Sends interpreter PIN-server requests using caller-provided HTTP I/O.
///
/// Futures need not be `Send`; the trait does not select an async runtime.
#[async_trait(?Send)]
pub trait HttpClient {
    /// An HTTP request failure.
    type Error: Debug;
    /// Sends the encoded request to `url` and returns the encoded response body.
    async fn request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Returns the kind of `error`; defaults to [`ErrorKind::Transport`].
    fn error_kind(&self, _error: &Self::Error) -> ErrorKind {
        ErrorKind::Transport
    }
}

/// Collects typed user input requested by a device.
///
/// Futures need not be `Send`. The command driver validates and encodes returned
/// responses with [`HostResponse::into_bytes_for`].
#[async_trait(?Send)]
pub trait HostInteraction {
    /// Returns input for `request`, or an error such as cancellation.
    async fn respond(
        &mut self,
        request: &common::HostRequest,
    ) -> Result<common::HostResponse, common::Error>;
}

/// Asynchronous wallet operations with a backend-specific error type.
///
/// Support and required [`DeviceContext`] values vary by device. Unsupported
/// operations and missing context return errors. Futures need not be `Send`,
/// and the trait does not select an async runtime.
#[async_trait(?Send)]
pub trait HWI {
    /// A device, transport, or host-interaction failure.
    type Error: Debug;
    /// Requests a device backup, which need not produce a downloadable file.
    async fn backup_device(&mut self) -> Result<DeviceBackup, Self::Error>;
    /// Initializes a device using options and any required caller-supplied context.
    async fn setup_device(
        &mut self,
        options: SetupOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, Self::Error>;
    /// Requests a device wipe and returns the reported or assumed outcome.
    ///
    /// Qualifying post-write read errors are treated as `Ok(true)` without
    /// confirming the wipe. On BitBox this includes timeouts and short reports,
    /// even on the initial information query before the wipe request is sent.
    async fn wipe_device(&mut self) -> Result<bool, Self::Error>;
    /// Restores a device using options and any required recovery context.
    async fn restore_device(
        &mut self,
        options: RestoreOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, Self::Error>;
    /// Requests a passphrase-protection toggle and returns the backend's outcome.
    ///
    /// KeepKey can return `true` while awaiting PIN entry, before the setting changes.
    async fn toggle_passphrase(&mut self) -> Result<bool, Self::Error>;
    /// Requests PIN entry and returns whether the prompt was accepted.
    async fn prompt_pin(&mut self) -> Result<bool, Self::Error>;
    /// Submits scrambled keypad positions supplied in the device-specific context.
    async fn send_pin(&mut self, context: Option<DeviceContext>) -> Result<bool, Self::Error>;
    /// Runs the backend's initialization or unlock handshake for `network`.
    ///
    /// This may involve device or host interaction. Trezor and KeepKey initialization
    /// can succeed while a PIN is still required; `Ok(())` does not guarantee an
    /// unlocked wallet.
    async fn unlock(&mut self, network: Network) -> Result<(), Self::Error>;
    /// Returns device information, which may be synthesized by the backend.
    async fn get_info(&mut self) -> Result<Info, Self::Error>;
    /// Returns the master fingerprint of the currently selected wallet.
    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, Self::Error>;
    /// Derives an extended public key, optionally requesting on-device display.
    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, Self::Error>;
    /// Signs a message and returns the backend's header and ECDSA signature.
    async fn sign_message(
        &mut self,
        message: &[u8],
        path: DerivationPath,
    ) -> Result<(u8, Signature), Self::Error>;
    /// Displays an address using any backend-required policy or registration context.
    async fn display_address(
        &mut self,
        address: common::DisplayAddress,
        context: Option<common::DeviceContext>,
    ) -> Result<String, Self::Error>;
    /// Registers a named wallet policy, possibly leaving user confirmation pending.
    async fn register_wallet(
        &mut self,
        name: &str,
        policy: &str,
    ) -> Result<WalletRegistration, Self::Error>;
    /// Signs a PSBT using any backend-required context and returns the updated PSBT.
    ///
    /// Ledger requires a Ledger context even for a policy without a registration HMAC.
    async fn sign_tx(
        &mut self,
        psbt: Psbt,
        context: Option<common::DeviceContext>,
    ) -> Result<Psbt, Self::Error>;
}

// TODO: this will become a pain to maintain, but we can have a proc-macro
// generate this trait by putting it over HWI's definition and then also
// generate the blanket impl which will map the errors to HWIDeviceError
/// Object-safe wallet operations with errors erased into [`HWIDeviceError`].
///
/// The blanket implementation delegates to [`HWI`]. Support and context
/// requirements remain backend-specific; futures need not be `Send`.
#[async_trait(?Send)]
pub trait HWIDevice {
    /// Requests a device backup, which need not produce a downloadable file.
    async fn backup_device(&mut self) -> Result<DeviceBackup, HWIDeviceError>;
    /// Initializes a device using options and any required caller-supplied context.
    async fn setup_device(
        &mut self,
        options: SetupOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, HWIDeviceError>;
    /// Requests a device wipe and returns the reported or assumed outcome.
    ///
    /// Qualifying post-write read errors are treated as `Ok(true)` without
    /// confirming the wipe. On BitBox this includes timeouts and short reports,
    /// even on the initial information query before the wipe request is sent.
    async fn wipe_device(&mut self) -> Result<bool, HWIDeviceError>;
    /// Restores a device using options and any required recovery context.
    async fn restore_device(
        &mut self,
        options: RestoreOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, HWIDeviceError>;
    /// Requests a passphrase-protection toggle and returns the backend's outcome.
    ///
    /// KeepKey can return `true` while awaiting PIN entry, before the setting changes.
    async fn toggle_passphrase(&mut self) -> Result<bool, HWIDeviceError>;
    /// Requests PIN entry and returns whether the prompt was accepted.
    async fn prompt_pin(&mut self) -> Result<bool, HWIDeviceError>;
    /// Submits scrambled keypad positions supplied in the device-specific context.
    async fn send_pin(&mut self, context: Option<DeviceContext>) -> Result<bool, HWIDeviceError>;
    /// Runs the backend's initialization or unlock handshake for `network`.
    ///
    /// This may involve device or host interaction. Trezor and KeepKey initialization
    /// can succeed while a PIN is still required; `Ok(())` does not guarantee an
    /// unlocked wallet.
    async fn unlock(&mut self, network: Network) -> Result<(), HWIDeviceError>;
    /// Returns device information, which may be synthesized by the backend.
    async fn get_info(&mut self) -> Result<Info, HWIDeviceError>;
    /// Returns the master fingerprint of the currently selected wallet.
    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, HWIDeviceError>;
    /// Derives an extended public key, optionally requesting on-device display.
    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, HWIDeviceError>;
    /// Signs a message and returns the backend's header and ECDSA signature.
    async fn sign_message(
        &mut self,
        message: &[u8],
        path: DerivationPath,
    ) -> Result<(u8, Signature), HWIDeviceError>;
    /// Displays an address using any backend-required policy or registration context.
    async fn display_address(
        &mut self,
        address: common::DisplayAddress,
        context: Option<common::DeviceContext>,
    ) -> Result<String, HWIDeviceError>;
    /// Registers a named wallet policy, possibly leaving user confirmation pending.
    async fn register_wallet(
        &mut self,
        name: &str,
        policy: &str,
    ) -> Result<WalletRegistration, HWIDeviceError>;
    /// Signs a PSBT using any backend-required context and returns the updated PSBT.
    ///
    /// Ledger requires a Ledger context even for a policy without a registration HMAC.
    async fn sign_tx(
        &mut self,
        psbt: Psbt,
        context: Option<common::DeviceContext>,
    ) -> Result<Psbt, HWIDeviceError>;
}

/// An erased wallet-operation error that retains the original error as its source.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct HWIDeviceError {
    #[source]
    error: Box<dyn StdError + Send + Sync + 'static>,
    kind: Option<ErrorKind>,
}

impl HWIDeviceError {
    /// Wraps a backend error while retaining its error chain.
    pub fn new(error: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            error: Box::new(error),
            kind: None,
        }
    }

    /// Creates an erased error with an explicit kind.
    pub fn with_kind(error: impl StdError + Send + Sync + 'static, kind: ErrorKind) -> Self {
        Self {
            kind: Some(kind),
            ..Self::new(error)
        }
    }

    /// Returns the kind set on this error, or else the first one in its source chain.
    pub fn kind(&self) -> Option<ErrorKind> {
        if self.kind.is_some() {
            return self.kind;
        }
        let mut source: Option<&(dyn StdError + 'static)> = Some(self.error.as_ref());
        while let Some(current) = source {
            if let Some(error) = current.downcast_ref::<common::Error>() {
                return Some(error.kind());
            }
            if let Some(kind) = current
                .downcast_ref::<HWIDeviceError>()
                .and_then(Self::kind)
            {
                return Some(kind);
            }
            source = current.source();
        }
        None
    }
}

impl From<Box<dyn StdError + Send + Sync + 'static>> for HWIDeviceError {
    fn from(error: Box<dyn StdError + Send + Sync + 'static>) -> Self {
        Self { error, kind: None }
    }
}

/// An error that reports its [`ErrorKind`].
pub trait ErrorKindOf {
    /// Returns the error's kind.
    fn error_kind(&self) -> ErrorKind;
}

impl ErrorKindOf for common::Error {
    fn error_kind(&self) -> ErrorKind {
        self.kind()
    }
}

/// A failure while driving a common command through its interpreter and I/O.
#[derive(Debug, thiserror::Error)]
pub enum Error<E, F> {
    /// A device transport failure.
    #[error("transport error: {error}")]
    Transport {
        /// The failure kind.
        kind: ErrorKind,
        /// The transport's error.
        error: E,
    },

    /// A PIN-server HTTP failure.
    #[error("http client error: {error}")]
    HttpClient {
        /// The failure kind.
        kind: ErrorKind,
        /// The HTTP client's error.
        error: F,
    },

    /// An interpreter or host-interaction failure.
    #[error("{0}")]
    Interpreter(
        /// The command or input error.
        #[from]
        common::Error,
    ),
}

impl<E, F> Error<E, F> {
    /// Returns the failure kind from whichever layer failed.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Transport { kind, .. } | Self::HttpClient { kind, .. } => *kind,
            Self::Interpreter(error) => error.kind(),
        }
    }
}

impl<E, F> ErrorKindOf for Error<E, F> {
    fn error_kind(&self) -> ErrorKind {
        self.kind()
    }
}

fn kinded<E>(error: E) -> HWIDeviceError
where
    E: ErrorKindOf + StdError + Send + Sync + 'static,
{
    let kind = error.error_kind();
    HWIDeviceError::with_kind(error, kind)
}

#[async_trait(?Send)]
impl<D> HWI for D
where
    D: CommonInterface<common::Command, common::Transmit, common::Response, common::Error>
        + OnUnlock,
{
    type Error = Error<D::TransportError, D::HttpClientError>;
    async fn backup_device(&mut self) -> Result<DeviceBackup, Self::Error> {
        if let common::Response::Backup(backup) = run_command(self, common::Command::Backup).await?
        {
            Ok(backup)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn setup_device(
        &mut self,
        options: SetupOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, Self::Error> {
        if let common::Response::DeviceAction(success) =
            run_command(self, common::Command::Setup(options, context)).await?
        {
            Ok(success)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn wipe_device(&mut self) -> Result<bool, Self::Error> {
        if let common::Response::DeviceAction(success) =
            run_command_allowing_final_disconnect(self, common::Command::Wipe).await?
        {
            Ok(success)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn restore_device(
        &mut self,
        options: RestoreOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, Self::Error> {
        if let common::Response::DeviceAction(success) =
            run_command(self, common::Command::Restore(options, context)).await?
        {
            Ok(success)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn toggle_passphrase(&mut self) -> Result<bool, Self::Error> {
        if let common::Response::DeviceAction(success) =
            run_command(self, common::Command::TogglePassphrase).await?
        {
            Ok(success)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn prompt_pin(&mut self) -> Result<bool, Self::Error> {
        if let common::Response::DeviceAction(success) =
            run_command(self, common::Command::PromptPin).await?
        {
            Ok(success)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn send_pin(&mut self, context: Option<DeviceContext>) -> Result<bool, Self::Error> {
        if let common::Response::DeviceAction(success) =
            run_command(self, common::Command::SendPin(context)).await?
        {
            Ok(success)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn unlock(&mut self, network: Network) -> Result<(), Self::Error> {
        let res = run_command(
            self,
            common::Command::Unlock {
                options: common::UnlockOptions {
                    network: Some(network),
                },
            },
        )
        .await?;
        self.on_unlock(res)?;
        Ok(())
    }

    async fn get_info(&mut self) -> Result<Info, Self::Error> {
        if let common::Response::Info(version) =
            run_command(self, common::Command::GetVersion).await?
        {
            Ok(version)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, Self::Error> {
        if let common::Response::MasterFingerprint(fg) =
            run_command(self, common::Command::GetMasterFingerprint).await?
        {
            Ok(fg)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, Self::Error> {
        if let common::Response::Xpub(xpub) =
            run_command(self, common::Command::GetXpub { path, display }).await?
        {
            Ok(xpub)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn sign_message(
        &mut self,
        message: &[u8],
        path: DerivationPath,
    ) -> Result<(u8, Signature), Self::Error> {
        if let common::Response::Signature(header, signature) = run_command(
            self,
            common::Command::SignMessage {
                message: message.to_vec(),
                path,
            },
        )
        .await?
        {
            Ok((header, signature))
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn display_address(
        &mut self,
        address: common::DisplayAddress,
        context: Option<common::DeviceContext>,
    ) -> Result<String, Self::Error> {
        if let common::Response::Address(addr) =
            run_command(self, common::Command::DisplayAddress(address, context)).await?
        {
            Ok(addr)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn register_wallet(
        &mut self,
        name: &str,
        policy: &str,
    ) -> Result<WalletRegistration, Self::Error> {
        let wallet_policy = WalletPolicy::from_str(policy)
            .map_err(|e| common::Error::new(ErrorKind::Serialization, e.to_string()))?;
        if let common::Response::WalletRegistration(registration) = run_command(
            self,
            common::Command::RegisterWallet {
                name: name.to_string(),
                policy: wallet_policy,
            },
        )
        .await?
        {
            Ok(registration)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }

    async fn sign_tx(
        &mut self,
        psbt: Psbt,
        context: Option<common::DeviceContext>,
    ) -> Result<Psbt, Self::Error> {
        if let common::Response::SignedPsbt(psbt) =
            run_command(self, common::Command::SignTx(psbt, context)).await?
        {
            Ok(psbt)
        } else {
            Err(
                common::Error::new(ErrorKind::UnexpectedResponse, "no error or result returned")
                    .into(),
            )
        }
    }
}

#[async_trait(?Send)]
impl<T> HWIDevice for T
where
    T: HWI,
    T::Error: ErrorKindOf + StdError + Send + Sync + 'static,
{
    async fn backup_device(&mut self) -> Result<DeviceBackup, HWIDeviceError> {
        HWI::backup_device(self).await.map_err(kinded)
    }

    async fn setup_device(
        &mut self,
        options: SetupOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, HWIDeviceError> {
        HWI::setup_device(self, options, context)
            .await
            .map_err(kinded)
    }

    async fn wipe_device(&mut self) -> Result<bool, HWIDeviceError> {
        HWI::wipe_device(self).await.map_err(kinded)
    }

    async fn restore_device(
        &mut self,
        options: RestoreOptions,
        context: Option<DeviceContext>,
    ) -> Result<bool, HWIDeviceError> {
        HWI::restore_device(self, options, context)
            .await
            .map_err(kinded)
    }

    async fn toggle_passphrase(&mut self) -> Result<bool, HWIDeviceError> {
        HWI::toggle_passphrase(self).await.map_err(kinded)
    }

    async fn prompt_pin(&mut self) -> Result<bool, HWIDeviceError> {
        HWI::prompt_pin(self).await.map_err(kinded)
    }

    async fn send_pin(&mut self, context: Option<DeviceContext>) -> Result<bool, HWIDeviceError> {
        HWI::send_pin(self, context).await.map_err(kinded)
    }

    async fn unlock(&mut self, network: Network) -> Result<(), HWIDeviceError> {
        HWI::unlock(self, network).await.map_err(kinded)
    }

    async fn get_info(&mut self) -> Result<Info, HWIDeviceError> {
        HWI::get_info(self).await.map_err(kinded)
    }

    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, HWIDeviceError> {
        HWI::get_master_fingerprint(self).await.map_err(kinded)
    }

    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, HWIDeviceError> {
        HWI::get_extended_pubkey(self, path, display)
            .await
            .map_err(kinded)
    }

    async fn sign_message(
        &mut self,
        message: &[u8],
        path: DerivationPath,
    ) -> Result<(u8, Signature), HWIDeviceError> {
        HWI::sign_message(self, message, path).await.map_err(kinded)
    }

    async fn display_address(
        &mut self,
        address: DisplayAddress,
        context: Option<DeviceContext>,
    ) -> Result<String, HWIDeviceError> {
        HWI::display_address(self, address, context)
            .await
            .map_err(kinded)
    }

    async fn register_wallet(
        &mut self,
        name: &str,
        policy: &str,
    ) -> Result<WalletRegistration, HWIDeviceError> {
        HWI::register_wallet(self, name, policy)
            .await
            .map_err(kinded)
    }

    async fn sign_tx(
        &mut self,
        psbt: Psbt,
        context: Option<common::DeviceContext>,
    ) -> Result<Psbt, HWIDeviceError> {
        HWI::sign_tx(self, psbt, context).await.map_err(kinded)
    }
}

/// Updates persistent client state after the unlock interpreter completes.
pub trait OnUnlock {
    /// Applies the unlock response, or returns an error if it cannot be accepted.
    fn on_unlock(&mut self, _response: common::Response) -> Result<(), common::Error>;
}

/// Supplies the I/O endpoints and interpreter used to drive a command.
pub trait CommonInterface<C, T, R, E> {
    /// The device transport's error type.
    type TransportError: Debug;
    /// The PIN-server client's error type.
    type HttpClientError: Debug;

    /// Borrows the transport, HTTP client, optional host input, and a fresh interpreter.
    ///
    /// Session state may be borrowed by the interpreter and retained between commands.
    #[allow(clippy::type_complexity)]
    fn components(
        &mut self,
    ) -> (
        &mut (dyn Transport<Error = Self::TransportError> + '_),
        &(dyn HttpClient<Error = Self::HttpClientError> + '_),
        Option<&mut (dyn HostInteraction + 'static)>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    );
}

async fn run_command<D, C, E, F>(
    device: &mut D,
    command: C,
) -> Result<common::Response, Error<E, F>>
where
    E: Debug,
    F: Debug,
    D: CommonInterface<
            common::Command,
            common::Transmit,
            common::Response,
            common::Error,
            TransportError = E,
            HttpClientError = F,
        >,
    C: Into<common::Command>,
{
    run_command_inner(device, command, false).await
}

async fn run_command_allowing_final_disconnect<D, C, E, F>(
    device: &mut D,
    command: C,
) -> Result<common::Response, Error<E, F>>
where
    E: Debug,
    F: Debug,
    D: CommonInterface<
            common::Command,
            common::Transmit,
            common::Response,
            common::Error,
            TransportError = E,
            HttpClientError = F,
        >,
    C: Into<common::Command>,
{
    run_command_inner(device, command, true).await
}

async fn run_command_inner<D, C, E, F>(
    device: &mut D,
    command: C,
    allow_final_disconnect: bool,
) -> Result<common::Response, Error<E, F>>
where
    E: Debug,
    F: Debug,
    D: CommonInterface<
            common::Command,
            common::Transmit,
            common::Response,
            common::Error,
            TransportError = E,
            HttpClientError = F,
        >,
    C: Into<common::Command>,
{
    let (transport, http_client, mut host_interaction, mut intpr) = device.components();
    let mut transmit = Some(intpr.start(command.into())?);
    while let Some(t) = &transmit {
        match &t.recipient {
            common::Recipient::PinServer { url } => {
                let res = http_client
                    .request(url, &t.payload)
                    .await
                    .map_err(|error| Error::HttpClient {
                        kind: http_client.error_kind(&error),
                        error,
                    })?;
                transmit = intpr.exchange(res)?;
            }
            common::Recipient::Host(request) => {
                let interaction = host_interaction.as_deref_mut().ok_or_else(|| {
                    common::Error::new(ErrorKind::Unsupported, "host interaction required")
                })?;
                let response = interaction.respond(request).await?;
                transmit = intpr.exchange(response.into_bytes_for(request)?)?;
            }
            common::Recipient::Device => {
                let exchange = match transport.exchange(&t.payload, t.encrypted).await {
                    Ok(exchange) => exchange,
                    Err(error)
                        if allow_final_disconnect && transport.is_post_write_disconnect(&error) =>
                    {
                        return Ok(common::Response::DeviceAction(true));
                    }
                    Err(error) => {
                        return Err(Error::Transport {
                            kind: transport.error_kind(&error),
                            error,
                        });
                    }
                };
                transmit = intpr.exchange(exchange)?;
            }
        }
    }
    intpr.end().map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use std::{
        cell::{Cell, RefCell},
        convert::Infallible,
        rc::Rc,
    };

    struct ScriptedTransport {
        calls: usize,
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    #[async_trait(?Send)]
    impl Transport for ScriptedTransport {
        type Error = Infallible;

        async fn exchange(
            &mut self,
            command: &[u8],
            encrypted: bool,
        ) -> Result<Vec<u8>, Self::Error> {
            self.events.borrow_mut().push("device");
            self.calls += 1;
            assert_eq!(command, &[0x01]);
            assert!(!encrypted);
            Ok(vec![0x02])
        }
    }

    struct NoHttp;

    #[async_trait(?Send)]
    impl HttpClient for NoHttp {
        type Error = Infallible;

        async fn request(&self, _url: &str, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
            panic!("host interaction must not use HTTP")
        }
    }

    struct ScriptedHost {
        response: Option<common::HostResponse>,
        calls: Rc<Cell<usize>>,
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    #[async_trait(?Send)]
    impl HostInteraction for ScriptedHost {
        async fn respond(
            &mut self,
            request: &common::HostRequest,
        ) -> Result<common::HostResponse, common::Error> {
            assert_eq!(
                request,
                &common::HostRequest::PinMatrix {
                    kind: common::PinMatrixRequestKind::Current,
                }
            );
            self.events.borrow_mut().push("host");
            self.calls.set(self.calls.get() + 1);
            Ok(self.response.take().expect("one scripted host response"))
        }
    }

    #[derive(Default)]
    struct ScriptedInterpreter {
        state: u8,
        host_first: bool,
    }

    impl Interpreter for ScriptedInterpreter {
        type Command = common::Command;
        type Transmit = common::Transmit;
        type Response = common::Response;
        type Error = common::Error;

        fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
            assert!(matches!(command, common::Command::GetVersion));
            assert_eq!(self.state, 0);
            self.state = 1;
            if self.host_first {
                Ok(common::HostRequest::PinMatrix {
                    kind: common::PinMatrixRequestKind::Current,
                }
                .into())
            } else {
                Ok(vec![0x01].into())
            }
        }

        fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
            match (self.host_first, self.state) {
                (false, 1) => {
                    assert_eq!(data.as_slice(), &[0x02]);
                    self.state = 2;
                    Ok(Some(
                        common::HostRequest::PinMatrix {
                            kind: common::PinMatrixRequestKind::Current,
                        }
                        .into(),
                    ))
                }
                (false, 2) => {
                    assert_eq!(data.as_slice(), b"123");
                    self.state = 3;
                    Ok(None)
                }
                (true, 1) => {
                    assert_eq!(data.as_slice(), b"123");
                    self.state = 2;
                    Ok(Some(vec![0x01].into()))
                }
                (true, 2) => {
                    assert_eq!(data.as_slice(), &[0x02]);
                    self.state = 3;
                    Ok(None)
                }
                _ => panic!("unexpected scripted interpreter state"),
            }
        }

        fn end(self) -> Result<Self::Response, Self::Error> {
            assert_eq!(self.state, 3);
            Ok(common::Response::DeviceAction(true))
        }
    }

    struct ScriptedDevice {
        transport: ScriptedTransport,
        host_interaction: Option<Box<dyn HostInteraction>>,
        host_first: bool,
    }

    impl CommonInterface<common::Command, common::Transmit, common::Response, common::Error>
        for ScriptedDevice
    {
        type TransportError = Infallible;
        type HttpClientError = Infallible;

        fn components(
            &mut self,
        ) -> (
            &mut (dyn Transport<Error = Self::TransportError> + '_),
            &(dyn HttpClient<Error = Self::HttpClientError> + '_),
            Option<&mut (dyn HostInteraction + 'static)>,
            impl Interpreter<
                Command = common::Command,
                Transmit = common::Transmit,
                Response = common::Response,
                Error = common::Error,
            >,
        ) {
            (
                &mut self.transport,
                &NoHttp,
                self.host_interaction.as_deref_mut(),
                ScriptedInterpreter {
                    host_first: self.host_first,
                    ..Default::default()
                },
            )
        }
    }

    fn scripted_device(
        response: Option<common::HostResponse>,
    ) -> (ScriptedDevice, Rc<Cell<usize>>) {
        scripted_device_with_sequence(response, false)
    }

    fn scripted_device_with_sequence(
        response: Option<common::HostResponse>,
        host_first: bool,
    ) -> (ScriptedDevice, Rc<Cell<usize>>) {
        let calls = Rc::new(Cell::new(0));
        let events = Rc::new(RefCell::new(Vec::new()));
        let host_interaction = response.map(|response| {
            Box::new(ScriptedHost {
                response: Some(response),
                calls: Rc::clone(&calls),
                events: Rc::clone(&events),
            }) as Box<dyn HostInteraction>
        });
        (
            ScriptedDevice {
                transport: ScriptedTransport { calls: 0, events },
                host_interaction,
                host_first,
            },
            calls,
        )
    }

    #[test]
    fn initial_host_recipient_uses_provider_before_device_exchange() {
        let (mut device, host_calls) = scripted_device_with_sequence(
            Some(common::HostResponse::PinPositions("123".into())),
            true,
        );

        let response = block_on(run_command_inner(
            &mut device,
            common::Command::GetVersion,
            false,
        ))
        .expect("scripted command succeeds");

        assert!(matches!(response, common::Response::DeviceAction(true)));
        assert_eq!(host_calls.get(), 1);
        assert_eq!(device.transport.calls, 1);
        assert_eq!(
            device.transport.events.borrow().as_slice(),
            &["host", "device"]
        );
    }

    #[test]
    fn host_recipient_uses_provider_without_second_device_exchange() {
        let (mut device, host_calls) =
            scripted_device(Some(common::HostResponse::PinPositions("123".into())));

        let response = block_on(run_command_inner(
            &mut device,
            common::Command::GetVersion,
            false,
        ))
        .expect("scripted command succeeds");

        assert!(matches!(response, common::Response::DeviceAction(true)));
        assert_eq!(device.transport.calls, 1);
        assert_eq!(host_calls.get(), 1);
    }

    #[test]
    fn host_recipient_requires_provider_without_second_device_exchange() {
        let (mut device, host_calls) = scripted_device(None);

        let error = match block_on(run_command_inner(
            &mut device,
            common::Command::GetVersion,
            false,
        )) {
            Err(error) => error,
            Ok(_) => panic!("missing host provider succeeds"),
        };

        assert!(matches!(
            error,
            Error::Interpreter(e) if e.kind() == common::ErrorKind::Unsupported
                && e.message() == "host interaction required"
        ));
        assert_eq!(device.transport.calls, 1);
        assert_eq!(host_calls.get(), 0);
    }

    #[test]
    fn host_recipient_validates_response_without_second_device_exchange() {
        let (mut device, host_calls) =
            scripted_device(Some(common::HostResponse::RecoveryCharacter('a')));

        let error = match block_on(run_command_inner(
            &mut device,
            common::Command::GetVersion,
            false,
        )) {
            Err(error) => error,
            Ok(_) => panic!("mismatched host response succeeds"),
        };

        assert!(matches!(
            error,
            Error::Interpreter(e) if e.kind() == common::ErrorKind::InvalidInput
                && e.message() == "host response does not match request"
        ));
        assert_eq!(device.transport.calls, 1);
        assert_eq!(host_calls.get(), 1);
    }
}
