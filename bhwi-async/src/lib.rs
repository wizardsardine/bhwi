pub mod coldcard;
pub mod jade;
pub mod ledger;
pub mod transport;

use std::{error::Error as StdError, fmt::Debug, str::FromStr};

use async_trait::async_trait;
pub use bhwi::common::DeviceContext;
pub use bhwi::common::DisplayAddress;
pub use bhwi::common::Info;
use bhwi::miniscript::descriptor::WalletPolicy;
use bhwi::{
    Interpreter,
    bitcoin::{
        Network,
        bip32::{DerivationPath, Fingerprint, Xpub},
        secp256k1::ecdsa::Signature,
    },
    common::{self},
};
pub use jade::Jade;
pub use ledger::Ledger;

#[async_trait(?Send)]
pub trait Transport {
    type Error: Debug;
    async fn exchange(&mut self, command: &[u8], encrypted: bool) -> Result<Vec<u8>, Self::Error>;
}

#[async_trait(?Send)]
pub trait HttpClient {
    type Error: Debug;
    async fn request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[async_trait(?Send)]
pub trait HWI {
    type Error: Debug;
    async fn unlock(&mut self, network: Network) -> Result<(), Self::Error>;
    async fn get_info(&mut self) -> Result<Info, Self::Error>;
    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, Self::Error>;
    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, Self::Error>;
    async fn sign_message(
        &mut self,
        message: &[u8],
        path: DerivationPath,
    ) -> Result<(u8, Signature), Self::Error>;
    async fn display_address(
        &mut self,
        address: common::DisplayAddress,
        context: Option<common::DeviceContext>,
    ) -> Result<String, Self::Error>;
    async fn register_wallet(&mut self, name: &str, policy: &str) -> Result<[u8; 32], Self::Error>;
}

// TODO: this will become a pain to maintain, but we can have a proc-macro
// generate this trait by putting it over HWI's definition and then also
// generate the blanket impl which will map the errors to HWIDeviceError
#[async_trait(?Send)]
pub trait HWIDevice {
    async fn unlock(&mut self, network: Network) -> Result<(), HWIDeviceError>;
    async fn get_info(&mut self) -> Result<Info, HWIDeviceError>;
    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, HWIDeviceError>;
    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, HWIDeviceError>;
    async fn sign_message(
        &mut self,
        message: &[u8],
        path: DerivationPath,
    ) -> Result<(u8, Signature), HWIDeviceError>;
    async fn display_address(
        &mut self,
        address: common::DisplayAddress,
        context: Option<common::DeviceContext>,
    ) -> Result<String, HWIDeviceError>;
    async fn register_wallet(
        &mut self,
        name: &str,
        policy: &str,
    ) -> Result<[u8; 32], HWIDeviceError>;
}

#[derive(Debug, thiserror::Error)]
#[error("hwi device error: {0}")]
pub struct HWIDeviceError(#[from] Box<dyn StdError + Send + Sync + 'static>);

impl HWIDeviceError {
    pub fn new(error: impl StdError + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error<E, F> {
    #[error("transport error: {0}")]
    Transport(E),

    #[error("http client error: {0}")]
    HttpClient(F),

    #[error("interpreter error: {0}")]
    Interpreter(#[from] common::Error),
}

#[async_trait(?Send)]
impl<D> HWI for D
where
    D: CommonInterface<common::Command, common::Transmit, common::Response, common::Error>
        + OnUnlock,
{
    type Error = Error<D::TransportError, D::HttpClientError>;
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
            Err(common::Error::NoErrorOrResult.into())
        }
    }

    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, Self::Error> {
        if let common::Response::MasterFingerprint(fg) =
            run_command(self, common::Command::GetMasterFingerprint).await?
        {
            Ok(fg)
        } else {
            Err(common::Error::NoErrorOrResult.into())
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
            Err(common::Error::NoErrorOrResult.into())
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
            Err(common::Error::NoErrorOrResult.into())
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
            Err(common::Error::NoErrorOrResult.into())
        }
    }

    async fn register_wallet(&mut self, name: &str, policy: &str) -> Result<[u8; 32], Self::Error> {
        let wallet_policy = WalletPolicy::from_str(policy)
            .map_err(|e| common::Error::Serialization(e.to_string()))?;
        if let common::Response::WalletHmac(hmac) = run_command(
            self,
            common::Command::RegisterWallet {
                name: name.to_string(),
                policy: wallet_policy,
            },
        )
        .await?
        {
            Ok(hmac)
        } else {
            Err(common::Error::NoErrorOrResult.into())
        }
    }
}

#[async_trait(?Send)]
impl<T> HWIDevice for T
where
    T: HWI,
    T::Error: StdError + Send + Sync + 'static,
{
    async fn unlock(&mut self, network: Network) -> Result<(), HWIDeviceError> {
        HWI::unlock(self, network)
            .await
            .map_err(HWIDeviceError::new)
    }

    async fn get_info(&mut self) -> Result<Info, HWIDeviceError> {
        HWI::get_info(self).await.map_err(HWIDeviceError::new)
    }

    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, HWIDeviceError> {
        HWI::get_master_fingerprint(self)
            .await
            .map_err(HWIDeviceError::new)
    }

    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, HWIDeviceError> {
        HWI::get_extended_pubkey(self, path, display)
            .await
            .map_err(HWIDeviceError::new)
    }

    async fn sign_message(
        &mut self,
        message: &[u8],
        path: DerivationPath,
    ) -> Result<(u8, Signature), HWIDeviceError> {
        HWI::sign_message(self, message, path)
            .await
            .map_err(HWIDeviceError::new)
    }

    async fn display_address(
        &mut self,
        address: DisplayAddress,
        context: Option<DeviceContext>,
    ) -> Result<String, HWIDeviceError> {
        HWI::display_address(self, address, context)
            .await
            .map_err(HWIDeviceError::new)
    }

    async fn register_wallet(
        &mut self,
        name: &str,
        policy: &str,
    ) -> Result<[u8; 32], HWIDeviceError> {
        HWI::register_wallet(self, name, policy)
            .await
            .map_err(HWIDeviceError::new)
    }
}

pub trait OnUnlock {
    fn on_unlock(&mut self, _response: common::Response) -> Result<(), common::Error>;
}

pub trait CommonInterface<C, T, R, E> {
    type TransportError: Debug;
    type HttpClientError: Debug;

    #[allow(clippy::type_complexity)]
    fn components(
        &mut self,
    ) -> (
        &mut dyn Transport<Error = Self::TransportError>,
        &dyn HttpClient<Error = Self::HttpClientError>,
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
    let (transport, http_client, mut intpr) = device.components();
    let transmit = intpr.start(command.into())?;
    let exchange = transport
        .exchange(&transmit.payload, transmit.encrypted)
        .await
        .map_err(Error::Transport)?;
    let mut transmit = intpr.exchange(exchange)?;
    while let Some(t) = &transmit {
        match &t.recipient {
            common::Recipient::PinServer { url } => {
                let res = http_client
                    .request(url, &t.payload)
                    .await
                    .map_err(Error::HttpClient)?;
                transmit = intpr.exchange(res)?;
            }
            common::Recipient::Device => {
                let exchange = transport
                    .exchange(&t.payload, t.encrypted)
                    .await
                    .map_err(Error::Transport)?;
                transmit = intpr.exchange(exchange)?;
            }
        }
    }
    intpr.end().map_err(|e| e.into())
}
