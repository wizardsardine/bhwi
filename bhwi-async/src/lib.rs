pub mod coldcard;
pub mod jade;
pub mod ledger;
pub mod transport;

use std::fmt::Debug;

use async_trait::async_trait;
use bhwi::{
    bitcoin::{
        bip32::{DerivationPath, Fingerprint, Xpub},
        Network,
    },
    common, Interpreter,
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
    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, Self::Error>;
    async fn get_extended_pubkey(
        &mut self,
        path: DerivationPath,
        display: bool,
    ) -> Result<Xpub, Self::Error>;
}

#[derive(Debug)]
pub enum Error<E, F> {
    Transport(E),
    HttpClient(F),
    Interpreter(common::Error),
}

impl<E, F> From<common::Error> for Error<E, F> {
    fn from(value: common::Error) -> Self {
        Self::Interpreter(value)
    }
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
}

pub trait OnUnlock {
    fn on_unlock(&mut self, _response: common::Response) -> Result<(), common::Error>;
}

pub trait CommonInterface<C, T, R, E> {
    type TransportError: Debug;
    type HttpClientError: Debug;
    fn components(
        &mut self,
    ) -> (
        &mut dyn Transport<Error = Self::TransportError>,
        &dyn HttpClient<Error = Self::HttpClientError>,
        impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>,
    );
}

async fn run_command<'a, D, C, E, F>(
    device: &'a mut D,
    command: C,
) -> Result<common::Response, Error<E, F>>
where
    E: std::fmt::Debug + 'a,
    F: std::fmt::Debug + 'a,
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
