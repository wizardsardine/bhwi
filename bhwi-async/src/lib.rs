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
    common, Device, Interpreter,
};
pub use jade::Jade;
pub use ledger::Ledger;

#[async_trait(?Send)]
pub trait Transport {
    type Error: Debug;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error>;
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
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Self::Error>;
    async fn get_extended_pubkey<'a>(
        &self,
        path: &'a DerivationPath,
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
impl<E, F, D> HWI for D
where
    F: Debug,
    E: Debug,
    D: for<'a> Device<'a, common::Command<'a>, common::Transmit, common::Response, common::Error>
        + Transport<Error = E>
        + HttpClient<Error = F>,
{
    type Error = Error<E, F>;
    async fn unlock(&mut self, network: Network) -> Result<(), Self::Error> {
        let res = run_command(
            self,
            self,
            self.interpreter(),
            common::Command::Unlock(network),
        )
        .await?;
        self.on_unlock(res)?;
        Ok(())
    }
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Self::Error> {
        if let common::Response::MasterFingerprint(fg) = run_command(
            self,
            self,
            self.interpreter(),
            common::Command::GetMasterFingerprint,
        )
        .await?
        {
            Ok(fg)
        } else {
            Err(common::Error::NoErrorOrResult.into())
        }
    }

    async fn get_extended_pubkey<'a>(
        &self,
        path: &'a DerivationPath,
        display: bool,
    ) -> Result<Xpub, Self::Error> {
        if let common::Response::Xpub(xpub) = run_command(
            self,
            self,
            self.interpreter(),
            common::Command::GetXpub { path, display },
        )
        .await?
        {
            Ok(xpub)
        } else {
            Err(common::Error::NoErrorOrResult.into())
        }
    }
}

async fn run_command<'a, T, S, I, C>(
    transport: &T,
    http_client: &S,
    mut intpr: I,
    command: C,
) -> Result<common::Response, Error<T::Error, S::Error>>
where
    T: Transport + ?Sized,
    S: HttpClient + ?Sized,
    I: Interpreter<Transmit = common::Transmit, Response = common::Response, Error = common::Error>,
    C: Into<I::Command>,
    I::Command: From<common::Command<'a>>,
{
    let transmit = intpr.start(command.into())?;
    let exchange = transport
        .exchange(&transmit.payload)
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
                    .exchange(&t.payload)
                    .await
                    .map_err(Error::Transport)?;
                transmit = intpr.exchange(exchange)?;
            }
        }
    }
    intpr.end().map_err(|e| e.into())
}
