pub mod transport;

use async_trait::async_trait;
use bhwi::{
    bitcoin::bip32::Fingerprint,
    common::{self},
    ledger::LedgerError,
    Device, Interpreter,
};
pub use bhwi::{jade::Jade, ledger::Ledger};
use std::fmt::Debug;

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
pub trait HWI<E> {
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, E>;
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
impl<E, F, D> HWI<Error<E, F>> for D
where
    E: Debug,
    D: Device<common::Command, common::Transmit, common::Response, common::Error>
        + Transport<Error = E>
        + HttpClient<Error = F>,
{
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Error<E, F>> {
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
}

async fn run_command<T, S, I>(
    transport: &T,
    http_client: &S,
    mut intpr: I,
    command: common::Command,
) -> Result<common::Response, Error<T::Error, S::Error>>
where
    T: Transport + ?Sized,
    S: HttpClient + ?Sized,
    I: Interpreter<
        Command = common::Command,
        Transmit = common::Transmit,
        Response = common::Response,
        Error = common::Error,
    >,
{
    let transmit = intpr.start(command)?;
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
    let res = intpr.end().unwrap();
    Ok(res)
}

#[async_trait(?Send)]
impl<T, E> Transport for Ledger<T>
where
    E: Debug,
    T: Transport<Error = E>,
{
    type Error = T::Error;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.exchange(command).await
    }
}

#[async_trait(?Send)]
impl<T> HttpClient for Ledger<T> {
    type Error = LedgerError;
    async fn request(&self, _url: &str, _req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unreachable!("Ledger does not need http client")
    }
}

#[async_trait(?Send)]
impl<T, S, E> Transport for Jade<T, S>
where
    E: Debug,
    T: Transport<Error = E>,
{
    type Error = T::Error;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.exchange(command).await
    }
}

#[async_trait(?Send)]
impl<T, S> HttpClient for Jade<T, S>
where
    S: HttpClient,
{
    type Error = S::Error;
    async fn request(&self, url: &str, req: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.request(url, req).await
    }
}
