pub mod transport;

use async_trait::async_trait;
use bhwi::{bitcoin::bip32::Fingerprint, common, Interpreter};
use std::fmt::Debug;

#[async_trait(?Send)]
pub trait Transport {
    type Error: Debug;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[async_trait(?Send)]
pub trait HWI {
    type Error: Debug;
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Self::Error>;
}

#[derive(Debug)]
pub enum Error<E> {
    Transport(E),
    Interpreter(common::Error),
}

impl<E> From<common::Error> for Error<E> {
    fn from(value: common::Error) -> Self {
        Self::Interpreter(value)
    }
}

pub struct Device<T, I> {
    pub transport: T,
    pub interpreter: Box<dyn Fn() -> I>,
}

impl<T, I> Device<T, I>
where
    T: Transport,
    I: Interpreter<
        Command = common::Command,
        Transmit = common::Transmit,
        Response = common::Response,
        Error = common::Error,
    >,
{
    pub fn new(transport: T, interpreter: impl Fn() -> I + 'static) -> Self {
        Self {
            transport,
            interpreter: Box::new(interpreter),
        }
    }

    async fn run_command(
        &self,
        command: common::Command,
    ) -> Result<common::Response, Error<T::Error>> {
        let mut intpr = (self.interpreter)();
        let transmit = intpr.start(command)?;
        let exchange = self
            .transport
            .exchange(&transmit.payload)
            .await
            .map_err(Error::Transport)?;
        let mut transmit = intpr.exchange(exchange)?;
        while let Some(t) = &transmit {
            if matches!(t.recipient, common::Recipient::Device) {
                let exchange = self
                    .transport
                    .exchange(&t.payload)
                    .await
                    .map_err(Error::Transport)?;
                transmit = intpr.exchange(exchange)?;
            } else {
                break;
            }
        }
        let res = intpr.end().unwrap();
        Ok(res)
    }
}

#[async_trait(?Send)]
impl<T, I> HWI for Device<T, I>
where
    T: Transport,
    I: Interpreter<
        Command = common::Command,
        Transmit = common::Transmit,
        Response = common::Response,
        Error = common::Error,
    >,
{
    type Error = Error<T::Error>;
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Self::Error> {
        if let common::Response::MasterFingerprint(fg) = self
            .run_command(common::Command::GetMasterFingerprint)
            .await?
        {
            Ok(fg)
        } else {
            Err(common::Error::NoErrorOrResult.into())
        }
    }
}
