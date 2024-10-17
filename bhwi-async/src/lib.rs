pub mod transport;

use async_trait::async_trait;
use bhwi::{
    bitcoin::bip32::Fingerprint,
    common::{self},
    DeviceApp, Interpreter,
};
use std::fmt::Debug;

#[async_trait(?Send)]
pub trait Transport {
    type Error: Debug;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[async_trait(?Send)]
pub trait HWI<E> {
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, E>;
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

pub trait Connected<E> {
    fn transport(&self) -> &dyn Transport<Error = E>;
}

#[async_trait(?Send)]
impl<E, I, D> HWI<Error<E>> for D
where
    E: Debug,
    I: Interpreter<
        Command = common::Command,
        Transmit = common::Transmit,
        Response = common::Response,
        Error = common::Error,
    >,
    D: DeviceApp<Interpreter = I> + Connected<E>,
{
    async fn get_master_fingerprint(&self) -> Result<Fingerprint, Error<E>> {
        if let common::Response::MasterFingerprint(fg) = run_command(
            self.transport(),
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

async fn run_command<T, I>(
    transport: &T,
    mut intpr: I,
    command: common::Command,
) -> Result<common::Response, Error<T::Error>>
where
    T: Transport + ?Sized,
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
        if matches!(t.recipient, common::Recipient::Device) {
            let exchange = transport
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

pub struct Ledger<T, I> {
    transport: T,
    init: Box<dyn Fn() -> I>,
}

impl<E, T, I> Connected<E> for Ledger<T, I>
where
    T: Transport<Error = E>,
{
    fn transport(&self) -> &dyn Transport<Error = T::Error> {
        &self.transport
    }
}

impl<T, I> Ledger<T, I> {
    pub fn new(transport: T, init: impl Fn() -> I + 'static) -> Self {
        Self {
            transport,
            init: Box::new(init),
        }
    }
}

impl<T, I> DeviceApp for Ledger<T, I> {
    type Interpreter = I;
    fn interpreter(&self) -> Self::Interpreter {
        (self.init)()
    }
}
