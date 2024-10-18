pub use bitcoin;

pub mod common;
pub mod jade;
pub mod ledger;

pub trait Interpreter {
    type Command;
    type Transmit;
    type Response;
    type Error;
    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error>;
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error>;
    fn end(self) -> Result<Self::Response, Self::Error>;
}

pub trait Client<C, T, R, E> {
    fn interpreter(&self) -> impl Interpreter<Command = C, Transmit = T, Response = R, Error = E>;
}
