pub use bitcoin;
pub use miniscript;

#[cfg(feature = "bitbox")]
pub mod bitbox;
pub mod coldcard;
pub mod common;
pub mod device;
pub mod jade;
pub mod ledger;
pub mod policy;
#[cfg(feature = "trezor")]
pub mod trezor;

pub trait Interpreter {
    type Command;
    type Transmit;
    type Response;
    type Error;
    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error>;
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error>;
    fn end(self) -> Result<Self::Response, Self::Error>;
}
