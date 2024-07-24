pub mod common;
pub mod jade;
pub mod ledger;

pub trait Interpreter {
    type Command;
    type Transmit;
    type Response;
    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, ()>;
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, ()>;
    fn end(self) -> Result<Self::Response, ()>;
}
