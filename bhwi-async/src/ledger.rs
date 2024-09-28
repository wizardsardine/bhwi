use async_trait::async_trait;
use bhwi::ledger::{
    apdu::{ApduCommand, ApduResponse},
    LedgerCommand, LedgerResponse,
};
use std::fmt::Debug;

#[async_trait]
pub trait LedgerTransport {
    type Error: Debug;
    async fn exchange(&self, command: &ApduCommand) -> Result<ApduResponse, Self::Error>;
}

pub struct Ledger<T> {
    transport: T,
}

impl<T: LedgerTransport> Ledger<T> {
    fn run_command<C, R>(&self, command: C) -> Result<R, ()>
    where
        C: Into<LedgerCommand>,
        R: From<LedgerResponse>,
    {
        Err(())
    }
}
