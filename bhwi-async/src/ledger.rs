use std::fmt::Debug;
use async_trait::async_trait;
use bhwi::ledger::apdu::{ApduCommand, ApduResponse};

#[async_trait]
pub trait LedgerTransport {
    type Error: Debug;
    async fn exchange(&self, command: &ApduCommand) -> Result<ApduResponse, Self::Error>;
}

pub struct Ledger<T> {
    transport: T
}

impl <T: LedgerTransport> Ledger<T> {

}
