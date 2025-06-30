pub mod coldcard_hid;
pub mod ledger_hid;

use async_trait::async_trait;

#[async_trait(?Send)]
pub trait Channel {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error>;
    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error>;
}
