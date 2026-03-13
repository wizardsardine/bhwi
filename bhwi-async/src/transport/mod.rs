pub mod coldcard;
pub mod jade;
pub mod ledger;

use async_trait::async_trait;

pub use bhwi::device::DeviceId;

#[async_trait(?Send)]
pub trait Channel {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error>;
    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error>;
}
