use super::webhid::WebHidDevice;
use async_trait::async_trait;
use bhwi_async::transport::ledger::hid::Channel;

#[async_trait(?Send)]
impl Channel for WebHidDevice {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        let mut data = data.to_vec();
        self.write(&mut data).await;
        Ok(data.len())
    }
    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        if let Some(array) = self.read().await {
            let length = array.len();
            data.copy_from_slice(&array);
            Ok(length)
        } else {
            Ok(0)
        }
    }
}
