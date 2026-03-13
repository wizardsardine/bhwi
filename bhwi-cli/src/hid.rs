use std::sync::Arc;

use async_hid::{AsyncHidRead, AsyncHidWrite, DeviceReaderWriter};
use async_trait::async_trait;
use bhwi_async::transport::Channel;
use tokio::sync::Mutex;

pub struct HidChannel {
    device: Arc<Mutex<DeviceReaderWriter>>,
}

impl HidChannel {
    pub fn new(device: DeviceReaderWriter) -> Self {
        Self {
            device: Arc::new(Mutex::new(device)),
        }
    }
}

#[async_trait(?Send)]
impl Channel for HidChannel {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.device
            .lock()
            .await
            .write_output_report(data)
            .await
            .map_err(std::io::Error::other)?;
        Ok(data.len())
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        self.device
            .lock()
            .await
            .read_input_report(data)
            .await
            .map_err(std::io::Error::other)
    }
}
