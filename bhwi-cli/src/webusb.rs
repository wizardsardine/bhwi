use std::io;

use async_trait::async_trait;
use bhwi_async::transport::Channel;
use nusb::Endpoint;
use nusb::transfer::{Buffer, In, Interrupt, Out};
use tokio::sync::Mutex;

const INTERFACE: u8 = 0;
const ENDPOINT_OUT: u8 = 0x01;
const ENDPOINT_IN: u8 = 0x81;
const PACKET_SIZE: usize = 64;

pub struct WebUsbChannel {
    out: Mutex<Endpoint<Interrupt, Out>>,
    ep_in: Endpoint<Interrupt, In>,
}

impl WebUsbChannel {
    pub async fn open(info: &nusb::DeviceInfo) -> io::Result<Self> {
        let device = info.open().await.map_err(io::Error::other)?;
        let interface = device
            .claim_interface(INTERFACE)
            .await
            .map_err(io::Error::other)?;
        let out = interface
            .endpoint::<Interrupt, Out>(ENDPOINT_OUT)
            .map_err(io::Error::other)?;
        let ep_in = interface
            .endpoint::<Interrupt, In>(ENDPOINT_IN)
            .map_err(io::Error::other)?;
        Ok(Self {
            out: Mutex::new(out),
            ep_in,
        })
    }
}

#[async_trait(?Send)]
impl Channel for WebUsbChannel {
    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        let mut out = self.out.lock().await;
        out.submit(data.to_vec().into());
        let completion = out.next_complete().await;
        completion.status.map_err(io::Error::other)?;
        Ok(completion.actual_len)
    }

    async fn receive(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.ep_in.submit(Buffer::new(PACKET_SIZE));
        let completion = self.ep_in.next_complete().await;
        completion.status.map_err(io::Error::other)?;
        let n = completion.actual_len.min(data.len());
        data[..n].copy_from_slice(&completion.buffer[..n]);
        Ok(n)
    }
}
