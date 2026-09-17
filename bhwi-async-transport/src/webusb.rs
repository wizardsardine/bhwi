use std::io;
use std::time::Duration;

use async_trait::async_trait;
use bhwi_async::transport::Channel;
use nusb::Endpoint;
use nusb::transfer::{Buffer, In, Interrupt, Out};
use tokio::sync::Mutex;

const INTERFACE: u8 = 0;
const ENDPOINT_OUT: u8 = 0x01;
const ENDPOINT_IN: u8 = 0x81;
const PACKET_SIZE: usize = 64;
const DRAIN_TIMEOUT: Duration = Duration::from_millis(50);

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
        let mut channel = Self {
            out: Mutex::new(out),
            ep_in,
        };
        channel.drain();
        Ok(channel)
    }

    fn drain(&mut self) {
        loop {
            self.ep_in.submit(Buffer::new(PACKET_SIZE));
            if self.ep_in.wait_next_complete(DRAIN_TIMEOUT).is_none() {
                self.ep_in.cancel_all();
                while self.ep_in.pending() > 0 {
                    self.ep_in.wait_next_complete(DRAIN_TIMEOUT);
                }
                return;
            }
        }
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

pub(crate) fn webusb_path(info: &nusb::DeviceInfo) -> String {
    let mut path = format!("webusb:{}", bus_number(info.bus_id()));
    for port in info.port_chain() {
        path.push_str(&format!(":{port}"));
    }
    path
}

fn bus_number(bus_id: &str) -> String {
    let parsed = if cfg!(target_os = "macos") {
        u32::from_str_radix(bus_id, 16).ok()
    } else {
        bus_id.parse::<u32>().ok()
    };
    match parsed {
        Some(bus) => format!("{bus:03}"),
        None => bus_id.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_number_is_three_digit_decimal() {
        if cfg!(target_os = "macos") {
            assert_eq!(bus_number("14"), "020");
            assert_eq!(bus_number("01"), "001");
        } else {
            assert_eq!(bus_number("001"), "001");
            assert_eq!(bus_number("20"), "020");
        }
    }

    #[test]
    fn bus_number_falls_back_to_the_raw_id() {
        assert_eq!(bus_number("PCIROOT(0)#PCI(0201)"), "PCIROOT(0)#PCI(0201)");
    }
}
