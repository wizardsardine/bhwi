use std::sync::Arc;

use async_trait::async_trait;
use bhwi_async::coldcard::Coldcard;
use bhwi_async::transport::Channel;
use bhwi_async::transport::coldcard_hid::ColdcardTransportHID;
use tokio::net::{TcpStream, UnixDatagram};
use tokio::sync::Mutex;

const CLIENT_SOCKET: &str = "/tmp/rust-ckcc-client.sock";

pub type ColdcardDevice = Coldcard<ColdcardTransportHID<SimulatorClient>>;

pub struct SimulatorClient {
    /// the tcp server to control simulated device keys
    device_control: Arc<Mutex<TcpStream>>,
    /// the ckcc simulator socket (used for ckcc cli)
    socket: UnixDatagram,
}

impl SimulatorClient {
    pub async fn new(socket_path: &str, control_endpoint: &str) -> Self {
        let _ = std::fs::remove_file(CLIENT_SOCKET);
        let socket = UnixDatagram::bind(CLIENT_SOCKET).expect("unbound socket");
        socket
            .connect(socket_path)
            .expect("couldn't connect to socket");
        Self {
            socket,
            device_control: Arc::new(Mutex::new(
                TcpStream::connect(control_endpoint)
                    .await
                    .expect("headless simulator control TCP endpoint"),
            )),
        }
    }

    pub async fn default() -> Self {
        Self::new("/tmp/ckcc-simulator.sock", "127.0.0.1:9999").await
    }
}

#[async_trait(?Send)]
impl Channel for SimulatorClient {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.socket.send(data).await?;
        Ok(data.len())
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        Ok(self.socket.recv(data).await?)
    }
}

#[cfg(test)]
mod tests {
    use bhwi_async::HWI;
    use bitcoin::Network;

    use super::*;

    async fn device() -> ColdcardDevice {
        let mut rng = rand_core::OsRng;
        let mut dev = ColdcardDevice::new(
            ColdcardTransportHID::new(SimulatorClient::default().await),
            &mut rng,
        );
        dev.unlock(Network::Testnet).await.expect("can't unlock");
        dev
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let mut dev = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        assert_eq!(fingerprint.to_string(), "0f056943");
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let mut dev = device().await;
        let xpub = dev
            .get_extended_pubkey("44'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(
            xpub.to_string(),
            "tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB"
        );
    }
}
