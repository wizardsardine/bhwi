use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bhwi_async::Transport;
use bhwi_async::coldcard::Coldcard;
use bhwi_async::transport::Channel;
use bhwi_async::transport::coldcard_hid::ColdcardTransportHID;
use tokio::net::UnixDatagram;

const CLIENT_SOCKET: &str = "/tmp/rust-ckcc-client.sock";

pub type ColdcardDevice = Coldcard<ColdcardTransportHID<SimulatorClient>>;

#[derive(Clone)]
pub struct SimulatorClient {
    /// the ckcc simulator socket (used for ckcc cli too)
    socket: Arc<UnixDatagram>,
}

impl SimulatorClient {
    pub async fn new(socket_path: &str) -> Self {
        let _ = std::fs::remove_file(CLIENT_SOCKET);
        let socket = UnixDatagram::bind(CLIENT_SOCKET).expect("unbound socket");
        socket
            .connect(socket_path)
            .expect("couldn't connect to socket");
        Self {
            socket: Arc::new(socket),
        }
    }

    pub async fn default() -> Self {
        Self::new("/tmp/ckcc-simulator.sock").await
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

pub struct DeviceControl {
    client: ColdcardTransportHID<SimulatorClient>,
}

impl DeviceControl {
    pub fn new(client: SimulatorClient) -> Self {
        Self {
            client: ColdcardTransportHID::new(client),
        }
    }

    // https://github.com/Coldcard/firmware/blob/0b425b8609c4c42f6986f4d209b6068136bb7cd4/shared/usb_test_commands.py#L23
    pub async fn approve(&mut self) -> Result<()> {
        // artificial delay until signing is done
        tokio::time::sleep(std::time::Duration::from_millis(0)).await;
        self.client.exchange(b"XKEYy", false).await.unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use bhwi_async::HWI;
    use bitcoin::Network;

    use super::*;

    async fn device() -> (ColdcardDevice, DeviceControl) {
        let mut rng = rand_core::OsRng;
        let client = SimulatorClient::default().await;
        let mut dev = ColdcardDevice::new(ColdcardTransportHID::new(client.clone()), &mut rng);
        let control = DeviceControl::new(client);
        dev.unlock(Network::Testnet).await.expect("can't unlock");
        (dev, control)
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let (mut dev, _) = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        assert_eq!(fingerprint.to_string(), "0f056943");
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let (mut dev, _) = device().await;
        let xpub = dev
            .get_extended_pubkey("44'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(
            xpub.to_string(),
            "tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB"
        );
    }

    // NOTE: this can be unstable if you repeat it quickly. It seems that the
    // simulator along with the simulated device input sharing the same socket
    // can interfere and sometimes return junk data.
    #[tokio::test]
    async fn can_sign_message() {
        let (mut dev, mut control) = device().await;

        let sign_task = dev.sign_message(b"hello", "44'/1'/0'".parse().unwrap());

        let (sign_res, approve_res) = tokio::join!(sign_task, control.approve());
        let (header, sig) = sign_res.unwrap();
        approve_res.unwrap();

        let mut uncompressed = vec![header];
        uncompressed.extend_from_slice(&sig.serialize_compact());

        assert_eq!(header, 40);
        assert_eq!(
            Base64::encode_string(&uncompressed),
            "KEMkoamxdI4o4yIKww0ZwbabbSWukI8WY1reuuPle/EJXzQ61fB/TFm+v/qmGCgTyEkhP3qCuAOOONBauJ/VtEA="
        );
    }
}
