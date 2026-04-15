use anyhow::Result;
use bhwi_async::Transport;
use bhwi_async::coldcard::Coldcard;
use bhwi_async::transport::coldcard::hid::ColdcardTransportHID;
use bhwi_cli::coldcard::emulator::EmulatorClient;

pub type ColdcardDevice = Coldcard<ColdcardTransportHID<EmulatorClient>>;

pub struct DeviceControl {
    client: ColdcardTransportHID<EmulatorClient>,
}

impl DeviceControl {
    pub fn new(client: EmulatorClient) -> Self {
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
    use bhwi_async::{HWI, transport::coldcard::DEFAULT_CKCC_SOCKET};
    use bitcoin::Network;

    use super::*;

    async fn device() -> (ColdcardDevice, DeviceControl) {
        let mut rng = rand_core::OsRng;
        let client = EmulatorClient::new(DEFAULT_CKCC_SOCKET).await.unwrap();
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
    // emulator along with the emulated device input sharing the same socket
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

    #[tokio::test]
    async fn can_get_info() {
        let (mut dev, _) = device().await;
        let info = dev.get_info().await.unwrap();
        assert_eq!(info.firmware, Some("mk4".to_string()));
        assert_eq!(info.version.to_string(), "5.x.x");
    }
}
