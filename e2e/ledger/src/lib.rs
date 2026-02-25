use async_trait::async_trait;
use bhwi_async::{Ledger, Transport};
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub type SpeculosDevice = Ledger<SpeculosClient>;

pub struct SpeculosClient {
    endpoint: String,
    inner: Client,
}

impl SpeculosClient {
    pub fn new(endpoint: &str) -> SpeculosClient {
        SpeculosClient {
            endpoint: endpoint.into(),
            inner: Client::new(),
        }
    }
}

impl Default for SpeculosClient {
    fn default() -> SpeculosClient {
        SpeculosClient::new("http://localhost:5000")
    }
}

#[derive(Serialize, Deserialize)]
struct Apdu {
    /// hex encoded apdu data
    data: String,
}

#[async_trait(?Send)]
impl Transport for SpeculosClient {
    type Error = anyhow::Error;

    async fn exchange(
        &mut self,
        apdu_command: &[u8],
        _encrypted: bool,
    ) -> Result<Vec<u8>, Self::Error> {
        let Apdu { data } = self
            .inner
            .post(format!("{}/apdu", self.endpoint))
            .json(&Apdu {
                data: hex::encode(apdu_command),
            })
            .send()
            .await?
            .json()
            .await?;
        Ok(hex::decode(data)?)
    }
}

#[cfg(test)]
mod tests {
    use bhwi_async::HWI;

    use super::*;

    async fn init_device() -> SpeculosDevice {
        SpeculosDevice::new(SpeculosClient::default())
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let mut dev = init_device().await;
        let fingerprint = dev
            .get_master_fingerprint()
            .await
            .expect("failed to get fingerprint");
        assert_eq!(fingerprint.to_string(), "f5acc2fd");
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let mut dev = init_device().await;
        let xpub = dev
            .get_extended_pubkey("m/44'/1'/0'".parse().unwrap(), false)
            .await
            .expect("failed to get xpub");
        assert_eq!(
            xpub.to_string(),
            "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
        );
    }
}
