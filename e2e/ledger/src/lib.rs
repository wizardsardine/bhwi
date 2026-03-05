use async_trait::async_trait;
use bhwi_async::{
    Ledger,
    transport::ledger::speculos::{SpeculosClient, SpeculosTransport},
};
use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};

pub type SpeculosDevice = Ledger<SpeculosTransport<SpeculosReqwestClient>>;

pub struct SpeculosReqwestClient {
    endpoint: String,
    inner: Client,
}

impl SpeculosReqwestClient {
    pub fn new(url: &str) -> SpeculosReqwestClient {
        SpeculosReqwestClient {
            endpoint: url.into(),
            inner: Client::new(),
        }
    }
}

#[async_trait(?Send)]
impl SpeculosClient for SpeculosReqwestClient {
    type Error = anyhow::Error;

    fn url(&self) -> &str {
        &self.endpoint
    }

    async fn post<Req: Serialize>(
        &self,
        endpoint: &str,
        req: Req,
    ) -> std::result::Result<(), Self::Error> {
        self.inner
            .post(endpoint)
            .json(&req)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn post_json<Req: Serialize, Res: DeserializeOwned>(
        &self,
        endpoint: &str,
        req: Req,
    ) -> std::result::Result<Res, Self::Error> {
        Ok(self
            .inner
            .post(endpoint)
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

impl Default for SpeculosReqwestClient {
    fn default() -> SpeculosReqwestClient {
        SpeculosReqwestClient::new("http://localhost:5000")
    }
}

#[cfg(test)]
mod tests {
    use base64ct::Encoding;
    use bhwi_async::HWI;
    use serde_json::Value;

    use super::*;

    async fn init_device() -> SpeculosDevice {
        SpeculosDevice::new(SpeculosTransport::new(SpeculosReqwestClient::default()))
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

    // https://github.com/LedgerHQ/app-bitcoin-new/blob/d30a667239cd15c5a0769f07e60ef5bff1e1cb66/bitcoin_client_rs/tests/client.rs#L45
    #[tokio::test]
    async fn can_sign_message() {
        let mut dev = init_device().await;
        let msg = b"hello";

        dev.transport
            .client
            .set_automation(
                &serde_json::from_str::<Value>(include_str!("../automations/sign_message.json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (header, sig) = dev
            .sign_message(msg, "m/44'/1'/0'/0".parse().unwrap())
            .await
            .expect("failed to sign message");
        let mut res = vec![header];
        res.extend_from_slice(&sig.serialize_compact());

        assert_eq!(
            base64ct::Base64::encode_string(&res),
            "IL3u9GLAzgG5BdtSBqUe0Fo2Zx0UlKwSsYx2TbuVX0VULFgZYRBQCW0W7QOlsB/JgGwWNhl3eYYjXtdfyR7pM+Y="
        );

        dev.transport
            .client
            .set_automation(
                &serde_json::from_str::<Value>(include_str!(
                    "../automations/sign_message_reject.json"
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        let res = dev
            .sign_message(msg, "m/44'/1'/0'/0".parse().unwrap())
            .await;
        assert!(res.is_err());
    }
}
