use std::fmt::Display;

use anyhow::Result;
use async_trait::async_trait;
use bhwi_async::{Ledger, Transport};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type SpeculosDevice = Ledger<SpeculosClient>;

pub struct SpeculosClient {
    endpoint: String,
    inner: Client,
}

#[derive(Debug, Clone, Copy)]
pub enum Button {
    Left,
    Right,
    Both,
}

impl Display for Button {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Button::Left => "left",
                Button::Right => "right",
                Button::Both => "both",
            }
        )
    }
}

#[derive(Serialize)]
struct ButtonRequest {
    action: String,
}

impl SpeculosClient {
    pub fn new(endpoint: &str) -> SpeculosClient {
        SpeculosClient {
            endpoint: endpoint.into(),
            inner: Client::new(),
        }
    }

    pub async fn button_press(&self, button: Button) -> Result<()> {
        self.inner
            .post(format!("{}/button/{button}", self.endpoint))
            .json(&ButtonRequest {
                action: "press-and-release".into(),
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn set_automation(&self, automation_json: Value) -> Result<()> {
        self.inner
            .post(format!("{}/automation", self.endpoint))
            .json(&automation_json)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
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
    use base64ct::Encoding;
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

    // https://github.com/LedgerHQ/app-bitcoin-new/blob/d30a667239cd15c5a0769f07e60ef5bff1e1cb66/bitcoin_client_rs/tests/client.rs#L45
    #[tokio::test]
    async fn can_sign_message() {
        let mut dev = init_device().await;
        let msg = b"hello";

        dev.transport
            .set_automation(
                serde_json::from_str(include_str!("../automations/sign_message.json")).unwrap(),
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
            .set_automation(
                serde_json::from_str(include_str!("../automations/sign_message_reject.json"))
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
