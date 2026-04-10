#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use anyhow::Result;
    use base64ct::Encoding;
    use bhwi_async::HWI;
    use bhwi_async::{Ledger, transport::ledger::speculos::LedgerTransportTcp};
    use bhwi_cli::ledger::SpeculosTcpChannel;
    use reqwest::Client;
    use serde::Serialize;
    use serde_json::Value;
    use tokio::net::TcpStream;

    pub type SpeculosDevice = Ledger<LedgerTransportTcp<SpeculosTcpChannel>>;

    struct SpeculosReqwestClient {
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

    impl SpeculosReqwestClient {
        fn new(url: &str) -> SpeculosReqwestClient {
            SpeculosReqwestClient {
                endpoint: url.into(),
                inner: Client::new(),
            }
        }

        async fn post<Req: Serialize>(&self, endpoint: &str, req: Req) -> Result<()> {
            self.inner
                .post(endpoint)
                .json(&req)
                .send()
                .await?
                .error_for_status()?;
            Ok(())
        }

        async fn button_press(&self, button: Button) -> Result<()> {
            self.post(
                &format!("{}/button/{button}", self.endpoint),
                &ButtonRequest {
                    action: "press-and-release".into(),
                },
            )
            .await
        }

        async fn set_automation<T: Serialize>(&self, automation_json: &T) -> Result<()> {
            self.post(&format!("{}/automation", self.endpoint), automation_json)
                .await
        }
    }

    impl Default for SpeculosReqwestClient {
        fn default() -> SpeculosReqwestClient {
            SpeculosReqwestClient::new("http://localhost:5000")
        }
    }

    async fn init() -> (SpeculosDevice, SpeculosReqwestClient) {
        (
            SpeculosDevice::new(LedgerTransportTcp::new(SpeculosTcpChannel::new(
                TcpStream::connect("localhost:9999").await.unwrap(),
            ))),
            SpeculosReqwestClient::default(),
        )
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let (mut dev, _) = init().await;
        let fingerprint = dev
            .get_master_fingerprint()
            .await
            .expect("failed to get fingerprint");
        assert_eq!(fingerprint.to_string(), "f5acc2fd");
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let (mut dev, _) = init().await;
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
        let (mut dev, client) = init().await;
        let msg = b"hello";

        client
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

        client
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

    #[tokio::test]
    async fn can_get_version() {
        let (mut dev, _) = init().await;
        let version = dev.get_version().await.unwrap();
        assert_eq!(version.version.to_string(), "2.4.5");
        assert_eq!(version.firmware, Some("Bitcoin Test".to_string()));
        assert_eq!(version.network.unwrap().to_string(), "testnet");
    }
}
