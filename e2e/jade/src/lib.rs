#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use bhwi_async::transport::jade::tcp::TcpTransport;
    use bhwi_async::{DisplayAddress, HWI};
    use bhwi_cli::jade::{JadeQemuDevice, PinServerClient, TcpClient};
    use bitcoin::Network;
    use tokio::net::TcpStream;

    async fn device() -> JadeQemuDevice {
        let mut dev = JadeQemuDevice::new(
            Network::Testnet,
            TcpTransport::new(TcpClient::new(
                TcpStream::connect("localhost:30121").await.unwrap(),
            )),
            PinServerClient::new(),
        );
        dev.unlock(Network::Testnet).await.expect("jade auth");
        dev
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let mut dev = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        assert_eq!(fingerprint.to_string(), "e3ebcc79");
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let mut dev = device().await;
        let xpub = dev
            .get_extended_pubkey("m/44'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(
            xpub.to_string(),
            "tpubDCKD5cdxMEFd2i4cNa3PJUbUHMsGDxsnfqjxVpMoG1ymWYUQUaZzTcHQo3JwYgaKe2FyKGA2FzGPSVczBoAiHGyERuA1mZ2UkGKufEnUxKk"
        );
    }

    #[tokio::test]
    async fn can_sign_message() {
        let mut dev = device().await;
        let (header, s) = dev
            .sign_message(b"hello", "m/44'/1'/0'".parse().unwrap())
            .await
            .unwrap();
        let mut sig = vec![header];
        sig.extend_from_slice(&s.serialize_compact());
        assert_eq!(
            Base64::encode_string(&sig),
            "H+SvKg15TSz+2C5ra6Q8/e8BaImOZVEeS0rOL6GCEt4vO+4xRRt+YYKavSqgAJBYZaGEiTqr7f9imyyElMNhYXU="
        );
    }

    #[tokio::test]
    async fn can_get_info() {
        let mut dev = device().await;
        let info = dev.get_info().await.unwrap();
        // 1.0.39-beta2-11-g1ca0a0a4-dirty
        assert!(info.version.to_string().contains("1.0.39"));
        // jade has "all" networks
        assert_eq!(
            info.networks,
            vec![
                Network::Bitcoin,
                Network::Testnet,
                Network::Testnet4,
                Network::Regtest,
                Network::Signet
            ]
        );
    }

    #[tokio::test]
    async fn can_display_address_miniscript() {
        let mut dev = device().await;
        let res = dev
            .display_address(
                DisplayAddress::ByPath {
                    path: "m/84'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: None,
                },
                None,
            )
            .await;
        // Jade does not support Path-based address display
        assert!(res.is_err());
    }
}
