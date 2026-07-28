#[cfg(test)]
mod tests {
    use bhwi::bitcoin::Network;
    use bhwi_async::{HWI, Trezor, transport::trezor::TrezorTransport};
    use bhwi_cli::trezor::emulator::{DEFAULT_EMULATOR_ADDR, EmulatorClient};

    const FINGERPRINT: &str = "5c9e228d";
    const XPUB_44: &str = "tpubDDKn3FtHc74CaRrRbi1WFdJNaaenZkDWqq9NsEhcafnDZ4VuKeuLG2aKHm5SuwuLgAhRkkfHqcCxpnVNSrs5kJYZXwa6Ud431VnevzzzK3U";
    const XPUB_49: &str = "tpubDCHRnuvE95JrpEVTUmr36sK3K9ADf3s3aztpXzL8coBeCTE8cHV8PjxS6SjWJM3GfPn798gyEa3dRPgjoUDSuNfuC9xz4PHznwKEk2XL7X1";
    const XPUB_84: &str = "tpubDCZB6sR48s4T5Cr8qHUYSZEFCQMMHRg8AoVKVmvcAP5bRw7ArDKeoNwKAJujV3xCPkBvXH5ejSgbgyN6kREmF7sMd41NdbuHa8n1DZNxSMg";

    async fn device() -> Trezor<TrezorTransport<EmulatorClient>> {
        let client = EmulatorClient::new(DEFAULT_EMULATOR_ADDR)
            .await
            .expect("connect to the Trezor emulator");
        let mut dev = Trezor::new(TrezorTransport::new(client)).with_network(Network::Testnet);
        dev.unlock(Network::Testnet).await.expect("can't unlock");
        dev
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let mut dev = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        assert_eq!(fingerprint.to_string(), FINGERPRINT);
    }

    #[tokio::test]
    async fn can_get_xpub_legacy() {
        let mut dev = device().await;
        let xpub = dev
            .get_extended_pubkey("44'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(xpub.to_string(), XPUB_44);
    }

    #[tokio::test]
    async fn can_get_xpub_wrapped_segwit() {
        let mut dev = device().await;
        let xpub = dev
            .get_extended_pubkey("49'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(xpub.to_string(), XPUB_49);
    }

    #[tokio::test]
    async fn can_get_xpub_segwit() {
        let mut dev = device().await;
        let xpub = dev
            .get_extended_pubkey("84'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(xpub.to_string(), XPUB_84);
    }

    #[tokio::test]
    async fn can_get_info() {
        let mut dev = device().await;
        let info = dev.get_info().await.unwrap();
        assert_eq!(info.initialized, Some(true));
        assert!(info.networks.contains(&Network::Testnet));
        let expected = match std::env::var("TREZOR_MODEL").as_deref() {
            Ok("trezor-t") => "2.8.9",
            _ => "1.13.1",
        };
        assert_eq!(info.version, expected);
    }
}
