#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;
    use base64ct::Encoding;
    use bhwi::bitcoin::{
        Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
        absolute::LockTime,
        address::Address,
        bip32::{ChildNumber, DerivationPath},
        psbt::{Input, Output, Psbt},
        secp256k1::Secp256k1,
        transaction::Version as TxVersion,
    };
    use bhwi::ledger::{LedgerWalletPolicy, Version};
    use bhwi_async::{DeviceContext, DisplayAddress, HWI};
    use bhwi_async::{Ledger, transport::ledger::speculos::LedgerTransportTcp};

    use bhwi_cli::ledger::SpeculosTcpChannel;
    use miniscript::descriptor::WalletPolicy;
    use reqwest::Client;
    use serde::Serialize;
    use serde_json::Value;
    use tokio::net::TcpStream;

    pub type SpeculosDevice = Ledger<LedgerTransportTcp<SpeculosTcpChannel>>;

    struct SpeculosReqwestClient {
        endpoint: String,
        inner: Client,
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
        let info = dev.get_info().await.unwrap();
        assert_eq!(info.version.to_string(), "2.4.6");
        assert_eq!(info.firmware, Some("Bitcoin Test".to_string()));
        assert_eq!(info.networks.first().unwrap().to_string(), "testnet");
    }

    #[tokio::test]
    async fn can_display_address() {
        let (mut dev, client) = init().await;
        client
            .set_automation(
                &serde_json::from_str::<Value>(include_str!("../automations/display_address.json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let address = dev
            .display_address(
                DisplayAddress::ByPath {
                    path: "m/84'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: None,
                },
                None,
            )
            .await
            .expect("failed to display address");
        assert_eq!(address, "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk");
    }

    #[tokio::test]
    async fn can_display_address_by_descriptor() {
        let (mut dev, client) = init().await;
        client
            .set_automation(
                &serde_json::from_str::<Value>(include_str!(
                    "../automations/register_wallet_accept.json"
                ))
                .unwrap(),
            )
            .await
            .unwrap();

        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        let xpub = dev
            .get_extended_pubkey("m/84'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();

        let key_str = format!("[{fingerprint}/84'/1'/0']{xpub}");
        let policy_str = format!("wpkh({key_str}/<0;1>/*)",);
        let name = "testwallet";

        let hmac = dev
            .register_wallet(name, &policy_str)
            .await
            .expect("failed to register wallet");
        let wallet_policy = WalletPolicy::from_str(&policy_str).unwrap();
        let ledger_policy = LedgerWalletPolicy::new(name.to_string(), Version::V2, wallet_policy);
        let ctx = DeviceContext::Ledger {
            wallet_policy: ledger_policy,
            wallet_hmac: Some(hmac),
        };

        client
            .set_automation(
                &serde_json::from_str::<Value>(include_str!(
                    "../automations/register_wallet_accept.json"
                ))
                .unwrap(),
            )
            .await
            .unwrap();

        let address = dev
            .display_address(
                DisplayAddress::ByDescriptor {
                    index: 0,
                    change: false,
                    display: true,
                    descriptor_name: name.to_string(),
                },
                Some(ctx),
            )
            .await
            .expect("failed to display address by descriptor");
        assert_eq!(address, "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk");
    }

    #[tokio::test]
    async fn can_sign_psbt() {
        let (mut dev, client) = init().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        let xpub = dev
            .get_extended_pubkey("m/84'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        let secp = Secp256k1::verification_only();
        let input_path: DerivationPath = "m/84'/1'/0'/0/0".parse().unwrap();
        let change_path: DerivationPath = "m/84'/1'/0'/1/0".parse().unwrap();
        let input_child_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ]);
        let change_child_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ]);
        let input_xpub = xpub.derive_pub(&secp, &input_child_path).unwrap();
        let change_xpub = xpub.derive_pub(&secp, &change_child_path).unwrap();
        let input_pubkey = PublicKey::new(input_xpub.public_key);
        let change_pubkey = PublicKey::new(change_xpub.public_key);
        let input_script = Address::p2wpkh(&input_xpub.to_pub(), Network::Testnet).script_pubkey();
        let change_script =
            Address::p2wpkh(&change_xpub.to_pub(), Network::Testnet).script_pubkey();
        let prev_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: input_script.clone(),
            }],
        };
        let unsigned_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: change_script,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(prev_tx),
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: input_script,
            }),
            bip32_derivation: [(input_pubkey.inner, (fingerprint, input_path))].into(),
            ..Default::default()
        };
        psbt.outputs[0] = Output {
            bip32_derivation: [(change_pubkey.inner, (fingerprint, change_path))].into(),
            ..Default::default()
        };

        let key_str = format!("[{fingerprint}/84'/1'/0']{xpub}");
        let policy = format!("wpkh({key_str}/<0;1>/*)");
        let name = "psbttest";
        client
            .set_automation(
                &serde_json::from_str::<Value>(include_str!(
                    "../automations/register_wallet_accept.json"
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        let hmac = dev
            .register_wallet(name, &policy)
            .await
            .expect("failed to register psbt wallet");

        client
            .set_automation(
                &serde_json::from_str::<Value>(include_str!("../automations/sign_psbt.json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let signed = dev
            .sign_tx(psbt, Some(name), Some(&policy), Some(hmac))
            .await
            .expect("failed to sign psbt");

        assert_eq!(signed.inputs.len(), 1);
        assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
        assert!(signed.inputs[0].partial_sigs.contains_key(&input_pubkey));
    }
}
