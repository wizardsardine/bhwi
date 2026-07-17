#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use bhwi_async::transport::jade::tcp::TcpTransport;
    use bhwi_async::{DisplayAddress, HWI, WalletRegistration};
    use bhwi_cli::jade::{JadeQemuDevice, PinServerClient, TcpClient};
    use bitcoin::{
        Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
        absolute::LockTime,
        address::{Address, AddressType},
        bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
        blockdata::{opcodes, script::Builder},
        psbt::{Input, Psbt},
        secp256k1::Secp256k1,
        transaction::Version as TxVersion,
    };
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
                Network::Signet,
                Network::Regtest
            ]
        );
    }

    #[tokio::test]
    async fn can_display_address_by_path() {
        let mut dev = device().await;
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
            .unwrap();
        assert_eq!(address, "tb1q9t9pgtdsyf6r8ks7gnxvj99sea4d3nmjl0tnzu");
    }

    #[tokio::test]
    async fn can_display_nested_segwit_address_by_path() {
        let mut dev = device().await;
        let address = dev
            .display_address(
                DisplayAddress::ByPath {
                    path: "m/49'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: Some(AddressType::P2sh),
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(address, "2MsFo9x4kZMVumePtLZvjh9Hn9A98bS3MF6");
    }

    #[tokio::test]
    async fn can_register_and_display_descriptor_address() {
        let mut dev = device().await;
        let secp = Secp256k1::new();
        let account_path: DerivationPath = "m/48'/1'/0'/2'".parse().unwrap();
        let device_fingerprint = dev.get_master_fingerprint().await.unwrap();
        let device_xpub = dev
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .unwrap();
        let cosigner_master = Xpriv::new_master(Network::Testnet, &[7u8; 32]).unwrap();
        let cosigner_fingerprint = cosigner_master.fingerprint(&secp);
        let cosigner_xpriv = cosigner_master.derive_priv(&secp, &account_path).unwrap();
        let cosigner_xpub = Xpub::from_priv(&secp, &cosigner_xpriv);
        let policy = format!(
            "wsh(sortedmulti(2,[{device_fingerprint}/{account_path}]{device_xpub}/<0;1>/*,[{cosigner_fingerprint}/{account_path}]{cosigner_xpub}/<0;1>/*))"
        );

        let registration = dev
            .register_wallet("jade-e2e", &policy)
            .await
            .expect("register Jade descriptor");
        assert_eq!(registration, WalletRegistration::Complete { hmac: None });

        let address = dev
            .display_address(
                DisplayAddress::ByDescriptor {
                    index: 0,
                    change: false,
                    display: true,
                    descriptor_name: "jade-e2e".to_string(),
                },
                None,
            )
            .await
            .expect("display registered Jade descriptor address");
        assert_eq!(
            address,
            multisig_address(&secp, device_xpub, cosigner_xpub, 0, 0)
        );
    }

    fn multisig_address(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        first: Xpub,
        second: Xpub,
        branch: u32,
        index: u32,
    ) -> String {
        let path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(branch).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ]);
        let mut keys = [
            first.derive_pub(secp, &path).unwrap().public_key,
            second.derive_pub(secp, &path).unwrap().public_key,
        ];
        keys.sort_by_key(|key| key.serialize());
        let script = Builder::new()
            .push_int(2)
            .push_key(&PublicKey::new(keys[0]))
            .push_key(&PublicKey::new(keys[1]))
            .push_int(2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .into_script();
        Address::p2wsh(&script, Network::Testnet).to_string()
    }

    #[tokio::test]
    async fn rejects_unsupported_path_address_format() {
        let mut dev = device().await;
        let err = dev
            .display_address(
                DisplayAddress::ByPath {
                    path: "m/86'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: Some(AddressType::P2tr),
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unsupported display address"));
    }

    #[tokio::test]
    async fn can_sign_psbt() {
        let mut dev = device().await;
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
        psbt.outputs[0].bip32_derivation =
            [(change_pubkey.inner, (fingerprint, change_path))].into();

        let signed = dev.sign_tx(psbt, None).await.expect("failed to sign psbt");

        assert_eq!(signed.inputs.len(), 1);
        assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
        assert!(signed.inputs[0].partial_sigs.contains_key(&input_pubkey));
    }
}
