#[cfg(test)]
mod debuglink;

#[cfg(test)]
mod tests {
    use bhwi::bitcoin::Network;
    use bhwi_async::{HWI, Trezor, transport::trezor::TrezorTransport};
    use bhwi_cli::trezor::emulator::{DEFAULT_EMULATOR_ADDR, EmulatorClient};

    use crate::debuglink::{DEFAULT_DEBUGLINK_ADDR, DebugLink};
    use bhwi::bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime,
        address::Address,
        bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
        psbt::{Input, Output, Psbt},
        secp256k1::Secp256k1,
        transaction::Version as TxVersion,
    };
    use std::str::FromStr;
    use std::time::Duration;

    const FINGERPRINT: &str = "5c9e228d";
    const XPUB_44: &str = "tpubDDKn3FtHc74CaRrRbi1WFdJNaaenZkDWqq9NsEhcafnDZ4VuKeuLG2aKHm5SuwuLgAhRkkfHqcCxpnVNSrs5kJYZXwa6Ud431VnevzzzK3U";
    const XPUB_49: &str = "tpubDCHRnuvE95JrpEVTUmr36sK3K9ADf3s3aztpXzL8coBeCTE8cHV8PjxS6SjWJM3GfPn798gyEa3dRPgjoUDSuNfuC9xz4PHznwKEk2XL7X1";
    const XPUB_86: &str = "tpubDC88gkaZi5HvJGxGDNLADkvtdpni3mLmx6vr2KnXmWMG8zfkBRggsxHVBkUpgcwPe2KKpkyvTJCdXHb1UHEWE64vczyyPQfHr1skBcsRedN";
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

    fn sample_psbt() -> Psbt {
        let secp = Secp256k1::verification_only();
        let account: DerivationPath = "m/84'/1'/0'".parse().unwrap();
        let xpub = Xpub::from_str(XPUB_84).unwrap();
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();

        let recv_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ]);
        let change_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ]);
        let recv = xpub.derive_pub(&secp, &recv_path).unwrap();
        let change = xpub.derive_pub(&secp, &change_path).unwrap();
        let recv_script = Address::p2wpkh(&recv.to_pub(), Network::Testnet).script_pubkey();
        let change_script = Address::p2wpkh(&change.to_pub(), Network::Testnet).script_pubkey();

        let prev = Transaction {
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
                script_pubkey: recv_script.clone(),
            }],
        };
        let unsigned = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev.compute_txid(),
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
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(prev),
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: recv_script,
            }),
            bip32_derivation: [(recv.public_key, (fingerprint, account.extend(recv_path)))].into(),
            ..Default::default()
        };
        psbt.outputs[0] = Output {
            bip32_derivation: [(
                change.public_key,
                (fingerprint, account.extend(change_path)),
            )]
            .into(),
            ..Default::default()
        };

        psbt
    }

    #[tokio::test]
    async fn can_sign_psbt() {
        let mut dev = device().await;
        let debug = DebugLink::new(DEFAULT_DEBUGLINK_ADDR)
            .await
            .expect("connect to debuglink");
        let signed = tokio::select! {
            signed = dev.sign_tx(sample_psbt(), None) => signed.expect("sign psbt"),
            _ = debug.confirm_until_done(Duration::from_millis(300)) => unreachable!(),
        };
        assert!(!signed.inputs[0].partial_sigs.is_empty());
    }

    fn foreign_outputs() -> Vec<TxOut> {
        let secp = Secp256k1::verification_only();
        let xpub = Xpub::from_str(XPUB_84).unwrap();
        let key = |index: u32| {
            xpub.derive_pub(&secp, &[ChildNumber::from_normal_idx(index).unwrap()])
                .unwrap()
                .to_pub()
        };
        let value = Amount::from_sat(5_000);
        let p2tr_key = bhwi::bitcoin::key::XOnlyPublicKey::from(key(20).0);
        vec![
            TxOut {
                value,
                script_pubkey: ScriptBuf::new_p2pkh(&key(10).pubkey_hash()),
            },
            TxOut {
                value,
                script_pubkey: ScriptBuf::new_p2sh(
                    &ScriptBuf::new_p2wpkh(&key(11).wpubkey_hash()).script_hash(),
                ),
            },
            TxOut {
                value,
                script_pubkey: ScriptBuf::new_p2wpkh(&key(12).wpubkey_hash()),
            },
            TxOut {
                value,
                script_pubkey: ScriptBuf::new_p2tr(&secp, p2tr_key, None),
            },
        ]
    }

    #[tokio::test]
    async fn can_sign_psbt_with_every_output_type() {
        let mut psbt = sample_psbt();
        psbt.unsigned_tx.output[0].value = Amount::from_sat(29_000);
        for output in foreign_outputs() {
            psbt.unsigned_tx.output.push(output);
            psbt.outputs.push(Default::default());
        }
        let payload: [u8; 32] = core::array::from_fn(|i| i as u8);
        let data: &bhwi::bitcoin::script::PushBytes =
            payload.as_slice().try_into().expect("push bytes");
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new_op_return(data),
        });
        psbt.outputs.push(Default::default());

        let mut dev = device().await;
        let debug = DebugLink::new(DEFAULT_DEBUGLINK_ADDR)
            .await
            .expect("connect to debuglink");
        let signed = tokio::select! {
            signed = dev.sign_tx(psbt, None) => signed.expect("sign psbt with every output type"),
            _ = debug.confirm_until_done(Duration::from_millis(300)) => unreachable!(),
        };
        assert!(!signed.inputs[0].partial_sigs.is_empty());
    }

    fn taproot_psbt() -> Psbt {
        let secp = Secp256k1::verification_only();
        let account: DerivationPath = "m/86'/1'/0'".parse().unwrap();
        let xpub = Xpub::from_str(XPUB_86).unwrap();
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let recv_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(0).unwrap(),
        ]);
        let recv = xpub.derive_pub(&secp, &recv_path).unwrap();
        let internal_key = bhwi::bitcoin::key::XOnlyPublicKey::from(recv.public_key);
        let script = ScriptBuf::new_p2tr(&secp, internal_key, None);

        let prev = Transaction {
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
                script_pubkey: script.clone(),
            }],
        };
        let unsigned = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: script.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0] = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: script,
            }),
            tap_internal_key: Some(internal_key),
            tap_key_origins: [(
                internal_key,
                (vec![], (fingerprint, account.extend(recv_path))),
            )]
            .into(),
            ..Default::default()
        };
        psbt
    }

    #[tokio::test]
    async fn can_sign_taproot_psbt() {
        let mut dev = device().await;
        let debug = DebugLink::new(DEFAULT_DEBUGLINK_ADDR)
            .await
            .expect("connect to debuglink");
        let signed = tokio::select! {
            signed = dev.sign_tx(taproot_psbt(), None) => signed.expect("sign taproot psbt"),
            _ = debug.confirm_until_done(Duration::from_millis(300)) => unreachable!(),
        };
        assert!(signed.inputs[0].tap_key_sig.is_some());
    }

    #[tokio::test]
    async fn can_sign_taproot_psbt_with_every_output_type() {
        let mut psbt = taproot_psbt();
        psbt.unsigned_tx.output[0].value = Amount::from_sat(29_000);
        for output in foreign_outputs() {
            psbt.unsigned_tx.output.push(output);
            psbt.outputs.push(Default::default());
        }
        let payload: [u8; 32] = core::array::from_fn(|i| i as u8);
        let data: &bhwi::bitcoin::script::PushBytes =
            payload.as_slice().try_into().expect("push bytes");
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new_op_return(data),
        });
        psbt.outputs.push(Default::default());

        let mut dev = device().await;
        let debug = DebugLink::new(DEFAULT_DEBUGLINK_ADDR)
            .await
            .expect("connect to debuglink");
        let signed = tokio::select! {
            signed = dev.sign_tx(psbt, None) => signed.expect("sign taproot psbt with every output type"),
            _ = debug.confirm_until_done(Duration::from_millis(300)) => unreachable!(),
        };
        assert!(signed.inputs[0].tap_key_sig.is_some());
    }

    #[tokio::test]
    async fn can_sign_psbt_with_op_return() {
        let mut psbt = sample_psbt();
        let payload: [u8; 32] = core::array::from_fn(|i| i as u8);
        let data: &bhwi::bitcoin::script::PushBytes =
            payload.as_slice().try_into().expect("push bytes");
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new_op_return(data),
        });
        psbt.outputs.push(Default::default());

        let mut dev = device().await;
        let debug = DebugLink::new(DEFAULT_DEBUGLINK_ADDR)
            .await
            .expect("connect to debuglink");
        let signed = tokio::select! {
            signed = dev.sign_tx(psbt, None) => signed.expect("sign psbt with op_return"),
            _ = debug.confirm_until_done(Duration::from_millis(300)) => unreachable!(),
        };
        assert!(!signed.inputs[0].partial_sigs.is_empty());
    }

    #[tokio::test]
    async fn recovers_after_a_declined_signature() {
        let debug = DebugLink::new(DEFAULT_DEBUGLINK_ADDR)
            .await
            .expect("connect to debuglink");
        let mut dev = device().await;
        let declined = tokio::select! {
            result = dev.sign_tx(sample_psbt(), None) => result,
            _ = debug.decline_until_done(Duration::from_millis(300)) => unreachable!(),
        };
        assert!(declined.is_err(), "expected the device to refuse");

        let mut dev = device().await;
        let fingerprint = dev
            .get_master_fingerprint()
            .await
            .expect("get master fingerprint after a declined signature");
        assert_eq!(fingerprint.to_string(), FINGERPRINT);
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
