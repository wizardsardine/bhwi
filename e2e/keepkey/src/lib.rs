pub mod debuglink;

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        rc::Rc,
        str::FromStr,
    };

    use async_trait::async_trait;
    use bhwi::{
        bitcoin::{
            Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
            TxOut, Witness,
            absolute::LockTime,
            address::AddressType,
            bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
            blockdata::{opcodes::all::OP_CHECKMULTISIG, script::Builder},
            key::XOnlyPublicKey,
            psbt::{Input, Output as PsbtOutput, Psbt},
            secp256k1::Secp256k1,
            sighash::SighashCache,
            sign_message::{MessageSignature, signed_msg_hash},
            transaction::Version as TxVersion,
        },
        common::{
            DeviceContext, HostRequest, HostResponse, MultisigAddressType, MultisigDisplayAddress,
            PinMatrixRequestKind, RestoreOptions, SetupOptions,
        },
        keepkey::{HostPassphrase, HostPin, ManagementContext},
    };
    use bhwi_async::{
        DisplayAddress, HWI, HostInteraction, KeepKey, transport::trezor::TrezorTransport,
    };
    use bhwi_cli::trezor::emulator::EmulatorClient;

    use crate::debuglink::{
        DEFAULT_MAIN_ADDR, DebugButton, DebugLink, KeepKeyHostInteraction, SYNTHETIC_MNEMONIC,
        lock_device,
    };

    const FINGERPRINT: &str = "95d8f670";
    const XPUB_44: &str = "tpubDCknDegFqAdP4V2AhHhs635DPe8N1aTjfKE9m2UFbdej8zmeNbtqDzK59SxnsYSRSx5uS3AujbwgANUiAk4oHmDNUKoGGkWWUY6c48WgjEx";
    const XPUB_49: &str = "tpubDDfS76c9NLz6v8CxwsCBi6YFcW463axCZpc3FR26othehmeXowmSBJ6TVPYYqhkekpivwRgkvdHgy8bCp5eHrqu33bGanQQH2qnVbPLUJEh";
    const XPUB_84: &str = "tpubDDPHCt8nzaf3HZXAMeUj3grAcDdXmyy6BkUZgMyhCjUDLwpdE4gdzCFH6rG9Ex9PukLURFmGYhbrZAXzP4D464g8wHa2FRz3cbB6Q6QGqno";
    const TEST_PIN: &str = "1234";
    const MULTISIG_ORIGIN: &str = "48'/1'/0'/0'";

    type Device = KeepKey<TrezorTransport<EmulatorClient>>;

    async fn raw_device() -> Device {
        let client = EmulatorClient::new(DEFAULT_MAIN_ADDR)
            .await
            .expect("connect to the KeepKey emulator");
        KeepKey::new(TrezorTransport::new(client)).with_network(Network::Testnet)
    }

    async fn device() -> Device {
        let mut device = raw_device().await;
        device
            .unlock(Network::Testnet)
            .await
            .expect("unlock KeepKey session");
        device
    }

    async fn passphrase_device(value: String) -> Device {
        raw_device()
            .await
            .with_passphrase(Some(HostPassphrase::new(value)))
    }

    async fn decided<F: Future>(button: DebugButton, future: F) -> F::Output {
        DebugLink::connect_default()
            .await
            .expect("connect to KeepKey debuglink")
            .drive(button, future)
            .await
            .expect("drive KeepKey decision")
    }

    async fn approved<F: Future>(future: F) -> F::Output {
        decided(DebugButton::Yes, future).await
    }

    fn assert_error<T, E: std::fmt::Display>(result: Result<T, E>, expected: &str) {
        match result {
            Ok(_) => panic!("operation unexpectedly succeeded"),
            Err(error) => assert_eq!(error.to_string(), expected),
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Wrapper {
        Legacy,
        ShWit,
        Wit,
    }

    impl Wrapper {
        const ALL: [Self; 3] = [Self::Legacy, Self::ShWit, Self::Wit];

        fn purpose(self) -> u32 {
            match self {
                Self::Legacy => 44,
                Self::ShWit => 49,
                Self::Wit => 84,
            }
        }

        fn account_path(self) -> DerivationPath {
            format!("m/{}'/1'/0'", self.purpose()).parse().unwrap()
        }

        fn account_xpub(self) -> Xpub {
            Xpub::from_str(match self {
                Self::Legacy => XPUB_44,
                Self::ShWit => XPUB_49,
                Self::Wit => XPUB_84,
            })
            .unwrap()
        }

        fn address_type(self) -> AddressType {
            match self {
                Self::Legacy => AddressType::P2pkh,
                Self::ShWit => AddressType::P2sh,
                Self::Wit => AddressType::P2wpkh,
            }
        }

        fn script(self, child: Xpub) -> ScriptBuf {
            match self {
                Self::Legacy => Address::p2pkh(PublicKey::new(child.public_key), Network::Testnet)
                    .script_pubkey(),
                Self::ShWit => Address::p2wpkh(&child.to_pub(), Network::Testnet)
                    .script_pubkey()
                    .to_p2sh(),
                Self::Wit => Address::p2wpkh(&child.to_pub(), Network::Testnet).script_pubkey(),
            }
        }

        fn address(self, child: Xpub) -> Address {
            match self {
                Self::Legacy => Address::p2pkh(PublicKey::new(child.public_key), Network::Testnet),
                Self::ShWit => Address::p2shwpkh(&child.to_pub(), Network::Testnet),
                Self::Wit => Address::p2wpkh(&child.to_pub(), Network::Testnet),
            }
        }

        fn multisig_type(self) -> MultisigAddressType {
            match self {
                Self::Legacy => MultisigAddressType::Legacy,
                Self::ShWit => MultisigAddressType::ShWit,
                Self::Wit => MultisigAddressType::Wit,
            }
        }

        fn multisig_script_pubkey(self, script: &ScriptBuf) -> ScriptBuf {
            match self {
                Self::Legacy => script.to_p2sh(),
                Self::ShWit => script.to_p2wsh().to_p2sh(),
                Self::Wit => script.to_p2wsh(),
            }
        }
    }

    fn suffix(change: u32, index: u32) -> DerivationPath {
        DerivationPath::from(vec![
            ChildNumber::from_normal_idx(change).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ])
    }

    fn previous_tx(value: u64, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    struct Spendable {
        previous: Transaction,
        input: Input,
        key: PublicKey,
    }

    fn singlesig_spendable(
        wrapper: Wrapper,
        account_xpub: Xpub,
        fingerprint: Fingerprint,
        account_path: &DerivationPath,
        child_path: DerivationPath,
        value: u64,
    ) -> Spendable {
        let secp = Secp256k1::verification_only();
        let child = account_xpub.derive_pub(&secp, &child_path).unwrap();
        let script_pubkey = wrapper.script(child);
        let previous = previous_tx(value, script_pubkey.clone());
        let witness_utxo = (!matches!(wrapper, Wrapper::Legacy)).then_some(TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        });
        let redeem_script = matches!(wrapper, Wrapper::ShWit)
            .then(|| Address::p2wpkh(&child.to_pub(), Network::Testnet).script_pubkey());
        Spendable {
            previous: previous.clone(),
            input: Input {
                non_witness_utxo: Some(previous),
                witness_utxo,
                redeem_script,
                bip32_derivation: [(
                    child.public_key,
                    (fingerprint, account_path.extend(child_path)),
                )]
                .into(),
                ..Default::default()
            },
            key: PublicKey::new(child.public_key),
        }
    }

    fn singlesig_psbt(wrapper: Wrapper) -> (Psbt, PublicKey) {
        let secp = Secp256k1::verification_only();
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let account_path = wrapper.account_path();
        let account_xpub = wrapper.account_xpub();
        let input = singlesig_spendable(
            wrapper,
            account_xpub,
            fingerprint,
            &account_path,
            suffix(0, 0),
            50_000,
        );
        let change_path = suffix(1, 0);
        let change = account_xpub.derive_pub(&secp, &change_path).unwrap();
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: input.previous.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: wrapper.script(change),
            }],
        })
        .unwrap();
        psbt.inputs[0] = input.input;
        psbt.outputs[0] = PsbtOutput {
            redeem_script: matches!(wrapper, Wrapper::ShWit)
                .then(|| Address::p2wpkh(&change.to_pub(), Network::Testnet).script_pubkey()),
            bip32_derivation: [(
                change.public_key,
                (fingerprint, account_path.extend(change_path)),
            )]
            .into(),
            ..Default::default()
        };
        (psbt, input.key)
    }

    fn verify_signatures(original: &Psbt, signed: &Psbt, expected: &[(usize, &PublicKey)]) {
        let mut normalized = signed.clone();
        let mut cache = SighashCache::new(&original.unsigned_tx);
        let secp = Secp256k1::verification_only();
        for &(input_index, key) in expected {
            let signature = normalized.inputs[input_index]
                .partial_sigs
                .remove(key)
                .expect("device signature for expected key");
            let (message, sighash_type) = original
                .sighash_ecdsa(input_index, &mut cache)
                .expect("recompute ECDSA sighash");
            assert_eq!(signature.sighash_type, sighash_type);
            secp.verify_ecdsa(&message, &signature.signature, &key.inner)
                .expect("device signature verifies against recomputed sighash");
        }
        assert_eq!(
            &normalized, original,
            "signed PSBT changed outside expected partial signatures"
        );
    }

    #[test]
    #[should_panic(expected = "signed PSBT changed outside expected partial signatures")]
    fn psbt_verifier_rejects_non_signature_mutation() {
        let (original, _) = singlesig_psbt(Wrapper::Wit);
        let mut mutated = original.clone();
        mutated.unsigned_tx.output[0].value = Amount::from_sat(48_999);
        verify_signatures(&original, &mutated, &[]);
    }

    #[tokio::test]
    async fn info_fingerprint_and_exact_account_xpubs() {
        let mut device = device().await;
        let info = device.get_info().await.unwrap();
        assert_eq!(info.version, "7.10.0");
        assert_eq!(info.networks, vec![Network::Testnet]);
        assert!(
            info.firmware
                .as_ref()
                .is_some_and(|model| !model.is_empty())
        );
        assert_eq!(info.initialized, Some(true));
        assert_eq!(info.label.as_deref(), Some("test"));
        assert_eq!(info.on_device_passphrase_entry, Some(false));
        assert_eq!(info.needs_pin_sent, Some(false));
        assert_eq!(info.needs_passphrase_sent, Some(false));
        assert_eq!(
            device.get_master_fingerprint().await.unwrap().to_string(),
            FINGERPRINT
        );

        for (path, expected) in [
            ("m/44'/1'/0'", XPUB_44),
            ("m/49'/1'/0'", XPUB_49),
            ("m/84'/1'/0'", XPUB_84),
        ] {
            assert_eq!(
                device
                    .get_extended_pubkey(path.parse().unwrap(), false)
                    .await
                    .unwrap()
                    .to_string(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn legacy_wrapped_and_native_addresses_and_signatures_are_verified() {
        let secp = Secp256k1::verification_only();
        let mut device = device().await;
        for wrapper in Wrapper::ALL {
            let child_path = suffix(0, 0);
            let path = wrapper.account_path().extend(child_path.clone());
            let child = wrapper
                .account_xpub()
                .derive_pub(&secp, &child_path)
                .unwrap();
            let address = approved(device.display_address(
                DisplayAddress::ByPath {
                    path,
                    display: true,
                    address_format: Some(wrapper.address_type()),
                },
                None,
            ))
            .await
            .unwrap();
            assert_eq!(address, wrapper.address(child).to_string());

            let (original, key) = singlesig_psbt(wrapper);
            let signed = approved(device.sign_tx(original.clone(), None))
                .await
                .unwrap();
            verify_signatures(&original, &signed, &[(0, &key)]);
        }
    }

    #[derive(Clone)]
    struct DerivedMultisigKey {
        key: bhwi::bitcoin::secp256k1::PublicKey,
        fingerprint: Fingerprint,
        path: DerivationPath,
    }

    fn sorted_multisig_keys(
        device_xpub: Xpub,
        device_fingerprint: Fingerprint,
        cosigner_xpub: Xpub,
        cosigner_fingerprint: Fingerprint,
        account_path: &DerivationPath,
        child_path: &DerivationPath,
    ) -> Vec<DerivedMultisigKey> {
        let secp = Secp256k1::verification_only();
        let mut keys = vec![
            DerivedMultisigKey {
                key: device_xpub
                    .derive_pub(&secp, child_path)
                    .unwrap()
                    .public_key,
                fingerprint: device_fingerprint,
                path: account_path.extend(child_path.clone()),
            },
            DerivedMultisigKey {
                key: cosigner_xpub
                    .derive_pub(&secp, child_path)
                    .unwrap()
                    .public_key,
                fingerprint: cosigner_fingerprint,
                path: account_path.extend(child_path.clone()),
            },
        ];
        keys.sort_by_key(|key| key.key.serialize());
        keys
    }

    fn multisig_script(keys: &[DerivedMultisigKey]) -> ScriptBuf {
        Builder::new()
            .push_int(2)
            .push_key(&PublicKey::new(keys[0].key))
            .push_key(&PublicKey::new(keys[1].key))
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    fn fully_derived_multisig_display(
        wrapper: Wrapper,
        sorted: bool,
        keys: &[DerivedMultisigKey],
    ) -> DisplayAddress {
        DisplayAddress::ByMultisig(MultisigDisplayAddress {
            threshold: 2,
            address_type: wrapper.multisig_type(),
            sorted,
            keys: keys
                .iter()
                .map(|key| {
                    format!(
                        "[{}/{}]{}",
                        key.fingerprint,
                        key.path,
                        PublicKey::new(key.key)
                    )
                    .parse()
                    .unwrap()
                })
                .collect(),
        })
    }

    fn multisig_psbt(
        wrapper: Wrapper,
        device_xpub: Xpub,
        device_fingerprint: Fingerprint,
        cosigner_xpub: Xpub,
        cosigner_fingerprint: Fingerprint,
        account_path: &DerivationPath,
    ) -> (Psbt, PublicKey) {
        let receive = sorted_multisig_keys(
            device_xpub,
            device_fingerprint,
            cosigner_xpub,
            cosigner_fingerprint,
            account_path,
            &suffix(0, 0),
        );
        let change = sorted_multisig_keys(
            device_xpub,
            device_fingerprint,
            cosigner_xpub,
            cosigner_fingerprint,
            account_path,
            &suffix(1, 0),
        );
        let receive_script = multisig_script(&receive);
        let change_script = multisig_script(&change);
        let receive_script_pubkey = wrapper.multisig_script_pubkey(&receive_script);
        let change_script_pubkey = wrapper.multisig_script_pubkey(&change_script);
        let previous = previous_tx(50_000, receive_script_pubkey.clone());
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: previous.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: change_script_pubkey,
            }],
        })
        .unwrap();
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous),
            witness_utxo: (!matches!(wrapper, Wrapper::Legacy)).then_some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: receive_script_pubkey,
            }),
            redeem_script: match wrapper {
                Wrapper::Legacy => Some(receive_script.clone()),
                Wrapper::ShWit => Some(receive_script.to_p2wsh()),
                Wrapper::Wit => None,
            },
            witness_script: (!matches!(wrapper, Wrapper::Legacy)).then_some(receive_script),
            bip32_derivation: receive
                .iter()
                .map(|key| (key.key, (key.fingerprint, key.path.clone())))
                .collect(),
            ..Default::default()
        };
        psbt.outputs[0] = PsbtOutput {
            redeem_script: match wrapper {
                Wrapper::Legacy => Some(change_script.clone()),
                Wrapper::ShWit => Some(change_script.to_p2wsh()),
                Wrapper::Wit => None,
            },
            witness_script: (!matches!(wrapper, Wrapper::Legacy)).then_some(change_script),
            bip32_derivation: change
                .iter()
                .map(|key| (key.key, (key.fingerprint, key.path.clone())))
                .collect(),
            ..Default::default()
        };
        let device_key = receive
            .iter()
            .find(|key| key.fingerprint == device_fingerprint)
            .map(|key| PublicKey::new(key.key))
            .unwrap();
        (psbt, device_key)
    }

    #[tokio::test]
    async fn sorted_fully_derived_multisig_works_in_all_three_wrappers() {
        let secp = Secp256k1::new();
        let mut device = device().await;
        let device_fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let account_path: DerivationPath = format!("m/{MULTISIG_ORIGIN}").parse().unwrap();
        let device_xpub = device
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .unwrap();
        let cosigner_root = Xpriv::new_master(Network::Testnet, &[9u8; 32]).unwrap();
        let cosigner_fingerprint = cosigner_root.fingerprint(&secp);
        let cosigner_xpub = Xpub::from_priv(
            &secp,
            &cosigner_root.derive_priv(&secp, &account_path).unwrap(),
        );
        let receive = sorted_multisig_keys(
            device_xpub,
            device_fingerprint,
            cosigner_xpub,
            cosigner_fingerprint,
            &account_path,
            &suffix(0, 0),
        );

        for wrapper in Wrapper::ALL {
            let expected = Address::from_script(
                &wrapper.multisig_script_pubkey(&multisig_script(&receive)),
                Network::Testnet,
            )
            .unwrap();
            let displayed = approved(device.display_address(
                fully_derived_multisig_display(wrapper, true, &receive),
                None,
            ))
            .await
            .unwrap();
            assert_eq!(displayed, expected.to_string());

            let (original, key) = multisig_psbt(
                wrapper,
                device_xpub,
                device_fingerprint,
                cosigner_xpub,
                cosigner_fingerprint,
                &account_path,
            );
            let signed = approved(device.sign_tx(original.clone(), None))
                .await
                .unwrap();
            verify_signatures(&original, &signed, &[(0, &key)]);
        }
    }

    #[tokio::test]
    async fn mixed_owned_and_foreign_inputs_sign_only_owned_keys() {
        let secp = Secp256k1::new();
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let legacy_path: DerivationPath = "m/44'/1'/0'".parse().unwrap();
        let native_path: DerivationPath = "m/84'/1'/0'".parse().unwrap();
        let legacy = singlesig_spendable(
            Wrapper::Legacy,
            Xpub::from_str(XPUB_44).unwrap(),
            fingerprint,
            &legacy_path,
            suffix(0, 0),
            20_000,
        );
        let native = singlesig_spendable(
            Wrapper::Wit,
            Xpub::from_str(XPUB_84).unwrap(),
            fingerprint,
            &native_path,
            suffix(0, 1),
            30_000,
        );
        let foreign_root = Xpriv::new_master(Network::Testnet, &[42u8; 32]).unwrap();
        let foreign_fingerprint = foreign_root.fingerprint(&secp);
        let foreign_xpub = Xpub::from_priv(
            &secp,
            &foreign_root.derive_priv(&secp, &native_path).unwrap(),
        );
        let foreign = singlesig_spendable(
            Wrapper::Wit,
            foreign_xpub,
            foreign_fingerprint,
            &native_path,
            suffix(0, 2),
            40_000,
        );
        let change_path = suffix(1, 0);
        let change = Xpub::from_str(XPUB_84)
            .unwrap()
            .derive_pub(&secp, &change_path)
            .unwrap();
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: [&legacy, &native, &foreign]
                .into_iter()
                .map(|input| TxIn {
                    previous_output: OutPoint {
                        txid: input.previous.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(89_000),
                script_pubkey: Wrapper::Wit.script(change),
            }],
        })
        .unwrap();
        psbt.inputs = vec![legacy.input, native.input, foreign.input];
        psbt.outputs[0] = PsbtOutput {
            bip32_derivation: [(
                change.public_key,
                (fingerprint, native_path.extend(change_path)),
            )]
            .into(),
            ..Default::default()
        };

        let original = psbt;
        let mut device = device().await;
        let signed = approved(device.sign_tx(original.clone(), None))
            .await
            .unwrap();
        verify_signatures(&original, &signed, &[(0, &legacy.key), (1, &native.key)]);
    }

    #[tokio::test]
    async fn op_return_and_foreign_taproot_outputs_are_supported() {
        let secp = Secp256k1::new();
        let (mut original, key) = singlesig_psbt(Wrapper::Wit);
        original.unsigned_tx.output[0].value = Amount::from_sat(29_000);
        let foreign_root = Xpriv::new_master(Network::Testnet, &[33u8; 32]).unwrap();
        let foreign_key = Xpub::from_priv(&secp, &foreign_root)
            .public_key
            .x_only_public_key()
            .0;
        original.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: Address::p2tr(&secp, foreign_key, None, Network::Testnet)
                .script_pubkey(),
        });
        original.outputs.push(Default::default());
        let payload: [u8; 32] = core::array::from_fn(|index| index as u8);
        let data: &bhwi::bitcoin::script::PushBytes = payload.as_slice().try_into().unwrap();
        original.unsigned_tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(data),
        });
        original.outputs.push(Default::default());

        let mut device = device().await;
        let signed = approved(device.sign_tx(original.clone(), None))
            .await
            .unwrap();
        verify_signatures(&original, &signed, &[(0, &key)]);
    }

    #[tokio::test]
    async fn message_signature_recovers_the_derived_key() {
        let secp = Secp256k1::verification_only();
        let child_path = suffix(0, 0);
        let expected = PublicKey::new(
            Xpub::from_str(XPUB_44)
                .unwrap()
                .derive_pub(&secp, &child_path)
                .unwrap()
                .public_key,
        );
        let message = "hello";
        let mut device = device().await;
        let (header, signature) = approved(device.sign_message(
            message.as_bytes(),
            DerivationPath::from_str("m/44'/1'/0'/0/0").unwrap(),
        ))
        .await
        .unwrap();
        let mut payload = Vec::with_capacity(65);
        payload.push(header);
        payload.extend_from_slice(&signature.serialize_compact());
        let recovered = MessageSignature::from_slice(&payload)
            .unwrap()
            .recover_pubkey(&secp, signed_msg_hash(message))
            .unwrap();
        assert_eq!(recovered, expected);
    }

    #[tokio::test]
    async fn declined_signature_leaves_the_next_session_healthy() {
        let (psbt, _) = singlesig_psbt(Wrapper::Wit);
        let mut wallet = device().await;
        assert_error(
            decided(DebugButton::No, wallet.sign_tx(psbt, None)).await,
            "interpreter error: authentication refused",
        );
        let mut next = device().await;
        assert_eq!(
            next.get_master_fingerprint().await.unwrap().to_string(),
            FINGERPRINT
        );
    }

    fn owned_taproot_psbt(bip86_account_xpub: Xpub) -> Psbt {
        let secp = Secp256k1::verification_only();
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let path: DerivationPath = "m/86'/1'/0'/0/0".parse().unwrap();
        let child = bip86_account_xpub.derive_pub(&secp, &suffix(0, 0)).unwrap();
        let internal_key = XOnlyPublicKey::from(child.public_key);
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);
        let previous = previous_tx(50_000, script_pubkey.clone());
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: previous.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
            }],
        })
        .unwrap();
        psbt.inputs[0] = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey,
            }),
            tap_internal_key: Some(internal_key),
            tap_key_origins: [(internal_key, (Vec::new(), (fingerprint, path)))].into(),
            ..Default::default()
        };
        psbt
    }

    fn owned_taproot_change_psbt(bip86_account_xpub: Xpub) -> Psbt {
        let secp = Secp256k1::verification_only();
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let (mut psbt, _) = singlesig_psbt(Wrapper::Wit);
        let path: DerivationPath = "m/86'/1'/0'/1/0".parse().unwrap();
        let key = bip86_account_xpub
            .derive_pub(&secp, &suffix(1, 0))
            .unwrap()
            .public_key
            .x_only_public_key()
            .0;
        psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::new_p2tr(&secp, key, None);
        psbt.outputs[0] = PsbtOutput {
            tap_internal_key: Some(key),
            tap_key_origins: [(key, (Vec::new(), (fingerprint, path)))].into(),
            ..Default::default()
        };
        psbt
    }

    #[tokio::test]
    async fn taproot_rejection_fixtures_match_their_bip86_origins() {
        let secp = Secp256k1::verification_only();
        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let account_path: DerivationPath = "m/86'/1'/0'".parse().unwrap();
        let mut device = device().await;
        let account_xpub = device
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .unwrap();

        let receive_path = suffix(0, 0);
        let receive_key = account_xpub
            .derive_pub(&secp, &receive_path)
            .unwrap()
            .public_key
            .x_only_public_key()
            .0;
        let owned_input = owned_taproot_psbt(account_xpub);
        assert_eq!(owned_input.inputs[0].tap_internal_key, Some(receive_key));
        assert_eq!(owned_input.inputs[0].tap_key_origins.len(), 1);
        assert_eq!(
            owned_input.inputs[0].tap_key_origins.get(&receive_key),
            Some(&(Vec::new(), (fingerprint, account_path.extend(receive_path)),))
        );

        let change_path = suffix(1, 0);
        let change_key = account_xpub
            .derive_pub(&secp, &change_path)
            .unwrap()
            .public_key
            .x_only_public_key()
            .0;
        let owned_change = owned_taproot_change_psbt(account_xpub);
        assert_eq!(owned_change.outputs[0].tap_internal_key, Some(change_key));
        assert_eq!(owned_change.outputs[0].tap_key_origins.len(), 1);
        assert_eq!(
            owned_change.outputs[0].tap_key_origins.get(&change_key),
            Some(&(Vec::new(), (fingerprint, account_path.extend(change_path)),))
        );
    }

    #[tokio::test]
    async fn unsupported_taproot_multisig_registration_and_backup_are_exact() {
        let secp = Secp256k1::new();
        let mut device = device().await;
        let bip86_account_xpub = device
            .get_extended_pubkey("m/86'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_error(
            device
                .display_address(
                    DisplayAddress::ByPath {
                        path: "m/86'/1'/0'/0/0".parse().unwrap(),
                        display: true,
                        address_format: Some(AddressType::P2tr),
                    },
                    None,
                )
                .await,
            "interpreter error: unsupported display address: KeepKey does not support Taproot address display",
        );
        assert_error(
            device
                .sign_tx(owned_taproot_psbt(bip86_account_xpub), None)
                .await,
            "interpreter error: missing command info: KeepKey does not support Taproot inputs",
        );
        assert_error(
            device
                .sign_tx(owned_taproot_change_psbt(bip86_account_xpub), None)
                .await,
            "interpreter error: missing command info: KeepKey does not support Taproot change outputs",
        );

        let fingerprint = Fingerprint::from_str(FINGERPRINT).unwrap();
        let account_path: DerivationPath = format!("m/{MULTISIG_ORIGIN}").parse().unwrap();
        let device_xpub = device
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .unwrap();
        let cosigner_root = Xpriv::new_master(Network::Testnet, &[9u8; 32]).unwrap();
        let cosigner_fingerprint = cosigner_root.fingerprint(&secp);
        let cosigner_xpub = Xpub::from_priv(
            &secp,
            &cosigner_root.derive_priv(&secp, &account_path).unwrap(),
        );
        let receive = sorted_multisig_keys(
            device_xpub,
            fingerprint,
            cosigner_xpub,
            cosigner_fingerprint,
            &account_path,
            &suffix(0, 0),
        );
        assert_error(
            device
                .display_address(
                    fully_derived_multisig_display(Wrapper::Wit, false, &receive),
                    None,
                )
                .await,
            "interpreter error: unsupported display address: KeepKey does not support unsorted multisig address display",
        );
        let xpub_multisig = DisplayAddress::ByMultisig(MultisigDisplayAddress {
            threshold: 2,
            address_type: MultisigAddressType::Wit,
            sorted: true,
            keys: vec![
                format!("[{fingerprint}/{MULTISIG_ORIGIN}]{device_xpub}/0/0")
                    .parse()
                    .unwrap(),
                format!("[{cosigner_fingerprint}/{MULTISIG_ORIGIN}]{cosigner_xpub}/0/0")
                    .parse()
                    .unwrap(),
            ],
        });
        assert_error(
            device.display_address(xpub_multisig, None).await,
            "interpreter error: unsupported display address: KeepKey multisig address display requires fully-derived public keys",
        );
        let policy = format!("wpkh([{FINGERPRINT}/84'/1'/0']{XPUB_84}/0/*)");
        assert_error(
            device.register_wallet("keepkey-e2e", &policy).await,
            "interpreter error: missing command info: register_wallet is not supported",
        );
        assert_error(
            device.backup_device().await,
            "interpreter error: missing command info: The Keepkey does not support creating a backup via software",
        );
    }

    #[tokio::test]
    async fn exact_no_pin_and_invalid_pin_errors() {
        let mut wallet = device().await;
        assert_error(
            wallet.prompt_pin().await,
            "interpreter error: This device does not need a PIN",
        );
        let mut device = device().await;
        assert_error(
            device
                .send_pin(Some(DeviceContext::KeepKeyManagement(
                    ManagementContext::Pin(HostPin::new("1234".into()).unwrap()),
                )))
                .await,
            "interpreter error: This device does not need a PIN",
        );
        let error = match HostPin::new("notnum".into()) {
            Ok(_) => panic!("non-numeric PIN unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "Non-numeric PIN provided");
    }

    #[derive(Default)]
    struct InteractionCounts {
        pin_kinds: RefCell<Vec<PinMatrixRequestKind>>,
        recovery_requests: Cell<usize>,
    }

    struct CountingInteraction {
        inner: KeepKeyHostInteraction,
        counts: Rc<InteractionCounts>,
    }

    #[async_trait(?Send)]
    impl HostInteraction for CountingInteraction {
        async fn respond(
            &mut self,
            request: &HostRequest,
        ) -> Result<HostResponse, bhwi::common::Error> {
            match request {
                HostRequest::PinMatrix { kind } => self.counts.pin_kinds.borrow_mut().push(*kind),
                HostRequest::RecoveryCharacter { .. } => self
                    .counts
                    .recovery_requests
                    .set(self.counts.recovery_requests.get() + 1),
            }
            self.inner.host_response(request).await
        }
    }

    async fn management_device(counts: Rc<InteractionCounts>) -> Device {
        let interaction = KeepKeyHostInteraction::connect_default(TEST_PIN, SYNTHETIC_MNEMONIC)
            .await
            .expect("connect management host interaction");
        raw_device()
            .await
            .with_host_interaction(Box::new(CountingInteraction {
                inner: interaction,
                counts,
            }))
    }

    fn pin_context(positions: String) -> DeviceContext {
        DeviceContext::KeepKeyManagement(ManagementContext::Pin(HostPin::new(positions).unwrap()))
    }

    async fn finish_pending_toggle(device: &mut Device) {
        let debug = DebugLink::connect_default()
            .await
            .expect("connect toggle debuglink");
        assert!(
            debug
                .drive(DebugButton::Yes, device.toggle_passphrase())
                .await
                .unwrap()
                .unwrap()
        );
        let positions = debug.pin_positions(TEST_PIN).await.unwrap();
        assert!(device.send_pin(Some(pin_context(positions))).await.unwrap());
    }

    async fn fingerprint_with_passphrase(value: String) -> Fingerprint {
        let mut device = passphrase_device(value).await;
        device.unlock(Network::Testnet).await.unwrap();
        let debug = DebugLink::connect_default().await.unwrap();
        debug
            .drive(DebugButton::Yes, device.get_master_fingerprint())
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires a fresh KeepKey emulator image"]
    async fn keepkey_management_lifecycle() {
        let setup_counts = Rc::new(InteractionCounts::default());
        let mut device = management_device(setup_counts.clone()).await;
        assert!(
            approved(device.setup_device(
                SetupOptions {
                    label: "BHWI KeepKey E2E".into(),
                    backup_passphrase: String::new(),
                },
                Some(DeviceContext::KeepKeyManagement(ManagementContext::Setup {
                    host_entropy: [7u8; 32],
                },)),
            ))
            .await
            .unwrap()
        );
        assert_eq!(
            setup_counts.pin_kinds.borrow().as_slice(),
            &[
                PinMatrixRequestKind::NewFirst,
                PinMatrixRequestKind::NewSecond
            ]
        );
        let info = device.get_info().await.unwrap();
        assert_eq!(info.initialized, Some(true));
        assert_eq!(info.label.as_deref(), Some("BHWI KeepKey E2E"));

        assert!(approved(device.wipe_device()).await.unwrap());
        drop(device);
        let mut uninitialized = raw_device().await;
        assert_eq!(
            uninitialized.get_info().await.unwrap().initialized,
            Some(false)
        );
        drop(uninitialized);

        let restore_counts = Rc::new(InteractionCounts::default());
        let mut restored = management_device(restore_counts.clone()).await;
        assert!(
            approved(restored.restore_device(
                RestoreOptions {
                    label: "BHWI KeepKey Restored".into(),
                    word_count: 12,
                },
                Some(DeviceContext::KeepKeyManagement(
                    ManagementContext::Restore { u2f_counter: 1 },
                )),
            ))
            .await
            .unwrap()
        );
        assert_eq!(
            restore_counts.pin_kinds.borrow().as_slice(),
            &[
                PinMatrixRequestKind::NewFirst,
                PinMatrixRequestKind::NewSecond
            ]
        );
        assert!(restore_counts.recovery_requests.get() >= 12);
        assert_eq!(
            restored.get_master_fingerprint().await.unwrap().to_string(),
            FINGERPRINT
        );
        let info = restored.get_info().await.unwrap();
        assert_eq!(info.initialized, Some(true));
        assert_eq!(info.label.as_deref(), Some("BHWI KeepKey Restored"));
        drop(restored);

        lock_device(DEFAULT_MAIN_ADDR).await.unwrap();
        let mut toggle = raw_device().await;
        finish_pending_toggle(&mut toggle).await;
        assert_eq!(
            toggle.get_info().await.unwrap().needs_passphrase_sent,
            Some(true)
        );

        let empty = fingerprint_with_passphrase(String::new()).await;
        let first = fingerprint_with_passphrase("fixture-passphrase-one".into()).await;
        let second = fingerprint_with_passphrase("fixture-passphrase-two".into()).await;
        assert_eq!(empty.to_string(), FINGERPRINT);
        assert_ne!(first, empty);
        assert_ne!(second, empty);
        assert_ne!(first, second);
        let mut too_long = passphrase_device("x".repeat(51)).await;
        too_long.unlock(Network::Testnet).await.unwrap();
        assert_error(
            too_long.get_master_fingerprint().await,
            "interpreter error: invalid input: Passphrase too long",
        );

        lock_device(DEFAULT_MAIN_ADDR).await.unwrap();
        let mut locked = raw_device().await;
        let info = locked.get_info().await.unwrap();
        assert_eq!(info.needs_pin_sent, Some(true));
        assert_eq!(info.needs_passphrase_sent, Some(true));
        assert!(locked.prompt_pin().await.unwrap());
        let debug = DebugLink::connect_default().await.unwrap();
        let positions = debug.pin_positions(TEST_PIN).await.unwrap();
        assert!(
            debug
                .drive(
                    DebugButton::Yes,
                    locked.send_pin(Some(pin_context(positions))),
                )
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(locked.get_info().await.unwrap().needs_pin_sent, Some(false));
        assert_error(
            locked.prompt_pin().await,
            "interpreter error: The PIN has already been sent to this device",
        );
        drop(locked);

        lock_device(DEFAULT_MAIN_ADDR).await.unwrap();
        let mut toggle = raw_device().await;
        finish_pending_toggle(&mut toggle).await;
        assert_eq!(
            toggle.get_info().await.unwrap().needs_passphrase_sent,
            Some(false)
        );
        assert_eq!(
            fingerprint_with_passphrase("ignored-when-disabled".into())
                .await
                .to_string(),
            FINGERPRINT
        );

        lock_device(DEFAULT_MAIN_ADDR).await.unwrap();
        let mut wrong = raw_device().await;
        assert!(wrong.prompt_pin().await.unwrap());
        assert!(
            !wrong
                .send_pin(Some(pin_context("1111".into())))
                .await
                .unwrap()
        );

        drop(wrong);
        lock_device(DEFAULT_MAIN_ADDR).await.unwrap();
        let mut recovered = raw_device().await;
        assert!(recovered.prompt_pin().await.unwrap());
        let debug = DebugLink::connect_default().await.unwrap();
        let positions = debug.pin_positions(TEST_PIN).await.unwrap();
        assert!(
            debug
                .drive(
                    DebugButton::Yes,
                    recovered.send_pin(Some(pin_context(positions))),
                )
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            recovered
                .get_master_fingerprint()
                .await
                .unwrap()
                .to_string(),
            FINGERPRINT
        );
        assert_eq!(
            recovered.get_info().await.unwrap().needs_pin_sent,
            Some(false)
        );
    }
}
