//! Specter-DIY simulator coverage using its pinned synthetic wallet.

#[cfg(test)]
mod tests {
    use std::{
        env,
        str::FromStr,
        time::{Duration, Instant},
    };

    use async_trait::async_trait;
    use bhwi::{
        bitcoin::{
            Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
            Witness,
            absolute::LockTime,
            address::Address,
            bip32::{ChildNumber, DerivationPath},
            hashes::Hash,
            key::TapTweak,
            psbt::{Input, Output, Psbt},
            secp256k1::{Message, Secp256k1},
            sighash::{Prevouts, SighashCache},
            sign_message::{MessageSignature, signed_msg_hash},
            taproot::Signature as TaprootSignature,
            transaction::Version as TxVersion,
        },
        common::DeviceContext,
    };
    use bhwi_async::{
        DisplayAddress, HWI, Specter,
        transport::specter::{SpecterStream, SpecterStreamError, SpecterTransport},
    };
    use miniscript::descriptor::WalletPolicy;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::{Instant as TokioInstant, timeout_at},
    };

    const USB_ADDRESS: &str = "127.0.0.1:8789";
    const FINGERPRINT: &str = "73c5da0a";
    const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
    const MENU_TIMEOUT: Duration = Duration::from_secs(3);
    const MAX_SCREEN_LINE: usize = 128;

    struct TcpSpecterStream(TcpStream);

    #[async_trait(?Send)]
    impl SpecterStream for TcpSpecterStream {
        type Error = std::io::Error;

        async fn write_all(
            &mut self,
            request: &[u8],
        ) -> Result<(), SpecterStreamError<Self::Error>> {
            self.0
                .write_all(request)
                .await
                .map_err(SpecterStreamError::Io)
        }

        async fn read_until(
            &mut self,
            buffer: &mut [u8],
            deadline: Instant,
        ) -> Result<usize, SpecterStreamError<Self::Error>> {
            timeout_at(TokioInstant::from_std(deadline), self.0.read(buffer))
                .await
                .map_err(|_| SpecterStreamError::Timeout)?
                .map_err(SpecterStreamError::Io)
        }
    }

    type Device = Specter<SpecterTransport<TcpSpecterStream>>;

    async fn device() -> Device {
        let stream = TcpStream::connect(USB_ADDRESS)
            .await
            .expect("Specter USB TCP");
        Device::new(
            Network::Bitcoin,
            SpecterTransport::new(TcpSpecterStream(stream))
                .with_confirmation_timeout(OPERATION_TIMEOUT),
        )
    }

    #[derive(Default)]
    struct ScreenCodec(Vec<u8>);

    impl ScreenCodec {
        fn push(&mut self, data: &[u8]) {
            self.0.extend_from_slice(data);
            assert!(
                self.0.len() <= MAX_SCREEN_LINE,
                "Specter GUI screen line exceeded the bounded controller buffer"
            );
        }

        fn next(&mut self) -> Option<String> {
            let end = self.0.iter().position(|byte| *byte == b'\n')?;
            let mut line = self.0.drain(..=end).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            assert!(!line.is_empty(), "Specter GUI sent an empty screen line");
            assert!(
                line.iter().all(u8::is_ascii_alphanumeric),
                "Specter GUI sent a non-screen controller line"
            );
            Some(String::from_utf8(line).expect("Specter GUI screen name is UTF-8"))
        }
    }

    struct GuiController {
        stream: TcpStream,
        codec: ScreenCodec,
    }

    impl GuiController {
        /// TCPGUI writes CRLF-delimited screen class names to one persistent
        /// controller connection. A response applies to exactly one screen.
        async fn connect() -> Self {
            let port = env::var("SPECTER_GUI_PORT").unwrap_or_else(|_| "8787".into());
            let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .expect("Specter GUI TCP");
            // TCPHost polls the accepted controller every 30ms. This only
            // waits for socket adoption; prompt readiness is line-driven.
            tokio::time::sleep(Duration::from_millis(100)).await;
            Self {
                stream,
                codec: ScreenCodec::default(),
            }
        }

        async fn next_screen(&mut self, scenario: &str, deadline: TokioInstant) -> String {
            loop {
                if let Some(screen) = self.codec.next() {
                    return screen;
                }
                let mut bytes = [0; 64];
                let received = timeout_at(deadline, self.stream.read(&mut bytes))
                    .await
                    .unwrap_or_else(|_| panic!("{scenario}: Specter GUI screen deadline elapsed"))
                    .unwrap_or_else(|_| panic!("{scenario}: Specter GUI controller read failed"));
                assert!(
                    received > 0,
                    "{scenario}: Specter GUI controller closed before a screen line"
                );
                self.codec.push(&bytes[..received]);
            }
        }

        async fn reply(&mut self, scenario: &str, value: bool) {
            self.stream
                .write_all(if value { b"true\r\n" } else { b"false\r\n" })
                .await
                .unwrap_or_else(|_| panic!("{scenario}: write Specter GUI response"));
        }

        async fn expect_menu(&mut self, scenario: &str) {
            let screen = self
                .next_screen(scenario, TokioInstant::now() + MENU_TIMEOUT)
                .await;
            assert_eq!(screen, "Menu", "{scenario}: expected trailing GUI Menu");
        }

        async fn respond_with<T>(
            &mut self,
            scenario: &str,
            operation: impl std::future::Future<Output = T>,
            value: bool,
        ) -> T {
            let deadline = TokioInstant::now() + OPERATION_TIMEOUT;
            tokio::pin!(operation);
            let mut saw_menu = false;
            loop {
                tokio::select! {
                    result = &mut operation => {
                        if !saw_menu {
                            self.expect_menu(scenario).await;
                        }
                        return result;
                    }
                    screen = self.next_screen(scenario, deadline) => {
                        if screen == "Menu" {
                            saw_menu = true;
                        } else {
                            self.reply(scenario, value).await;
                        }
                    }
                }
            }
        }
    }

    async fn confirm_with<T>(
        gui: &mut GuiController,
        scenario: &str,
        operation: impl std::future::Future<Output = T>,
    ) -> T {
        gui.respond_with(scenario, operation, true).await
    }

    fn child_path(branch: u32, index: u32) -> DerivationPath {
        DerivationPath::from(vec![
            ChildNumber::from_normal_idx(branch).expect("normal branch"),
            ChildNumber::from_normal_idx(index).expect("normal index"),
        ])
    }

    fn previous_tx(script_pubkey: ScriptBuf) -> Transaction {
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
                value: Amount::from_sat(50_000),
                script_pubkey,
            }],
        }
    }

    fn unsigned_psbt(input: ScriptBuf, change: ScriptBuf) -> Psbt {
        let previous = previous_tx(input);
        Psbt::from_unsigned_tx(Transaction {
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
                script_pubkey: change,
            }],
        })
        .expect("unsigned PSBT")
    }

    async fn account(
        device: &mut Device,
    ) -> (
        bhwi::bitcoin::bip32::Fingerprint,
        bhwi::bitcoin::bip32::Xpub,
    ) {
        let fingerprint = device.get_master_fingerprint().await.expect("fingerprint");
        let xpub = device
            .get_extended_pubkey("m/84'/0'/0'".parse().expect("account path"), false)
            .await
            .expect("account xpub");
        (fingerprint, xpub)
    }

    async fn reads_fingerprint_and_xpub(device: &mut Device) {
        assert_eq!(
            device.get_master_fingerprint().await.unwrap().to_string(),
            FINGERPRINT
        );
        let xpub = device
            .get_extended_pubkey("m/84'/0'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert!(xpub.to_string().starts_with("xpub"));
        assert!(
            device
                .get_extended_pubkey("m/84'/0'/0'".parse().unwrap(), true)
                .await
                .is_err()
        );
    }

    async fn imports_wallet_and_verifies_displayed_descriptor_address(
        device: &mut Device,
        gui: &mut GuiController,
    ) {
        let (fingerprint, _) = account(device).await;
        let account = std::process::id() % 10_000;
        let account_path = format!("m/44'/0'/{account}'");
        let xpub = device
            .get_extended_pubkey(account_path.parse().expect("legacy account path"), false)
            .await
            .expect("legacy account xpub");
        let policy = format!(
            "wpkh([{fingerprint}/{}]{xpub}/<0;1>/*)",
            account_path.trim_start_matches("m/")
        );
        let name = format!("specter-e2e-{}", std::process::id());
        let registered =
            confirm_with(gui, "wallet import", device.register_wallet(&name, &policy)).await;
        assert!(registered.is_ok(), "wallet registration failed");

        let displayed = confirm_with(
            gui,
            "descriptor address",
            device.display_address(
                DisplayAddress::ByDescriptor {
                    index: 0,
                    change: false,
                    display: true,
                    descriptor_name: name,
                },
                Some(DeviceContext::Specter {
                    policy: WalletPolicy::from_str(&policy).expect("wallet policy"),
                }),
            ),
        )
        .await
        .expect("display descriptor address");
        let expected = Address::p2wpkh(
            &xpub
                .derive_pub(&Secp256k1::verification_only(), &child_path(0, 0))
                .expect("receive child")
                .to_pub(),
            Network::Bitcoin,
        )
        .to_string();
        assert_eq!(displayed, expected);
    }

    async fn signs_a_legacy_message_and_reports_refusal(
        device: &mut Device,
        gui: &mut GuiController,
    ) {
        let secp = Secp256k1::verification_only();
        let message = "BHWI Specter-DIY synthetic message fixture";
        let xpub = device
            .get_extended_pubkey("m/84'/0'/0'".parse().unwrap(), false)
            .await
            .expect("message account xpub");
        let expected = PublicKey::new(
            xpub.derive_pub(&secp, &child_path(0, 0))
                .expect("message child pubkey")
                .public_key,
        );
        let signed = confirm_with(
            gui,
            "message approval",
            device.sign_message(message.as_bytes(), "m/84'/0'/0'/0/0".parse().unwrap()),
        )
        .await
        .expect("sign synthetic message");
        let mut payload = Vec::with_capacity(65);
        payload.push(signed.0);
        payload.extend_from_slice(&signed.1.serialize_compact());
        let recovered = MessageSignature::from_slice(&payload)
            .expect("compact message signature")
            .recover_pubkey(&secp, signed_msg_hash(message))
            .expect("recover message signing pubkey");
        assert_eq!(recovered, expected);

        let refused = gui
            .respond_with(
                "message refusal",
                device.sign_message(b"BHWI refusal fixture", "m/84'/0'/0'/0/0".parse().unwrap()),
                false,
            )
            .await;
        assert!(refused.is_err(), "unconfirmed message was accepted");
    }

    async fn signs_native_segwit_psbt_without_losing_metadata(
        device: &mut Device,
        gui: &mut GuiController,
    ) {
        let (fingerprint, xpub) = account(device).await;
        let secp = Secp256k1::verification_only();
        let input_path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
        let change_path: DerivationPath = "m/84'/0'/0'/1/0".parse().unwrap();
        let input_xpub = xpub.derive_pub(&secp, &child_path(0, 0)).unwrap();
        let change_xpub = xpub.derive_pub(&secp, &child_path(1, 0)).unwrap();
        let input_pubkey = PublicKey::new(input_xpub.public_key);
        let change_pubkey = PublicKey::new(change_xpub.public_key);
        let input_script = Address::p2wpkh(&input_xpub.to_pub(), Network::Bitcoin).script_pubkey();
        let change_script =
            Address::p2wpkh(&change_xpub.to_pub(), Network::Bitcoin).script_pubkey();
        let previous = previous_tx(input_script.clone());
        let mut psbt = unsigned_psbt(input_script.clone(), change_script);
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous),
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

        let original = psbt.clone();
        let signed = confirm_with(gui, "native SegWit signing", device.sign_tx(psbt, None))
            .await
            .expect("sign native SegWit PSBT");
        let signature = signed.inputs[0]
            .partial_sigs
            .get(&input_pubkey)
            .expect("native SegWit signature for derived input key");
        assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
        let sighash_type = signed.inputs[0]
            .ecdsa_hash_ty()
            .expect("standard native SegWit sighash type");
        assert_eq!(signature.sighash_type, sighash_type);
        let sighash = SighashCache::new(&original.unsigned_tx)
            .p2wpkh_signature_hash(
                0,
                &original.inputs[0]
                    .witness_utxo
                    .as_ref()
                    .expect("native SegWit witness UTXO")
                    .script_pubkey,
                original.inputs[0]
                    .witness_utxo
                    .as_ref()
                    .expect("native SegWit witness UTXO")
                    .value,
                sighash_type,
            )
            .expect("native SegWit sighash");
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &signature.signature,
            &input_pubkey.inner,
        )
        .expect("native SegWit signature verifies");
        assert!(signed.inputs[0].non_witness_utxo.is_some());
    }

    async fn signs_legacy_ecdsa_psbt(device: &mut Device, gui: &mut GuiController) {
        let fingerprint = device.get_master_fingerprint().await.unwrap();
        let account_path: DerivationPath = "m/44'/0'/0'".parse().unwrap();
        let xpub = device
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .unwrap();
        let secp = Secp256k1::verification_only();
        let input_path = account_path.extend(child_path(0, 0));
        let change_path = account_path.extend(child_path(1, 0));
        let input_xpub = xpub.derive_pub(&secp, &child_path(0, 0)).unwrap();
        let change_xpub = xpub.derive_pub(&secp, &child_path(1, 0)).unwrap();
        let input_pubkey = PublicKey::new(input_xpub.public_key);
        let change_pubkey = PublicKey::new(change_xpub.public_key);
        let input_script = Address::p2pkh(input_pubkey, Network::Bitcoin).script_pubkey();
        let change_script = Address::p2pkh(change_pubkey, Network::Bitcoin).script_pubkey();
        let previous = previous_tx(input_script.clone());
        let mut psbt = unsigned_psbt(input_script, change_script);
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous),
            bip32_derivation: [(input_pubkey.inner, (fingerprint, input_path))].into(),
            ..Default::default()
        };
        psbt.outputs[0] = Output {
            bip32_derivation: [(change_pubkey.inner, (fingerprint, change_path))].into(),
            ..Default::default()
        };

        let original = psbt.clone();
        let signed = tokio::time::timeout(
            Duration::from_secs(30),
            confirm_with(gui, "legacy ECDSA signing", device.sign_tx(psbt, None)),
        )
        .await
        .expect("legacy ECDSA PSBT signing timed out")
        .expect("sign legacy ECDSA PSBT");
        let signature = signed.inputs[0]
            .partial_sigs
            .get(&input_pubkey)
            .expect("legacy signature for derived input key");
        assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
        let sighash_type = signed.inputs[0]
            .ecdsa_hash_ty()
            .expect("standard legacy sighash type");
        assert_eq!(signature.sighash_type, sighash_type);
        let spent_script = &original.inputs[0]
            .non_witness_utxo
            .as_ref()
            .expect("legacy non-witness UTXO")
            .output[original.unsigned_tx.input[0].previous_output.vout as usize]
            .script_pubkey;
        let sighash = SighashCache::new(&original.unsigned_tx)
            .legacy_signature_hash(0, spent_script, sighash_type.to_u32())
            .expect("legacy sighash");
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &signature.signature,
            &input_pubkey.inner,
        )
        .expect("legacy ECDSA signature verifies");
        assert!(signed.inputs[0].non_witness_utxo.is_some());
    }

    async fn signs_taproot_key_path_into_final_witness(
        device: &mut Device,
        gui: &mut GuiController,
    ) {
        let fingerprint = device.get_master_fingerprint().await.unwrap();
        let account = std::process::id() % 10_000;
        let account_path: DerivationPath = format!("m/86'/0'/{account}'").parse().unwrap();
        let xpub = device
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .unwrap();
        let policy = format!(
            "tr([{fingerprint}/{}]{xpub}/<0;1>/*)",
            account_path.to_string().trim_start_matches("m/")
        );
        let name = format!("specter-taproot-{}", std::process::id());
        confirm_with(
            gui,
            "Taproot wallet import",
            device.register_wallet(&name, &policy),
        )
        .await
        .expect("register Taproot wallet");
        let secp = Secp256k1::verification_only();
        let input_path = account_path.extend(child_path(0, 0));
        let change_path = account_path.extend(child_path(1, 0));
        let input = xpub.derive_pub(&secp, &child_path(0, 0)).unwrap();
        let change = xpub.derive_pub(&secp, &child_path(1, 0)).unwrap();
        let input_key = PublicKey::new(input.public_key);
        let change_key = PublicKey::new(change.public_key);
        let input_xonly = input_key.inner.x_only_public_key().0;
        let change_xonly = change_key.inner.x_only_public_key().0;
        let input_script =
            Address::p2tr(&secp, input_xonly, None, Network::Bitcoin).script_pubkey();
        let change_script =
            Address::p2tr(&secp, change_xonly, None, Network::Bitcoin).script_pubkey();
        let previous = previous_tx(input_script.clone());
        let mut psbt = unsigned_psbt(input_script.clone(), change_script);
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous),
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: input_script,
            }),
            tap_internal_key: Some(input_xonly),
            tap_key_origins: [(input_xonly, (Vec::new(), (fingerprint, input_path)))].into(),
            ..Default::default()
        };
        psbt.outputs[0] = Output {
            tap_internal_key: Some(change_xonly),
            tap_key_origins: [(change_xonly, (Vec::new(), (fingerprint, change_path)))].into(),
            ..Default::default()
        };

        let original = psbt.clone();
        let signed = tokio::time::timeout(
            Duration::from_secs(30),
            confirm_with(gui, "Taproot key-path signing", device.sign_tx(psbt, None)),
        )
        .await
        .expect("Taproot key-path signing timed out")
        .expect("sign Taproot key path PSBT");
        let witness = signed.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("Taproot final witness");
        assert_eq!(
            witness.len(),
            1,
            "Taproot key-path witness has one signature"
        );
        let signature =
            TaprootSignature::from_slice(witness.iter().next().expect("Taproot witness signature"))
                .expect("parse Taproot witness signature");
        let prevouts = vec![
            original.inputs[0]
                .witness_utxo
                .clone()
                .expect("Taproot witness UTXO"),
        ];
        let sighash = SighashCache::new(&original.unsigned_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), signature.sighash_type)
            .expect("Taproot key-path sighash");
        let tweaked = input_xonly.tap_tweak(&secp, None).0.to_x_only_public_key();
        secp.verify_schnorr(&signature.signature, &Message::from(sighash), &tweaked)
            .expect("Taproot key-path signature verifies");
        assert!(signed.inputs[0].tap_key_sig.is_none());
    }

    async fn rejects_undisplayed_and_taproot_address_requests(device: &mut Device) {
        assert!(
            device
                .display_address(
                    DisplayAddress::ByPath {
                        path: "m/84'/0'/0'/0/0".parse().unwrap(),
                        display: false,
                        address_format: None,
                    },
                    None,
                )
                .await
                .is_err()
        );
        assert!(
            device
                .display_address(
                    DisplayAddress::ByPath {
                        path: "m/86'/0'/0'/0/0".parse().unwrap(),
                        display: true,
                        address_format: Some(bhwi::bitcoin::address::AddressType::P2tr),
                    },
                    None,
                )
                .await
                .is_err()
        );
    }

    #[test]
    fn screen_codec_retains_fragmented_and_coalesced_lines() {
        let mut codec = ScreenCodec::default();
        codec.push(b"Prom");
        assert!(codec.next().is_none());
        codec.push(b"pt\r\nMenu\r\n");
        assert_eq!(codec.next().as_deref(), Some("Prompt"));
        assert_eq!(codec.next().as_deref(), Some("Menu"));
        assert!(codec.next().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn specter_device_scenarios() {
        let mut gui = GuiController::connect().await;
        let mut device = device().await;

        reads_fingerprint_and_xpub(&mut device).await;
        imports_wallet_and_verifies_displayed_descriptor_address(&mut device, &mut gui).await;
        signs_a_legacy_message_and_reports_refusal(&mut device, &mut gui).await;
        signs_native_segwit_psbt_without_losing_metadata(&mut device, &mut gui).await;
        signs_legacy_ecdsa_psbt(&mut device, &mut gui).await;
        signs_taproot_key_path_into_final_witness(&mut device, &mut gui).await;
        rejects_undisplayed_and_taproot_address_requests(&mut device).await;
    }
}
