//! End-to-end tests for the BitBox02 integration, driven against the official BitBox02
//! firmware simulator over TCP.
//!
//! The simulator speaks the same U2F-HID framing as real hardware, so the only difference
//! from the USB path is the underlying byte channel (a `TcpStream` here instead of HID).
//! Start a simulator listening on `127.0.0.1:15423` before running these tests, e.g.:
//!
//! ```text
//! nix run .#bitbox        # downloads a pinned simulator and runs it
//! cargo test -p bhwi-e2e-bitbox
//! ```
//!
//! Every test seeds the device with the simulator's fixed BIP39 mnemonic via
//! `restore_from_mnemonic`, so all derived keys are deterministic and expected values are
//! computed host-side from `SIMULATOR_XPRV`.

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bhwi::Interpreter;
    use bhwi::bitbox::error::{BitBoxDeviceError, BitBoxError};
    use bhwi::bitbox::{
        BitBoxCommand, BitBoxResponse, BitBoxTransmit, policy::Policy as BitBoxPolicy,
    };
    use bhwi::miniscript::descriptor::{
        DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, WalletPolicy,
    };
    use bhwi::miniscript::psbt::{PsbtExt, PsbtInputExt, PsbtOutputExt};
    use bhwi_async::transport::Channel;
    use bhwi_async::transport::bitbox::hid::BitBoxTransportHID;
    use bhwi_async::{
        CommonInterface, DeviceBackup, DeviceContext, DisplayAddress, HWI, bitbox::BitBox,
    };
    use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
    use bitcoin::hashes::{Hash, sha256d};
    use bitcoin::psbt::Psbt;
    use bitcoin::secp256k1::{All, Message, Secp256k1};
    use bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness, absolute::LockTime, transaction::Version as TxVersion,
    };
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Mutex;

    const SIMULATOR_ENDPOINT: &str = "127.0.0.1:15423";

    /// BIP32 root xprv the BitBox02 simulator restores to (from the fixed simulator mnemonic
    /// "boring mistake dish oyster truth pigeon viable emerge sort crash wire portion cannon
    /// couple enact box walk height pull today solid off enable tide").
    const SIMULATOR_XPRV: &str = "xprv9s21ZrQH143K2qxpAMxVdyeza5dUBxY11XbJ7eKvRF51sQyhiFXgmn4P4ALi3Nf6bcG8cmPDvMMEFiAVjtXsqeZ47PJfBJif7uSYycMsx9c";

    /// A `Channel` over a raw TCP connection to the simulator. `BitBoxTransportHID` layers the
    /// U2F-HID + HWW framing on top, exactly as it does over USB HID.
    struct TcpChannel {
        stream: Mutex<TcpStream>,
    }

    impl TcpChannel {
        fn new(stream: TcpStream) -> Self {
            Self {
                stream: Mutex::new(stream),
            }
        }
    }

    #[async_trait(?Send)]
    impl Channel for TcpChannel {
        async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
            let mut stream = self.stream.lock().await;
            stream.write_all(data).await?;
            stream.flush().await?;
            Ok(data.len())
        }

        async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
            let mut stream = self.stream.lock().await;
            // The transport expects whole 64-byte HID frames; read exactly what it asked for.
            stream.read_exact(data).await?;
            Ok(data.len())
        }
    }

    type SimDevice = BitBox<BitBoxTransportHID<TcpChannel>>;

    /// Connect to the simulator, retrying for ~2s while it binds its port.
    async fn connect() -> TcpStream {
        for _ in 0..200 {
            if let Ok(stream) = TcpStream::connect(SIMULATOR_ENDPOINT).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("could not connect to BitBox02 simulator at {SIMULATOR_ENDPOINT}");
    }

    /// A paired, seeded simulator device ready for queries.
    async fn device() -> SimDevice {
        let stream = connect().await;
        let mut dev = BitBox::new(BitBoxTransportHID::new(TcpChannel::new(stream)), None);
        let (pairing_code_tx, pairing_code_rx) = mpsc::channel();
        dev.set_pairing_code_hook(Box::new(move |code| {
            pairing_code_tx.send(code.to_owned()).unwrap();
        }));
        // The simulator auto-confirms pairing (no user present).
        dev.unlock(Network::Bitcoin)
            .await
            .expect("pair with simulator");
        let code = pairing_code_rx
            .try_recv()
            .expect("pairing callback during simulator unlock");
        assert!(!code.is_empty());
        assert_eq!(dev.pairing_code(), Some(code.as_str()));
        // Seed the fixed simulator mnemonic so derived keys are deterministic. The simulator
        // process persists across tests, so once it is seeded a further restore reports
        // `InvalidState` — treat that as "already seeded" and carry on.
        match dev.restore_from_mnemonic(1_601_450_521, 0).await {
            Ok(()) => {}
            Err(BitBoxError::Device(BitBoxDeviceError::InvalidState, _)) => {}
            Err(e) => panic!("seed simulator mnemonic: {e:?}"),
        }
        dev
    }

    fn simulator_xprv() -> Xpriv {
        Xpriv::from_str(SIMULATOR_XPRV).unwrap()
    }

    /// Expected xpub at `path`, derived host-side from the known simulator seed.
    fn expected_xpub(secp: &Secp256k1<All>, path: &DerivationPath) -> Xpub {
        Xpub::from_priv(secp, &simulator_xprv().derive_priv(secp, path).unwrap())
    }
    struct RawCommand(BitBoxCommand);

    impl TryFrom<RawCommand> for BitBoxCommand {
        type Error = BitBoxError;

        fn try_from(command: RawCommand) -> Result<Self, Self::Error> {
            Ok(command.0)
        }
    }

    async fn run_native(dev: &mut SimDevice, command: BitBoxCommand) -> BitBoxResponse {
        let (transport, _http, _host, mut interpreter) = <SimDevice as CommonInterface<
            RawCommand,
            BitBoxTransmit,
            BitBoxResponse,
            BitBoxError,
        >>::components(dev);
        let mut transmit = interpreter.start(RawCommand(command)).unwrap();
        loop {
            let response = transport
                .exchange(&transmit.payload, transmit.encrypted)
                .await
                .unwrap();
            match interpreter.exchange(response).unwrap() {
                Some(next) => transmit = next,
                None => return interpreter.end().unwrap(),
            }
        }
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let mut dev = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        assert_eq!(fingerprint.to_string(), "4c00739d");
    }

    #[tokio::test]
    async fn can_get_info() {
        let mut dev = device().await;
        let info = dev.get_info().await.unwrap();
        assert!(!info.version.is_empty());
        assert!(info.firmware.is_some());
    }

    #[tokio::test]
    async fn can_backup_device() {
        let mut dev = device().await;
        let backup = dev.backup_device().await.unwrap();
        assert_eq!(backup, DeviceBackup::Complete);
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let secp = Secp256k1::new();
        let mut dev = device().await;
        let path: DerivationPath = "m/84'/0'/0'".parse().unwrap();
        let xpub = dev.get_extended_pubkey(path.clone(), false).await.unwrap();
        assert_eq!(xpub, expected_xpub(&secp, &path));
    }

    #[tokio::test]
    async fn can_display_address_by_path() {
        let secp = Secp256k1::new();
        let mut dev = device().await;
        let path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
        let address = dev
            .display_address(
                DisplayAddress::ByPath {
                    path: path.clone(),
                    display: true,
                    address_format: None,
                },
                None,
            )
            .await
            .unwrap();
        let expected = Address::p2wpkh(&expected_xpub(&secp, &path).to_pub(), Network::Bitcoin);
        assert_eq!(address, expected.to_string());
    }

    #[tokio::test]
    async fn can_sign_message() {
        let secp = Secp256k1::new();
        let mut dev = device().await;
        // Nested-segwit path: BitBox02 signs the message under the P2WPKH-P2SH script config.
        let path: DerivationPath = "m/49'/0'/0'/0/10".parse().unwrap();
        let (_header, sig) = dev.sign_message(b"hello", path.clone()).await.unwrap();

        // Recompute the BIP-137 message digest and verify the signature against our pubkey.
        let mut preimage = Vec::new();
        preimage.push(0x18u8);
        preimage.extend_from_slice(b"Bitcoin Signed Message:\n");
        preimage.push(b"hello".len() as u8);
        preimage.extend_from_slice(b"hello");
        let digest = sha256d::Hash::hash(&preimage);
        let message = Message::from_digest(digest.to_byte_array());
        let pubkey = expected_xpub(&secp, &path).public_key;
        secp.verify_ecdsa(&message, &sig, &pubkey)
            .expect("signature verifies against the derived pubkey");
    }

    #[tokio::test]
    async fn can_display_address_by_descriptor() {
        let secp = Secp256k1::new();
        let mut dev = device().await;
        let account: DerivationPath = "m/48'/0'/0'/2'".parse().unwrap();
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        let our_xpub = dev
            .get_extended_pubkey(account.clone(), false)
            .await
            .unwrap();

        // A fixed foreign cosigner derived from a throwaway seed. `WalletPolicy` (and the
        // BitBox) expect the `/<0;1>/*` multipath form with key origins.
        let foreign_root = Xpriv::new_master(Network::Bitcoin, &[42u8; 32]).unwrap();
        let foreign_fp = foreign_root.fingerprint(&secp);
        let foreign_xpub =
            Xpub::from_priv(&secp, &foreign_root.derive_priv(&secp, &account).unwrap());
        let policy = format!(
            "wsh(andor(pk([{fingerprint}/48'/0'/0'/2']{our_xpub}/<0;1>/*),older(12960),pk([{foreign_fp}/48'/0'/0'/2']{foreign_xpub}/<0;1>/*)))"
        );

        // BitBox02 requires the policy to be registered before an address can be displayed.
        dev.register_wallet("bhwi-e2e", &policy)
            .await
            .expect("register policy");

        let address = dev
            .display_address(
                DisplayAddress::ByDescriptor {
                    index: 0,
                    change: false,
                    display: true,
                    descriptor_name: "bhwi-e2e".to_string(),
                },
                Some(DeviceContext::BitBox {
                    policy: WalletPolicy::from_str(&policy).unwrap(),
                }),
            )
            .await
            .unwrap();

        let expected = definite_address(&policy, false, 0)
            .derived_descriptor(&secp)
            .address(Network::Bitcoin)
            .unwrap()
            .to_string();
        assert_eq!(address, expected);
    }

    #[tokio::test]
    async fn can_sign_decaying_multisig_psbt() {
        let secp = Secp256k1::new();
        let mut dev = device().await;
        let account: DerivationPath = "m/48'/0'/0'/2'".parse().unwrap();
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        let our_xpub = dev
            .get_extended_pubkey(account.clone(), false)
            .await
            .unwrap();

        // Liana-style inheritance: the device key spends immediately; a recovery key derived
        // from a fixed seed (never owned by the device) can spend only after a relative
        // timelock. Signing the always-available primary path yields exactly one signature —
        // the device's — so no locktime is needed on the PSBT.
        let recovery_root = Xpriv::new_master(Network::Bitcoin, &[0xc3u8; 32]).unwrap();
        let recovery_fp = recovery_root.fingerprint(&secp);
        let recovery_xpub =
            Xpub::from_priv(&secp, &recovery_root.derive_priv(&secp, &account).unwrap());
        let policy = format!(
            "wsh(or_d(pk([{fingerprint}/48'/0'/0'/2']{our_xpub}/<0;1>/*),and_v(v:pkh([{recovery_fp}/48'/0'/0'/2']{recovery_xpub}/<0;1>/*),older(10))))"
        );

        // BitBox02 requires the policy to be registered before it will sign under it.
        dev.register_wallet("bhwi-e2e-sign", &policy)
            .await
            .expect("register policy");

        let (receive, change) = definite_branches(&policy);
        let psbt = build_psbt(&secp, &receive, &change);

        let signed = dev
            .sign_tx(
                psbt,
                Some(DeviceContext::BitBox {
                    policy: WalletPolicy::from_str(&policy).unwrap(),
                }),
            )
            .await
            .expect("sign decaying multisig psbt");

        assert_eq!(signed.inputs.len(), 1);
        let input = &signed.inputs[0];
        assert_eq!(
            input.partial_sigs.len(),
            1,
            "expected exactly one signature"
        );
        assert!(
            input
                .partial_sigs
                .contains_key(&receive_pubkey(&secp, &our_xpub)),
            "device key signature missing"
        );
        verify_partials(&secp, &signed);
    }

    #[tokio::test]
    async fn can_sign_reused_multipath_key_psbt() {
        let secp = Secp256k1::new();
        let mut dev = device().await;
        let account: DerivationPath = "m/48'/0'/0'/2'".parse().unwrap();
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        let our_xpub = dev
            .get_extended_pubkey(account.clone(), false)
            .await
            .unwrap();

        // The recovery key recurs with two multipath pairs, so the policy
        // template sent to the BitBox must reuse its placeholder instead of
        // numbering each occurrence. The device co-holds the 1-of-2 primary
        // path and signs exactly once.
        let recovery_root = Xpriv::new_master(Network::Bitcoin, &[0xb4u8; 32]).unwrap();
        let recovery_fp = recovery_root.fingerprint(&secp);
        let recovery_xpub =
            Xpub::from_priv(&secp, &recovery_root.derive_priv(&secp, &account).unwrap());
        let policy = format!(
            "wsh(or_d(multi(1,[{fingerprint}/48'/0'/0'/2']{our_xpub}/<0;1>/*,[{recovery_fp}/48'/0'/0'/2']{recovery_xpub}/<0;1>/*),and_v(v:pkh([{recovery_fp}/48'/0'/0'/2']{recovery_xpub}/<2;3>/*),older(10))))"
        );

        dev.register_wallet("bhwi-e2e-reuse", &policy)
            .await
            .expect("register policy");

        let (receive, change) = definite_branches(&policy);
        let psbt = build_psbt(&secp, &receive, &change);

        let signed = dev
            .sign_tx(
                psbt,
                Some(DeviceContext::BitBox {
                    policy: WalletPolicy::from_str(&policy).unwrap(),
                }),
            )
            .await
            .expect("sign reused-multipath-key psbt");

        assert_eq!(signed.inputs.len(), 1);
        let input = &signed.inputs[0];
        assert_eq!(
            input.partial_sigs.len(),
            1,
            "expected exactly one signature"
        );
        assert!(
            input
                .partial_sigs
                .contains_key(&receive_pubkey(&secp, &our_xpub)),
            "device key signature missing"
        );
        verify_partials(&secp, &signed);
    }

    #[tokio::test]
    async fn can_sign_taproot_reused_multipath_key_psbt() {
        let secp = Secp256k1::new();
        let mut dev = device().await;
        let account: DerivationPath = "m/48'/0'/0'/2'".parse().unwrap();
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        let our_xpub = dev
            .get_extended_pubkey(account.clone(), false)
            .await
            .unwrap();

        // Liana-style taproot: the device key is the spendable internal key;
        // the recovery key recurs in two timelocked leaves with distinct
        // multipath pairs, so the policy template must reuse its placeholder.
        // Key-path signing yields exactly one signature, the device's.
        let recovery_root = Xpriv::new_master(Network::Bitcoin, &[0x5cu8; 32]).unwrap();
        let recovery_fp = recovery_root.fingerprint(&secp);
        let recovery_xpub =
            Xpub::from_priv(&secp, &recovery_root.derive_priv(&secp, &account).unwrap());
        let policy = format!(
            "tr([{fingerprint}/48'/0'/0'/2']{our_xpub}/<0;1>/*,{{and_v(v:pkh([{recovery_fp}/48'/0'/0'/2']{recovery_xpub}/<0;1>/*),older(10)),and_v(v:pkh([{recovery_fp}/48'/0'/0'/2']{recovery_xpub}/<2;3>/*),older(20))}})"
        );

        dev.register_wallet("bhwi-e2e-tr-reuse", &policy)
            .await
            .expect("register policy");

        let (receive, change) = definite_branches(&policy);
        let psbt = build_psbt(&secp, &receive, &change);

        let signed = dev
            .sign_tx(
                psbt,
                Some(DeviceContext::BitBox {
                    policy: WalletPolicy::from_str(&policy).unwrap(),
                }),
            )
            .await
            .expect("sign taproot reused-multipath-key psbt");

        assert_eq!(signed.inputs.len(), 1);
        let input = &signed.inputs[0];
        assert!(
            input.partial_sigs.is_empty() && input.tap_script_sigs.is_empty(),
            "expected no script-path or ECDSA signatures"
        );
        assert!(
            input.tap_key_sig.is_some(),
            "device key-path signature missing"
        );
    }
    #[tokio::test]
    async fn can_register_display_and_sign_canonical_sorted_multisig() {
        let secp = Secp256k1::new();
        for network in [Network::Bitcoin, Network::Testnet] {
            let mut dev = device().await.with_network(network);
            for wrapped in [false, true] {
                let coin = u32::from(network != Network::Bitcoin);
                let script_type = if wrapped { 1 } else { 2 };
                let account: DerivationPath =
                    format!("m/48'/{coin}'/0'/{script_type}'").parse().unwrap();
                let fingerprint = dev.get_master_fingerprint().await.unwrap();
                let our_xpub = dev
                    .get_extended_pubkey(account.clone(), false)
                    .await
                    .unwrap();
                let mut root = simulator_xprv();
                root.network = network.into();
                assert_eq!(
                    our_xpub,
                    Xpub::from_priv(&secp, &root.derive_priv(&secp, &account).unwrap())
                );
                let foreign_root = Xpriv::new_master(network, &[42; 32]).unwrap();
                let foreign_fp = foreign_root.fingerprint(&secp);
                let foreign_xpub =
                    Xpub::from_priv(&secp, &foreign_root.derive_priv(&secp, &account).unwrap());
                let ours = format!("[{fingerprint}/{account}]{our_xpub}/<0;1>/*");
                let foreign = format!("[{foreign_fp}/{account}]{foreign_xpub}/<0;1>/*");
                for owned_index in [0, 1] {
                    let keys = if owned_index == 0 {
                        [&ours, &foreign]
                    } else {
                        [&foreign, &ours]
                    };
                    let descriptor = format!("wsh(sortedmulti(2,{},{}))", keys[0], keys[1]);
                    let descriptor = if wrapped {
                        format!("sh({descriptor})")
                    } else {
                        descriptor
                    };
                    let name = format!("bhwi-sorted-{coin}-{script_type}");
                    let wallet = WalletPolicy::from_str(&descriptor).unwrap();
                    let bitbox_policy = BitBoxPolicy::from_wallet_policy(&wallet).unwrap();
                    dev.register_wallet(&name, &descriptor)
                        .await
                        .expect("register canonical sorted 2-of-2");
                    assert!(matches!(
                        run_native(
                            &mut dev,
                            BitBoxCommand::IsScriptConfigRegistered {
                                policy: bitbox_policy.clone(),
                            }
                        )
                        .await,
                        BitBoxResponse::IsRegistered(true)
                    ));
                    for (change, index) in [(false, 0), (false, 7), (true, 0), (true, 7)] {
                        let expected = definite_address(&descriptor, change, index)
                            .derived_descriptor(&secp)
                            .address(network)
                            .unwrap()
                            .to_string();
                        let address = dev
                            .display_address(
                                DisplayAddress::ByDescriptor {
                                    index,
                                    change,
                                    display: true,
                                    descriptor_name: name.clone(),
                                },
                                Some(DeviceContext::BitBox {
                                    policy: wallet.clone(),
                                }),
                            )
                            .await
                            .unwrap();
                        assert_eq!(address, expected);
                        let keypath = account.extend([
                            ChildNumber::Normal {
                                index: u32::from(change),
                            },
                            ChildNumber::Normal { index },
                        ]);
                        assert!(
                            matches!(run_native(&mut dev, BitBoxCommand::ShowPolicyAddress {
                            policy: bitbox_policy.clone(), keypath, display: true,
                        }).await, BitBoxResponse::Address(address) if address == expected)
                        );
                    }

                    let receive = definite_address(&descriptor, false, 0);
                    let change = definite_address(&descriptor, true, 7);
                    let original = build_psbt(&secp, &receive, &change);
                    for foreign_first in [false, true] {
                        let mut request = original.clone();
                        if foreign_first {
                            request
                                .sign(&foreign_root, &secp)
                                .expect("real foreign partial signature");
                        }
                        let previous = request.inputs[0].partial_sigs.clone();
                        let mut signed = dev
                            .sign_tx(
                                request,
                                Some(DeviceContext::BitBox {
                                    policy: wallet.clone(),
                                }),
                            )
                            .await
                            .expect("sign canonical sorted multisig");
                        let partials = std::mem::take(&mut signed.inputs[0].partial_sigs);
                        assert_eq!(signed, original);
                        signed.inputs[0].partial_sigs = partials;
                        for (key, signature) in previous {
                            assert_eq!(signed.inputs[0].partial_sigs.get(&key), Some(&signature));
                        }
                        let our_key = receive_pubkey(&secp, &our_xpub);
                        let device_signature = *signed.inputs[0]
                            .partial_sigs
                            .get(&our_key)
                            .expect("device signature");
                        assert_eq!(
                            signed.inputs[0].partial_sigs.len(),
                            if foreign_first { 2 } else { 1 }
                        );
                        verify_partials(&secp, &signed);
                        if !foreign_first {
                            signed
                                .sign(&foreign_root, &secp)
                                .expect("foreign cosigner after device");
                            assert_eq!(
                                signed.inputs[0].partial_sigs.get(&our_key),
                                Some(&device_signature)
                            );
                        }
                        assert_eq!(signed.inputs[0].partial_sigs.len(), 2);
                        verify_partials(&secp, &signed);
                        signed
                            .finalize_mut(&secp)
                            .expect("both signatures finalize");
                        let mut tx = PsbtExt::extract(&signed, &secp)
                            .expect("Miniscript interpreter verifies final spend");
                        for input in &mut tx.input {
                            input.script_sig = ScriptBuf::new();
                            input.witness = Witness::new();
                        }
                        assert_eq!(tx, original.unsigned_tx);
                    }

                    // A real fingerprint with the wrong account origin is not ownership.
                    let wrong_origin = descriptor.replace(
                        &format!("[{fingerprint}/{account}]"),
                        &format!("[{fingerprint}/48'/{coin}'/1'/{script_type}']"),
                    );
                    assert!(
                        dev.register_wallet("bhwi-invalid-origin", &wrong_origin)
                            .await
                            .is_err()
                    );
                }
            }
        }
    }

    fn verify_partials(secp: &Secp256k1<All>, psbt: &Psbt) {
        let mut cache = bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);
        for (index, input) in psbt.inputs.iter().enumerate() {
            let (message, sighash) = psbt.sighash_ecdsa(index, &mut cache).unwrap();
            assert_eq!(sighash, bitcoin::sighash::EcdsaSighashType::All);
            for (pubkey, signature) in &input.partial_sigs {
                assert_eq!(signature.sighash_type, sighash);
                secp.verify_ecdsa(&message, &signature.signature, &pubkey.inner)
                    .expect("valid real signature");
            }
        }
    }

    fn definite_address(
        descriptor: &str,
        change: bool,
        index: u32,
    ) -> Descriptor<DefiniteDescriptorKey> {
        Descriptor::<DescriptorPublicKey>::from_str(descriptor)
            .unwrap()
            .into_single_descriptors()
            .unwrap()
            .into_iter()
            .nth(usize::from(change))
            .unwrap()
            .derive_at_index(index)
            .unwrap()
    }

    /// Value of the single input the sign test spends (must equal the witness UTXO).
    const INPUT_VALUE: Amount = Amount::from_sat(50_000);
    /// Value sent to the change output (input minus fee).
    const CHANGE_VALUE: Amount = Amount::from_sat(49_000);

    /// Splits a multipath descriptor into definite receive (branch 0) and change (branch 1)
    /// descriptors at index 0.
    fn definite_branches(
        descriptor: &str,
    ) -> (
        Descriptor<DefiniteDescriptorKey>,
        Descriptor<DefiniteDescriptorKey>,
    ) {
        (
            definite_address(descriptor, false, 0),
            definite_address(descriptor, true, 0),
        )
    }

    /// Builds a single-input PSBT spending a receive output back to a change output.
    /// `update_with_descriptor_unchecked` fills the witness fields and per-key BIP-32
    /// derivations so the device can recognize and sign its key.
    fn build_psbt(
        secp: &Secp256k1<All>,
        receive: &Descriptor<DefiniteDescriptorKey>,
        change: &Descriptor<DefiniteDescriptorKey>,
    ) -> Psbt {
        let input_script = receive.derived_descriptor(secp).script_pubkey();
        let change_script = change.derived_descriptor(secp).script_pubkey();

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
                value: INPUT_VALUE,
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
                value: CHANGE_VALUE,
                script_pubkey: change_script,
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: INPUT_VALUE,
            script_pubkey: input_script,
        });
        psbt.inputs[0].non_witness_utxo = Some(prev_tx);
        psbt.inputs[0]
            .update_with_descriptor_unchecked(receive)
            .unwrap();
        psbt.outputs[0]
            .update_with_descriptor_unchecked(change)
            .unwrap();
        psbt
    }

    /// Receive-branch public key at index 0, used to assert the device signed.
    fn receive_pubkey(secp: &Secp256k1<All>, xpub: &Xpub) -> PublicKey {
        let child = xpub
            .derive_pub(
                secp,
                &[
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(0).unwrap(),
                ],
            )
            .unwrap();
        PublicKey::new(child.public_key)
    }
}
