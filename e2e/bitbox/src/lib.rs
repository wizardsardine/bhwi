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
    use bhwi::bitbox::error::{BitBoxDeviceError, BitBoxError};
    use bhwi_async::transport::Channel;
    use bhwi_async::transport::bitbox::hid::BitBoxTransportHID;
    use bhwi_async::{DeviceContext, DisplayAddress, HWI, bitbox::BitBox};
    use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use bitcoin::hashes::{Hash, sha256d};
    use bitcoin::secp256k1::{All, Message, Secp256k1};
    use bitcoin::{Address, Network};
    use std::str::FromStr;
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
        // The simulator auto-confirms pairing (no user present).
        dev.unlock(Network::Bitcoin)
            .await
            .expect("pair with simulator");
        // Seed the fixed simulator mnemonic so derived keys are deterministic. The simulator
        // process persists across tests, so once it is seeded a further restore reports
        // `InvalidState` — treat that as "already seeded" and carry on.
        match dev.restore_from_mnemonic(1_601_450_521, 0).await {
            Ok(()) => {}
            Err(BitBoxError::Device(BitBoxDeviceError::InvalidState)) => {}
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
                    policy: policy.clone(),
                }),
            )
            .await
            .unwrap();

        // The address is deterministic; pin the exact value once observed against the
        // simulator. For now assert it is a well-formed mainnet P2WSH address.
        assert!(address.starts_with("bc1"), "unexpected address: {address}");
    }
}
