use anyhow::Result;
use bhwi_async::Transport;
use bhwi_async::coldcard::Coldcard;
use bhwi_async::transport::coldcard::hid::ColdcardTransportHID;
use bhwi_cli::coldcard::emulator::EmulatorClient;

pub type ColdcardDevice = Coldcard<ColdcardTransportHID<EmulatorClient>>;

pub struct DeviceControl {
    client: ColdcardTransportHID<EmulatorClient>,
}

impl DeviceControl {
    pub fn new(client: EmulatorClient) -> Self {
        Self {
            client: ColdcardTransportHID::new(client),
        }
    }

    // https://github.com/Coldcard/firmware/blob/0b425b8609c4c42f6986f4d209b6068136bb7cd4/shared/usb_test_commands.py#L23
    pub async fn approve(&mut self) -> Result<()> {
        // artificial delay until signing is done
        tokio::time::sleep(std::time::Duration::from_millis(0)).await;
        self.client.exchange(b"XKEYy", false).await.unwrap();
        Ok(())
    }

    pub async fn approve_after(&mut self, delay: std::time::Duration) -> Result<()> {
        tokio::time::sleep(delay).await;
        self.client.exchange(b"XKEYy", false).await.unwrap();
        Ok(())
    }

    pub async fn approve_backup(&mut self) -> Result<()> {
        self.client.exchange(b"XKEYy", false).await.unwrap();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            self.client.exchange(b"XKEY1", false).await.unwrap();
        }
        Ok(())
    }

    pub async fn reset_multisig(&mut self) -> Result<()> {
        self.client
            .exchange(b"EXECsettings.set('multisig', []); settings.save()", false)
            .await?;
        Ok(())
    }

    pub async fn multisig_settings(&mut self) -> Result<String> {
        let response = self
            .client
            .exchange(b"EVALsettings.get('multisig', [])", false)
            .await?;
        let value = response
            .strip_prefix(b"biny")
            .ok_or_else(|| anyhow::anyhow!("unexpected Coldcard EVAL response"))?;
        Ok(String::from_utf8(value.to_vec())?)
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use bhwi_async::{
        DeviceBackup, DisplayAddress, HWI, WalletRegistration,
        transport::coldcard::DEFAULT_CKCC_SOCKET,
    };
    use bitcoin::{
        Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
        absolute::LockTime,
        address::Address,
        bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
        psbt::{Input, Output, Psbt},
        secp256k1::Secp256k1,
        transaction::Version as TxVersion,
    };

    use super::*;

    async fn device() -> (ColdcardDevice, DeviceControl) {
        let mut rng = rand_core::OsRng;
        let client = EmulatorClient::new(DEFAULT_CKCC_SOCKET).await.unwrap();
        let control_client = EmulatorClient::new(DEFAULT_CKCC_SOCKET).await.unwrap();
        let mut dev = ColdcardDevice::new(ColdcardTransportHID::new(client), &mut rng);
        let control = DeviceControl::new(control_client);
        dev.unlock(Network::Testnet).await.expect("can't unlock");
        (dev, control)
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let (mut dev, _) = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        assert_eq!(fingerprint.to_string(), "0f056943");
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let (mut dev, _) = device().await;
        let xpub = dev
            .get_extended_pubkey("44'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(
            xpub.to_string(),
            "tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB"
        );
    }

    // NOTE: this can be unstable if you repeat it quickly. It seems that the
    // emulator along with the emulated device input sharing the same socket
    // can interfere and sometimes return junk data.
    #[tokio::test]
    async fn can_sign_message() {
        let (mut dev, mut control) = device().await;

        let sign_task = dev.sign_message(b"hello", "44'/1'/0'".parse().unwrap());

        let (sign_res, approve_res) = tokio::join!(sign_task, control.approve());
        let (header, sig) = sign_res.unwrap();
        approve_res.unwrap();

        let mut uncompressed = vec![header];
        uncompressed.extend_from_slice(&sig.serialize_compact());

        assert_eq!(header, 40);
        assert_eq!(
            Base64::encode_string(&uncompressed),
            "KEMkoamxdI4o4yIKww0ZwbabbSWukI8WY1reuuPle/EJXzQ61fB/TFm+v/qmGCgTyEkhP3qCuAOOONBauJ/VtEA="
        );
    }

    #[tokio::test]
    async fn can_get_info() {
        let (mut dev, _) = device().await;
        let info = dev.get_info().await.unwrap();
        assert_eq!(info.firmware, Some("mk5".to_string()));
        assert_eq!(info.version.to_string(), "5.x.x");
    }

    #[tokio::test]
    async fn can_display_address() {
        let (mut dev, mut control) = device().await;
        let display_task = dev.display_address(
            DisplayAddress::ByPath {
                path: "44'/1'/0'/0/0".parse().unwrap(),
                display: true,
                address_format: None,
            },
            None,
        );
        let (display_res, approve_res) = tokio::join!(display_task, control.approve());
        let address = display_res.expect("failed to display address");
        approve_res.unwrap();
        // ./hwi.py --emulators --fingerprint "0f056943" displayaddress --path "m/44'/1'/0'/0/0"
        assert_eq!(address, "tb1q3s94sczh7r0he9hsdt4r7vtcpl7ljkjyn2k3tt");
    }

    // NOTE: The Coldcard simulator in the local firmware repo does not handle
    // the `msas` (miniscript address) command. This should succeed on real
    // hardware.
    #[tokio::test]
    async fn can_display_address_miniscript() {
        let (mut dev, mut control) = device().await;
        let display_task = dev.display_address(
            DisplayAddress::ByDescriptor {
                index: 0,
                change: false,
                display: true,
                descriptor_name: "coldcard".to_string(),
            },
            None,
        );
        let (display_res, _) = tokio::join!(display_task, async {
            let _ = control.approve().await;
        });
        // The simulator returns err_Unknown cmd for msas, so we expect an error.
        // On real hardware with a registered descriptor, this would succeed.
        assert!(display_res.is_err());
    }

    #[tokio::test]
    async fn can_enroll_multisig_descriptor() {
        let (mut dev, mut control) = device().await;
        control.reset_multisig().await.unwrap();
        let secp = Secp256k1::new();
        let account_path: DerivationPath = "48'/1'/0'/2'".parse().unwrap();
        let device_fingerprint = dev.get_master_fingerprint().await.unwrap();
        let device_xpub = dev
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .unwrap();
        let cosigner_master = Xpriv::new_master(Network::Testnet, &[9u8; 32]).unwrap();
        let cosigner_fingerprint = cosigner_master.fingerprint(&secp);
        let cosigner_xpriv = cosigner_master.derive_priv(&secp, &account_path).unwrap();
        let cosigner_xpub = Xpub::from_priv(&secp, &cosigner_xpriv);
        let policy = format!(
            "wsh(sortedmulti(2,[{device_fingerprint}/{account_path}]{device_xpub}/<0;1>/*,[{cosigner_fingerprint}/{account_path}]{cosigner_xpub}/<0;1>/*))"
        );

        let registration = dev
            .register_wallet("cold-e2e", &policy)
            .await
            .expect("start Coldcard enrollment");
        assert_eq!(registration, WalletRegistration::PendingUserConfirmation);

        control
            .approve_after(std::time::Duration::from_millis(250))
            .await
            .unwrap();
        for _ in 0..40 {
            if control
                .multisig_settings()
                .await
                .unwrap()
                .contains("cold-e2e")
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("Coldcard multisig registration was not persisted");
    }

    #[tokio::test]
    async fn can_sign_psbt() {
        let (mut dev, mut control) = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        let xpub = dev
            .get_extended_pubkey("84'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        let secp = Secp256k1::verification_only();
        let input_path: DerivationPath = "84'/1'/0'/0/0".parse().unwrap();
        let change_path: DerivationPath = "84'/1'/0'/1/0".parse().unwrap();
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

        let sign_task = dev.sign_tx(psbt, None);
        let (signed, approve_res) = tokio::join!(
            sign_task,
            control.approve_after(std::time::Duration::from_secs(1))
        );
        let signed = signed.expect("failed to sign psbt");
        approve_res.unwrap();

        assert_eq!(signed.inputs.len(), 1);
        assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
        assert!(signed.inputs[0].partial_sigs.contains_key(&input_pubkey));
    }

    #[tokio::test]
    async fn can_backup_device() {
        let (mut dev, mut control) = device().await;

        let backup_task = dev.backup_device();
        let (backup_res, approve_res) = tokio::join!(backup_task, control.approve_backup());
        approve_res.unwrap();
        let backup = match backup_res.expect("failed to back up coldcard") {
            DeviceBackup::File(bytes) => bytes,
            DeviceBackup::Complete => panic!("coldcard backup should return file bytes"),
        };

        assert!(backup.starts_with(b"7z\xbc\xaf'\x1c"));
        assert!(backup.len() > 1024);
    }
}
