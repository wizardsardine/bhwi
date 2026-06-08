use anyhow::{Result, bail};
use bhwi_async::HWIDevice;
use bitcoin::{
    Network,
    bip32::{ChildNumber, DerivationPath, Fingerprint},
};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    descriptor::{DescriptorType, DescriptorXKey, Wildcard, Wpkh},
};
use serde::{Serialize, Serializer};

use crate::{DeviceManager, OutputFormat};

#[derive(Debug, Clone)]
pub struct GetDescriptorOptions {
    /// The device's master fingerprint to use in the descriptor
    pub master_fingerprint: Fingerprint,
    /// The method used to derive the keys for the descriptor
    pub target: DescriptorTarget,
    /// Is this descriptor used for a change address?
    pub is_change: bool,
    /// The address type to use for the descriptor
    pub descriptor_type: DescriptorType,
    /// The Bitcoin network to use in descriptor paths
    pub network: Network,
}

#[derive(Debug, Clone)]
/// The method used to derive the keys for the descriptor
pub enum DescriptorTarget {
    /// Derivation path to derive keys
    Path(DerivationPath),
    /// BIP-44 account index
    Account(u32),
}

#[derive(Debug, Clone)]
pub struct GetKeypoolOptions {
    /// BIP account or parent path to derive the keypool branch from
    pub path: DerivationPath,
    /// First child index included in this keypool range
    pub start: u32,
    /// Last child index included in this keypool range
    pub end: u32,
    /// Whether this keypool is for change/internal addresses
    pub internal: bool,
    /// The address type to use for the descriptor
    pub descriptor_type: DescriptorType,
    /// The Bitcoin network to use in descriptor paths
    pub network: Network,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeypoolDescriptor {
    #[serde(serialize_with = "serialize_descriptor")]
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub range: [u32; 2],
    pub internal: bool,
    pub keypool: bool,
}

impl GetDescriptorOptions {
    pub fn with_path(
        master_fingerprint: Fingerprint,
        path: DerivationPath,
        is_change: bool,
        descriptor_type: DescriptorType,
        network: Network,
    ) -> Self {
        Self {
            master_fingerprint,
            target: DescriptorTarget::Path(path),
            is_change,
            descriptor_type,
            network,
        }
    }

    pub fn with_account(
        master_fingerprint: Fingerprint,
        account: u32,
        is_change: bool,
        descriptor_type: DescriptorType,
        network: Network,
    ) -> Self {
        Self {
            master_fingerprint,
            target: DescriptorTarget::Account(account),
            is_change,
            descriptor_type,
            network,
        }
    }
}

impl DeviceManager {
    /// Gets a descriptor with the given parameters
    // reference: https://github.com/bitcoin-core/HWI/blob/master/hwilib/commands.py#L274
    pub async fn get_descriptor(
        &self,
        device: &mut Box<dyn HWIDevice>,
        options: GetDescriptorOptions,
    ) -> Result<Descriptor<DescriptorPublicKey>> {
        let GetDescriptorOptions {
            master_fingerprint,
            target,
            is_change,
            descriptor_type,
            network,
        } = options;
        let path = match target {
            DescriptorTarget::Path(path) => path,
            DescriptorTarget::Account(account) => {
                let purpose = ChildNumber::from_hardened_idx(bip44_purpose(descriptor_type)?)?;
                let chain = ChildNumber::from_hardened_idx(bip44_chain(network))?;
                let account = ChildNumber::from_hardened_idx(account)?;
                let change = ChildNumber::from_normal_idx(is_change.into())?;

                [purpose, chain, account, change].as_ref().into()
            }
        };

        let split = path
            .into_iter()
            .rposition(ChildNumber::is_hardened)
            .map(|i| i + 1)
            .unwrap_or(0);
        let (origin, suffix) = (&path[..split], &path[split..]);

        let xpub = device.get_extended_pubkey(origin.into(), false).await?;
        let pk = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: Some((master_fingerprint, origin.into())),
            xkey: xpub,
            derivation_path: suffix.into(),
            wildcard: Wildcard::Unhardened,
        });
        Ok(match descriptor_type {
            DescriptorType::Pkh => Descriptor::new_pkh(pk)?,
            DescriptorType::Wpkh => Descriptor::new_wpkh(pk)?,
            DescriptorType::ShWpkh => Descriptor::new_sh_with_wpkh(Wpkh::new(pk)?),
            // TODO: check if device supports Taproot
            DescriptorType::Tr => Descriptor::new_tr(pk, None)?,
            _ => anyhow::bail!("Unsupported descriptor type {descriptor_type:?}"),
        })
    }

    /// Gets a ranged keypool descriptor from an account/parent path.
    pub async fn get_keypool_descriptor(
        &self,
        device: &mut Box<dyn HWIDevice>,
        master_fingerprint: Fingerprint,
        options: GetKeypoolOptions,
    ) -> Result<KeypoolDescriptor> {
        let descriptor_options = options.descriptor_options(master_fingerprint)?;
        let descriptor = self.get_descriptor(device, descriptor_options).await?;
        Ok(KeypoolDescriptor {
            descriptor,
            range: [options.start, options.end],
            internal: options.internal,
            keypool: true,
        })
    }

    /// Output a ranged descriptor suitable for Bitcoin Core keypool import.
    pub async fn get_keypool(&self, options: GetKeypoolOptions) -> Result<()> {
        let Some(mut device) = self.get_device_with_fingerprint().await? else {
            return Ok(());
        };
        let master_fingerprint = device.fingerprint().await?;
        let keypool = self
            .get_keypool_descriptor(device.device(), master_fingerprint, options)
            .await?;
        match self.config.format {
            Some(OutputFormat::Json) => println!("{}", serde_json::to_string(&keypool)?),
            Some(OutputFormat::Pretty) => {
                println!("{:<9} | {:<8} | {:<10}", "Range", "Internal", "Descriptor");
                println!("{}", "-".repeat(120));
                println!(
                    "{}-{} | {:<8} | {}",
                    keypool.range[0], keypool.range[1], keypool.internal, keypool.descriptor
                );
            }
            None => {
                println!(
                    "{:#} range={}-{} internal={} keypool=true",
                    keypool.descriptor, keypool.range[0], keypool.range[1], keypool.internal
                );
            }
        }
        Ok(())
    }

    /// Output all supported pubkey output descriptors for a device. Analogous
    /// to the Python HWI when uses with JSON formatting.
    // TODO: Python HWI outputs using h instead of ' for hardened paths but
    // rust-miniscript doesn't allow this when displaying an entire Descriptor.
    pub async fn get_pubkey_descriptors(&self, account: Option<u32>) -> Result<()> {
        let Some(mut device) = self.get_device_with_fingerprint().await? else {
            return Ok(());
        };
        let network = self.config.network;
        let format = self.config.format;
        let fingerprint = device.fingerprint().await?;
        let dev = device.device();
        let mut receive = vec![];
        let mut internal = vec![];
        for desc_type in [
            DescriptorType::Pkh,
            DescriptorType::Wpkh,
            DescriptorType::ShWpkh,
            DescriptorType::Tr,
        ] {
            let opts_receive = GetDescriptorOptions::with_account(
                fingerprint,
                account.unwrap_or(0),
                false,
                desc_type,
                network,
            );
            let opts_internal = GetDescriptorOptions::with_account(
                fingerprint,
                account.unwrap_or(0),
                true,
                desc_type,
                network,
            );
            receive.push(self.get_descriptor(dev, opts_receive).await?);
            internal.push(self.get_descriptor(dev, opts_internal).await?);
        }
        match format {
            Some(OutputFormat::Pretty) => {
                let header = format!("{:<10} | {:<120}", "Purpose", "Descriptor");
                println!("{}", header);
                println!("{}", "-".repeat(header.len()));
                for (purpose, items) in [("internal", internal), ("receive", receive)] {
                    for item in items {
                        println!("{:<10} | {:<120}", purpose, item);
                    }
                    println!("{}", "-".repeat(header.len()));
                }
            }
            Some(OutputFormat::Json) => {
                println!(
                    "{}",
                    serde_json::json!(
                    {
                        "receive": receive,
                        "internal": internal
                    })
                );
            }
            None => {
                receive
                    .iter()
                    .chain(internal.iter())
                    .for_each(|d| println!("{d:#}"));
            }
        }
        Ok(())
    }
}

impl GetKeypoolOptions {
    fn descriptor_options(&self, master_fingerprint: Fingerprint) -> Result<GetDescriptorOptions> {
        validate_keypool_range(self.start, self.end)?;
        let path = keypool_descriptor_path(&self.path, self.internal)?;
        Ok(GetDescriptorOptions::with_path(
            master_fingerprint,
            path,
            self.internal,
            self.descriptor_type,
            self.network,
        ))
    }
}

fn validate_keypool_range(start: u32, end: u32) -> Result<()> {
    if start > end {
        bail!("keypool start index must be less than or equal to end index");
    }
    Ok(())
}

fn keypool_descriptor_path(path: &DerivationPath, internal: bool) -> Result<DerivationPath> {
    if has_hardened_child_after_unhardened(path) {
        bail!("keypool path cannot contain hardened children after an unhardened child");
    }

    let branch = ChildNumber::from_normal_idx(internal.into())?;
    let mut children = path.as_ref().to_vec();
    children.push(branch);
    Ok(children.into())
}

fn has_hardened_child_after_unhardened(path: &DerivationPath) -> bool {
    let mut seen_unhardened = false;
    path.as_ref().iter().any(|child| {
        seen_unhardened |= !child.is_hardened();
        seen_unhardened && child.is_hardened()
    })
}

fn bip44_purpose(desc_type: DescriptorType) -> Result<u32> {
    Ok(match desc_type {
        DescriptorType::Sh | DescriptorType::Pkh => 44,
        DescriptorType::Wpkh | DescriptorType::Wsh => 84,
        DescriptorType::ShWsh | DescriptorType::ShWpkh => 49,
        DescriptorType::Tr => 86,
        DescriptorType::Bare => anyhow::bail!("Bare PK descriptors aren't supported"),
    })
}

fn bip44_chain(network: Network) -> u32 {
    if let Network::Bitcoin = network { 0 } else { 1 }
}

fn serialize_descriptor<S>(
    descriptor: &Descriptor<DescriptorPublicKey>,
    ser: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_str(&format!("{descriptor:#}"))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::DerivationPath;
    use miniscript::{Descriptor, DescriptorPublicKey};

    use super::{KeypoolDescriptor, keypool_descriptor_path, validate_keypool_range};

    #[test]
    fn keypool_path_appends_receive_branch() {
        let path = DerivationPath::from_str("m/84'/0'/0'").unwrap();

        let path = keypool_descriptor_path(&path, false).unwrap();

        assert_eq!(path.to_string(), "84'/0'/0'/0");
    }

    #[test]
    fn keypool_path_appends_internal_branch() {
        let path = DerivationPath::from_str("m/84'/0'/0'").unwrap();

        let path = keypool_descriptor_path(&path, true).unwrap();

        assert_eq!(path.to_string(), "84'/0'/0'/1");
    }

    #[test]
    fn keypool_range_rejects_start_after_end() {
        let err = validate_keypool_range(10, 9).unwrap_err();

        assert!(err.to_string().contains("start index"));
    }

    #[test]
    fn keypool_path_rejects_hardened_children_after_unhardened() {
        let path = DerivationPath::from_str("m/84'/0'/0'/0/1'").unwrap();

        let err = keypool_descriptor_path(&path, false).unwrap_err();

        assert!(err.to_string().contains("hardened children"));
    }

    #[test]
    fn keypool_descriptor_serializes_json_shape() {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(
            "wpkh([e3ebcc79/84'/1'/0']tpubDCKD5cdxMEFd2i4cNa3PJUbUHMsGDxsnfqjxVpMoG1ymWYUQUaZzTcHQo3JwYgaKe2FyKGA2FzGPSVczBoAiHGyERuA1mZ2UkGKufEnUxKk/0/*)",
        )
        .unwrap();
        let keypool = KeypoolDescriptor {
            descriptor,
            range: [7, 11],
            internal: false,
            keypool: true,
        };

        let json = serde_json::to_value(keypool).unwrap();

        assert_eq!(json["range"], serde_json::json!([7, 11]));
        assert_eq!(json["internal"], false);
        assert_eq!(json["keypool"], true);
        assert!(json["descriptor"].as_str().unwrap().starts_with("wpkh("));
    }
}
