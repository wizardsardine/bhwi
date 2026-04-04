use anyhow::Result;
use bhwi_async::HWIDevice;
use bitcoin::{
    Network,
    bip32::{ChildNumber, DerivationPath, Fingerprint},
};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    descriptor::{DescriptorType, DescriptorXKey, Wildcard, Wpkh},
};

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

fn bip44_purpose(desc_type: DescriptorType) -> Result<u32> {
    Ok(match desc_type {
        DescriptorType::Sh | DescriptorType::ShSortedMulti | DescriptorType::Pkh => 44,
        DescriptorType::Wpkh | DescriptorType::Wsh | DescriptorType::WshSortedMulti => 84,
        DescriptorType::ShWsh | DescriptorType::ShWpkh | DescriptorType::ShWshSortedMulti => 49,
        DescriptorType::Tr => 86,
        DescriptorType::Bare => anyhow::bail!("Bare PK descriptors aren't supported"),
    })
}

fn bip44_chain(network: Network) -> u32 {
    if let Network::Bitcoin = network { 0 } else { 1 }
}
