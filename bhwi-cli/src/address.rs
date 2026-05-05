use anyhow::Result;
use bhwi::ledger::{LedgerWalletPolicy, Version};
use bhwi_async::{DeviceContext, DisplayAddress};
use bitcoin::address::AddressType;
use miniscript::descriptor::WalletPolicy;

use crate::DeviceManager;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum AddressTarget {
    Path {
        path: String,
        display: bool,
        address_format: Option<AddressType>,
    },
    Descriptor {
        index: u32,
        change: bool,
        display: bool,
        descriptor_name: String,
        hmac: Option<String>,
        wallet_descriptor: Option<WalletPolicy>,
    },
}

impl DeviceManager {
    pub async fn get_address(&self, target: AddressTarget) -> Result<()> {
        let Some(mut device) = self.get_device_with_fingerprint().await? else {
            return Ok(());
        };
        let (display_address, context) = match target {
            AddressTarget::Path {
                path,
                display,
                address_format,
            } => (
                DisplayAddress::ByPath {
                    path: path.parse()?,
                    display,
                    address_format,
                },
                None,
            ),
            AddressTarget::Descriptor {
                index,
                change,
                display,
                descriptor_name,
                hmac,
                wallet_descriptor,
            } => {
                let context = match (hmac, wallet_descriptor) {
                    (Some(hmac_hex), Some(wallet_policy)) => {
                        let hmac = hex::decode(&hmac_hex)
                            .map_err(|e| anyhow::anyhow!("invalid hmac hex: {e}"))?;
                        let hmac: [u8; 32] = hmac
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("hmac must be 32 bytes (64 hex chars)"))?;
                        let ledger_policy = LedgerWalletPolicy::new(
                            descriptor_name.clone(),
                            Version::V2,
                            wallet_policy,
                        );
                        Some(DeviceContext::Ledger {
                            wallet_policy: ledger_policy,
                            wallet_hmac: Some(hmac),
                        })
                    }
                    (None, None) => None,
                    _ => anyhow::bail!(
                        "both --hmac and --wallet-descriptor must be provided for Ledger descriptor addresses"
                    ),
                };
                (
                    DisplayAddress::ByDescriptor {
                        index,
                        change,
                        display,
                        descriptor_name,
                    },
                    context,
                )
            }
        };
        let address = device
            .device()
            .display_address(display_address, context)
            .await?;
        println!("{address}");
        Ok(())
    }
}
