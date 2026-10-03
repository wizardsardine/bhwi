//! Device-backed address retrieval with stdout output.

use anyhow::Result;
use async_trait::async_trait;
#[cfg(feature = "ledger")]
use bhwi::ledger::{LedgerWalletPolicy, Version};
use bhwi_async::{DeviceContext, DisplayAddress};
use bitcoin::address::AddressType;
use miniscript::descriptor::WalletPolicy;

use bhwi_async_transport::DeviceType;

use crate::DeviceManager;

use crate::select_device;

/// An address request from a derivation path or a named wallet policy.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum AddressTarget {
    /// An address derived directly from a BIP32 path.
    Path {
        /// The BIP32 derivation path to parse.
        path: String,
        /// Whether to request display on the device, where supported.
        display: bool,
        /// The address encoding, or the backend's default when absent.
        address_format: Option<AddressType>,
    },
    /// An address derived from a wallet policy at a branch and index.
    ///
    /// BitBox02 and Specter require `wallet_descriptor`. Ledger accepts an HMAC
    /// and policy together or neither; missing required context is then reported
    /// by the backend. Coldcard and Jade resolve the policy by name on-device.
    /// Trezor and KeepKey do not support this named-policy mode.
    Descriptor {
        /// The child address index.
        index: u32,
        /// Whether to select the internal change branch.
        change: bool,
        /// Whether to request display on the device, where supported.
        display: bool,
        /// The registered wallet name, also used when constructing a Ledger policy.
        descriptor_name: String,
        /// A Ledger registration HMAC as 64 hexadecimal characters, if supplied.
        hmac: Option<String>,
        /// The wallet policy required by BitBox02 and Specter, or paired with a Ledger HMAC.
        wallet_descriptor: Option<WalletPolicy>,
    },
}

/// An asynchronous CLI helper that prints a device-derived address.
///
/// Returned futures need not be `Send`.
#[async_trait(?Send)]
pub trait AddressOutput {
    /// Retrieves an address and prints it to stdout.
    ///
    /// The [`DeviceManager`] implementation selects a device, may warn on stderr,
    /// and produces no address output if none is found. Returns selection,
    /// parsing, context, or device errors rather than an address value.
    async fn get_address(&self, target: AddressTarget) -> Result<()>;
}

#[async_trait(?Send)]
impl AddressOutput for DeviceManager {
    async fn get_address(&self, target: AddressTarget) -> Result<()> {
        let Some(mut device) = select_device(self).await? else {
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
                // BitBox re-supplies the policy descriptor each time; Ledger needs the
                // registered policy plus its hmac; Coldcard/Jade resolve by name on-device.
                let context = match device.device_type() {
                    #[cfg(feature = "bitbox")]
                    DeviceType::BitBox02 => {
                        let wallet_policy = wallet_descriptor.ok_or_else(|| {
                            anyhow::anyhow!(
                                "--wallet-descriptor is required for BitBox descriptor addresses"
                            )
                        })?;
                        Some(DeviceContext::BitBox {
                            policy: wallet_policy,
                        })
                    }
                    #[cfg(feature = "ledger")]
                    DeviceType::Ledger => match (hmac, wallet_descriptor) {
                        (Some(hmac_hex), Some(wallet_policy)) => {
                            let hmac = hex::decode(&hmac_hex)
                                .map_err(|e| anyhow::anyhow!("invalid hmac hex: {e}"))?;
                            let hmac: [u8; 32] = hmac.try_into().map_err(|_| {
                                anyhow::anyhow!("hmac must be 32 bytes (64 hex chars)")
                            })?;
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
                    },
                    #[cfg(feature = "specter")]
                    DeviceType::Specter => {
                        let policy = wallet_descriptor.ok_or_else(|| {
                            anyhow::anyhow!(
                                "--wallet-descriptor is required for Specter descriptor addresses"
                            )
                        })?;
                        Some(DeviceContext::Specter { policy })
                    }
                    _ => None,
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
