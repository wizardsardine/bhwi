use crate::DeviceManager;
use anyhow::Result;
use async_trait::async_trait;

pub use bhwi_async::descriptors::*;
use miniscript::{Descriptor, DescriptorPublicKey, descriptor::DescriptorType};
use serde::{Serialize, Serializer};

use crate::{OutputFormat, select_device};

#[derive(Debug, Clone, Serialize)]
pub struct KeypoolDescriptor {
    #[serde(serialize_with = "serialize_descriptor")]
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub range: [u32; 2],
    pub internal: bool,
    pub keypool: bool,
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

#[async_trait(?Send)]
pub trait DescriptorOutput {
    async fn get_keypool(
        &self,
        options: GetKeypoolOptions,
        format: Option<OutputFormat>,
    ) -> Result<()>;
    async fn get_pubkey_descriptors(
        &self,
        account: Option<u32>,
        format: Option<OutputFormat>,
    ) -> Result<()>;
}

#[async_trait(?Send)]
impl DescriptorOutput for DeviceManager {
    /// Output a ranged descriptor suitable for Bitcoin Core keypool import.
    async fn get_keypool(
        &self,
        options: GetKeypoolOptions,
        format: Option<OutputFormat>,
    ) -> Result<()> {
        let Some(mut device) = select_device(self).await? else {
            return Ok(());
        };
        let master_fingerprint = device.fingerprint().await?;
        let descriptor =
            get_keypool_descriptor(device.device().as_mut(), master_fingerprint, &options).await?;
        let keypool = KeypoolDescriptor {
            descriptor,
            range: [options.start, options.end],
            internal: options.internal,
            keypool: true,
        };
        match format {
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
    async fn get_pubkey_descriptors(
        &self,
        account: Option<u32>,
        format: Option<OutputFormat>,
    ) -> Result<()> {
        let Some(mut device) = select_device(self).await? else {
            return Ok(());
        };
        let network = self.selector.network;
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
            receive.push(get_descriptor(dev.as_mut(), opts_receive).await?);
            internal.push(get_descriptor(dev.as_mut(), opts_internal).await?);
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::{Descriptor, DescriptorPublicKey};

    use super::KeypoolDescriptor;

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
