use anyhow::Result;
use bhwi_async::DisplayAddress;
use bitcoin::address::AddressType;

use crate::DeviceManager;

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
    },
}

impl DeviceManager {
    pub async fn get_address(&self, target: AddressTarget) -> Result<()> {
        let Some(mut device) = self.get_device_with_fingerprint().await? else {
            return Ok(());
        };
        let display_address = match target {
            AddressTarget::Path {
                path,
                display,
                address_format,
            } => DisplayAddress::ByPath {
                path: path.parse()?,
                display,
                address_format,
            },
            AddressTarget::Descriptor {
                index,
                change,
                display,
                descriptor_name,
            } => DisplayAddress::ByDescriptor {
                index,
                change,
                display,
                descriptor_name,
            },
        };
        let address = device
            .device()
            .display_address(display_address, None)
            .await?;
        println!("{address}");
        Ok(())
    }
}
