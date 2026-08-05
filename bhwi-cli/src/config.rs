use bhwi::trezor::HostPassphrase;
use bitcoin::{Network, bip32::Fingerprint};

use crate::DeviceType;

#[derive(Debug, Clone)]
pub struct DeviceSelector {
    pub network: Network,
    pub fingerprint: Option<Fingerprint>,
    pub device_type: Option<DeviceType>,
    pub device_path: Option<String>,
    pub include_emulators: bool,
    pub passphrase: Option<HostPassphrase>,
}

impl Default for DeviceSelector {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            fingerprint: None,
            device_type: None,
            device_path: None,
            include_emulators: false,
            passphrase: None,
        }
    }
}

impl DeviceSelector {
    pub fn matches(&self, device_type: DeviceType, path: &str) -> bool {
        self.device_type.is_none_or(|target| target == device_type)
            && self
                .device_path
                .as_ref()
                .is_none_or(|target| target == path)
    }
}
