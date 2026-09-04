use anyhow::Result;
use async_trait::async_trait;
use bhwi_async::HWIDevice;
use bitcoin::{Network, bip32::Fingerprint};
use clap::ValueEnum;
use futures::future::join_all;
use serde::{Serialize, Serializer};
use strum::{EnumIter, IntoEnumIterator};

use crate::{
    bitbox::BitBoxDevice, coldcard::ColdcardDevice, config::DeviceSelector, jade::JadeDevice,
    keepkey::KeepKeyDevice, ledger::LedgerDevice, trezor::TrezorDevice,
};

pub mod address;
pub mod bitbox;
pub mod coldcard;
pub mod config;
pub mod get_descriptors;
pub mod hid;
pub mod hwi;
pub mod jade;
pub mod keepkey;
pub mod ledger;
pub mod management;
pub mod trezor;
pub mod udev;
pub mod webusb;

#[derive(Serialize)]
pub struct Device {
    name: String,
    device_type: DeviceType,
    path: String,
    model: String,
    #[serde(skip)]
    device: Box<dyn HWIDevice>,
    is_emulated: bool,
    #[serde(default, serialize_with = "option_fingerprint")]
    fingerprint: Option<Fingerprint>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    info: Option<Info>,
}

/// Serializable Device Information
#[derive(Debug, Clone, Default, Serialize)]
pub struct Info {
    pub version: String,
    pub networks: Vec<Network>,
    pub firmware: Option<String>,
    #[serde(skip)]
    pub initialized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip)]
    pub on_device_passphrase_entry: Option<bool>,
    #[serde(skip)]
    pub needs_pin_sent: Option<bool>,
    #[serde(skip)]
    pub needs_passphrase_sent: Option<bool>,
}

impl Info {
    pub fn networks_string(&self) -> String {
        self.networks
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl From<bhwi_async::Info> for Info {
    fn from(info: bhwi_async::Info) -> Self {
        Self {
            version: info.version,
            networks: info.networks,
            firmware: info.firmware,
            initialized: info.initialized,
            label: info.label,
            on_device_passphrase_entry: info.on_device_passphrase_entry,
            needs_pin_sent: info.needs_pin_sent,
            needs_passphrase_sent: info.needs_passphrase_sent,
        }
    }
}

impl Device {
    pub async fn new(
        name: &str,
        device_type: DeviceType,
        path: impl Into<String>,
        model: impl Into<String>,
        device: Box<dyn HWIDevice>,
        is_emulated: bool,
    ) -> Result<Self> {
        Ok(Self {
            name: name.into(),
            device_type,
            path: path.into(),
            model: model.into(),
            device,
            is_emulated,
            fingerprint: None,
            info: None,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn device(&mut self) -> &mut Box<dyn HWIDevice> {
        &mut self.device
    }

    pub fn is_emulated(&self) -> bool {
        self.is_emulated
    }

    pub async fn fingerprint(&mut self) -> Result<Fingerprint> {
        if let Some(fingerprint) = self.fingerprint {
            Ok(fingerprint)
        } else {
            let fingerprint = self.device.get_master_fingerprint().await?;
            self.fingerprint = Some(fingerprint);
            Ok(fingerprint)
        }
    }

    pub async fn info(&mut self) -> Result<Info> {
        if let Some(ref info) = self.info {
            Ok(info.clone())
        } else {
            let info: Info = self.device.get_info().await?.into();
            self.info = Some(info.clone());
            Ok(info)
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, EnumIter, ValueEnum, Serialize, strum::Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum DeviceType {
    #[value(name = "bitbox02", alias = "bit-box02")]
    BitBox02,
    Coldcard,
    Jade,
    #[value(name = "keepkey", alias = "keep-key")]
    KeepKey,
    Ledger,
    Trezor,
}

impl DeviceType {
    pub async fn enumerate(self, selector: &DeviceSelector) -> Result<Vec<Device>> {
        Ok(match self {
            DeviceType::BitBox02 => BitBoxDevice::enumerate(selector).await?,
            DeviceType::Ledger => LedgerDevice::enumerate(selector).await?,
            DeviceType::Coldcard => ColdcardDevice::enumerate(selector).await?,
            DeviceType::Jade => JadeDevice::enumerate(selector).await?,
            DeviceType::KeepKey => KeepKeyDevice::enumerate(selector).await?,
            DeviceType::Trezor => TrezorDevice::enumerate(selector).await?,
        })
    }
}

fn collect_enumeration_results<T>(
    targeted: bool,
    results: Vec<anyhow::Result<Vec<T>>>,
) -> anyhow::Result<Vec<T>> {
    let mut values = Vec::new();
    let mut first_error = None;

    for result in results {
        match result {
            Ok(mut found) => values.append(&mut found),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }

    if values.is_empty()
        && targeted
        && let Some(error) = first_error
    {
        return Err(error);
    }

    Ok(values)
}

pub struct DeviceManager {
    pub selector: DeviceSelector,
}

impl DeviceManager {
    pub fn new(selector: DeviceSelector) -> Self {
        Self { selector }
    }

    pub async fn get_device_with_fingerprint(&self) -> Result<Option<Device>> {
        let mut target_dev = None;
        for mut d in self.enumerate().await? {
            d.device.unlock(self.selector.network).await?;
            if let Some(fingerprint) = self.selector.fingerprint {
                if fingerprint == d.fingerprint().await? {
                    target_dev = Some(d);
                    break;
                }
            } else {
                target_dev = Some(d);
                break;
            }
        }
        let Some(mut dev) = target_dev else {
            return Ok(None);
        };
        if self.selector.passphrase.is_some() && dev.device_type == DeviceType::BitBox02 {
            anyhow::bail!(crate::bitbox::HOST_PASSPHRASE_REJECTED);
        }
        let info = dev.info().await?;
        let networks = &info.networks;
        let net = self.selector.network;
        if !networks.is_empty() && !networks.contains(&net) {
            eprintln!(
                "Warning: device {} is on {}, expected {net}",
                dev.name,
                info.networks_string()
            );
        }
        Ok(Some(dev))
    }

    /// Selects a device without sending it anything: an `Initialize` would clear the
    /// keypad a device is waiting on.
    pub async fn get_device_without_contacting(&self) -> Result<Option<Device>> {
        Ok(self.enumerate().await?.into_iter().next())
    }

    pub async fn enumerate(&self) -> Result<Vec<Device>> {
        let targeted = self.selector.device_type.is_some()
            || self.selector.device_path.is_some()
            || self.selector.fingerprint.is_some();
        let device_types: Vec<DeviceType> = self
            .selector
            .device_type
            .map(|device_type| vec![device_type])
            .unwrap_or_else(|| DeviceType::iter().collect());
        let results = join_all(
            device_types
                .into_iter()
                .map(|device_type| device_type.enumerate(&self.selector)),
        )
        .await;

        collect_enumeration_results(targeted, results)
    }
}

#[async_trait(?Send)]
pub trait DeviceEnumerator {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>>;
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
}

fn option_fingerprint<S>(value: &Option<Fingerprint>, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(v) = value {
        hex::serialize(v, ser)
    } else {
        ser.serialize_none()
    }
}

#[cfg(test)]
mod tests {
    use super::collect_enumeration_results;

    #[test]
    fn enumeration_results_unfiltered_success_plus_error() {
        let results = vec![
            Ok(vec![1_u8, 2]),
            Err(anyhow::anyhow!("unrelated")),
            Ok(vec![3]),
        ];

        assert_eq!(
            collect_enumeration_results(false, results).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn enumeration_results_explicit_family_error() {
        let error = collect_enumeration_results::<u8>(
            true,
            vec![
                Err(anyhow::anyhow!("first")),
                Err(anyhow::anyhow!("second")),
            ],
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "first");
    }

    #[test]
    fn enumeration_results_path_only_no_result_error() {
        let error =
            collect_enumeration_results::<u8>(true, vec![Err(anyhow::anyhow!("path failed"))])
                .unwrap_err();

        assert_eq!(error.to_string(), "path failed");
    }

    #[test]
    fn enumeration_results_fingerprint_only_no_result_error() {
        let error = collect_enumeration_results::<u8>(
            true,
            vec![Err(anyhow::anyhow!("fingerprint failed"))],
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "fingerprint failed");
    }

    #[test]
    fn enumeration_results_targeted_success_despite_another_family_error() {
        let results = vec![Err(anyhow::anyhow!("unrelated")), Ok(vec![7_u8])];

        assert_eq!(collect_enumeration_results(true, results).unwrap(), vec![7]);
    }
}
