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
    ledger::LedgerDevice,
};

pub mod address;
pub mod bitbox;
pub mod coldcard;
pub mod config;
pub mod get_descriptors;
pub mod hid;
pub mod hwi;
pub mod jade;
pub mod ledger;
pub mod management;
pub mod udev;

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
    Ledger,
}

impl DeviceType {
    pub async fn enumerate(self, selector: &DeviceSelector) -> Result<Vec<Device>> {
        Ok(match self {
            DeviceType::BitBox02 => BitBoxDevice::enumerate(selector).await?,
            DeviceType::Ledger => LedgerDevice::enumerate(selector).await?,
            DeviceType::Coldcard => ColdcardDevice::enumerate(selector).await?,
            DeviceType::Jade => JadeDevice::enumerate(selector).await?,
        })
    }
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

    pub async fn enumerate(&self) -> Result<Vec<Device>> {
        let device_types: Vec<DeviceType> = self
            .selector
            .device_type
            .map(|device_type| vec![device_type])
            .unwrap_or_else(|| DeviceType::iter().collect());
        let res = join_all(
            device_types
                .into_iter()
                .map(|device_type| device_type.enumerate(&self.selector)),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
        Ok(res.into_iter().flatten().collect())
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
