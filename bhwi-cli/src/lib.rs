use anyhow::Result;
use async_trait::async_trait;
use bhwi_async::HWIDevice;
use bitcoin::{Network, bip32::Fingerprint};
use clap::ValueEnum;
use futures::future::join_all;
use serde::{Serialize, Serializer};
use strum::{EnumIter, IntoEnumIterator};

use crate::{coldcard::ColdcardDevice, config::Config, jade::JadeDevice, ledger::LedgerDevice};

pub mod address;
pub mod coldcard;
pub mod config;
pub mod get_descriptors;
pub mod hid;
pub mod jade;
pub mod ledger;

#[derive(Serialize)]
pub struct Device {
    name: String,
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
        }
    }
}

impl Device {
    pub async fn new(name: &str, device: Box<dyn HWIDevice>, is_emulated: bool) -> Result<Self> {
        Ok(Self {
            name: name.into(),
            device,
            is_emulated,
            fingerprint: None,
            info: None,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
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

#[derive(Debug, EnumIter, strum::Display)]
pub enum DeviceType {
    Coldcard,
    Jade,
    Ledger,
}

impl DeviceType {
    pub async fn enumerate(self, config: &Config) -> Result<Vec<Device>> {
        Ok(match self {
            DeviceType::Ledger => LedgerDevice::enumerate(config).await?,
            DeviceType::Coldcard => ColdcardDevice::enumerate(config).await?,
            DeviceType::Jade => JadeDevice::enumerate(config).await?,
        })
    }
}

pub struct DeviceManager {
    pub config: Config,
}

impl DeviceManager {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn get_device_with_fingerprint(&self) -> Result<Option<Device>> {
        let mut target_dev = None;
        for mut d in self.enumerate().await? {
            d.device.unlock(self.config.network).await?;
            if let Some(fingerprint) = self.config.fingerprint {
                if fingerprint == d.fingerprint().await? {
                    target_dev = Some(d);
                }
            } else {
                target_dev = Some(d);
            }
        }
        let Some(mut dev) = target_dev else {
            return Ok(None);
        };
        let info = dev.info().await?;
        let networks = &info.networks;
        let net = self.config.network;
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
        let res = join_all(DeviceType::iter().map(|t| t.enumerate(&self.config)))
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        Ok(res.into_iter().flatten().collect())
    }
}

#[async_trait(?Send)]
pub trait DeviceEnumerator {
    async fn enumerate(config: &Config) -> Result<Vec<Device>>;
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
