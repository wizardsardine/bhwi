use anyhow::Result;
use async_trait::async_trait;
use bhwi_async::HWIDevice;
use bitcoin::bip32::Fingerprint;
use clap::ValueEnum;
use futures::future::join_all;
use serde::{Serialize, Serializer};
use strum::{EnumIter, IntoEnumIterator};

use crate::{coldcard::ColdcardDevice, config::Config, jade::JadeDevice, ledger::LedgerDevice};

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
}

impl Device {
    pub async fn new(name: &str, device: Box<dyn HWIDevice>, is_emulated: bool) -> Result<Self> {
        Ok(Self {
            name: name.into(),
            device,
            is_emulated,
            fingerprint: None,
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
        for mut d in self.enumerate().await? {
            d.device.unlock(self.config.network).await?;
            if let Some(fingerprint) = self.config.fingerprint {
                if fingerprint == d.fingerprint().await? {
                    return Ok(Some(d));
                }
            } else {
                return Ok(Some(d));
            }
        }
        Ok(None)
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
