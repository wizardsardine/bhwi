use std::rc::Rc;

#[cfg(target_os = "linux")]
pub use bhwi_async_transport::udev;
pub use bhwi_async_transport::{
    Device, DeviceSelector, DeviceType, NativeSource, SkippedDevice, can_sign_taproot,
    is_user_cancelled, networks_string, no_device, reports_device_info,
};
use bitcoin::{Network, bip32::Fingerprint};
use clap::ValueEnum;
use serde::{Serialize, Serializer};

pub type DeviceManager = bhwi_async_transport::DeviceManager<NativeSource>;

/// `Device` carries no serde of its own so each frontend keeps its own output format.
#[derive(Serialize)]
pub struct DeviceJson<'a> {
    name: &'a str,
    #[serde(serialize_with = "serialize_device_type")]
    device_type: DeviceType,
    path: &'a str,
    model: &'a str,
    is_emulated: bool,
    fingerprint: Option<Fingerprint>,
    #[serde(flatten)]
    info: Option<InfoJson<'a>>,
}

#[derive(Serialize)]
struct InfoJson<'a> {
    version: &'a str,
    networks: &'a [Network],
    firmware: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
}

impl<'a> From<&'a Device> for DeviceJson<'a> {
    fn from(device: &'a Device) -> Self {
        Self {
            name: device.name(),
            device_type: device.device_type(),
            path: device.path(),
            model: device.model(),
            is_emulated: device.is_emulated(),
            fingerprint: device.cached_fingerprint(),
            info: device.cached_info().map(|info| InfoJson {
                version: &info.version,
                networks: &info.networks,
                firmware: info.firmware.as_deref(),
                label: info.label.as_deref(),
            }),
        }
    }
}

fn serialize_device_type<S>(device_type: &DeviceType, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_str(device_type.as_str())
}

pub fn device_manager(selector: DeviceSelector) -> DeviceManager {
    let manager =
        DeviceManager::new(NativeSource, selector).with_pairing_code_prompt(Rc::new(|code| {
            eprintln!("\nBitBox02 pairing code — confirm on device:\n\n{code}\n");
        }));
    #[cfg(feature = "keepkey")]
    let manager = manager.with_host_interaction(host::cli_host_interaction());
    manager
}

pub fn warn_skipped(entry: &SkippedDevice) {
    eprintln!(
        "Warning: skipping {} at {}: {}",
        entry.device_type, entry.path, entry.error
    );
}

/// Adds a network warning, so the `hwi` binary deliberately does not use this.
pub async fn select_device(manager: &DeviceManager) -> anyhow::Result<Option<Device>> {
    let (device, skipped) = manager.select().await?;
    let Some(mut device) = device else {
        let Some(first) = skipped.first() else {
            return Ok(None);
        };
        anyhow::bail!("{}", first.error);
    };
    for entry in &skipped {
        warn_skipped(entry);
    }
    if let Some(mismatch) = device.network_mismatch(manager.selector.network).await? {
        eprintln!(
            "Warning: device {} is on {}, expected {}",
            device.name(),
            networks_string(&mismatch.reported),
            mismatch.expected
        );
    }
    Ok(Some(device))
}

pub mod address;
pub mod get_descriptors;
#[cfg(feature = "keepkey")]
pub mod host;
pub mod hwi;
pub mod management;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
}

/// The orphan rule stops us deriving `ValueEnum` on `bhwi-async`'s `DeviceType`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DeviceTypeArg {
    #[value(name = "bitbox02", alias = "bit-box02")]
    BitBox02,
    Coldcard,
    Jade,
    #[value(name = "keepkey", alias = "keep-key")]
    KeepKey,
    Ledger,
    Trezor,
}

impl From<DeviceTypeArg> for DeviceType {
    fn from(arg: DeviceTypeArg) -> Self {
        match arg {
            DeviceTypeArg::BitBox02 => DeviceType::BitBox02,
            DeviceTypeArg::Coldcard => DeviceType::Coldcard,
            DeviceTypeArg::Jade => DeviceType::Jade,
            DeviceTypeArg::KeepKey => DeviceType::KeepKey,
            DeviceTypeArg::Ledger => DeviceType::Ledger,
            DeviceTypeArg::Trezor => DeviceType::Trezor,
        }
    }
}
