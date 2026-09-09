use std::{ops::Deref, rc::Rc};

#[cfg(target_os = "linux")]
pub use bhwi_async_transport::udev;
pub use bhwi_async_transport::{
    Device, DeviceSelector, DeviceType, Info, NativeError, NativeSource, SelectError,
    SkippedDevice, is_user_cancelled, networks_string, no_device,
};
use bitcoin::{Network, bip32::Fingerprint};
use clap::ValueEnum;
use serde::{Serialize, Serializer};

/// Remembers whether `-p` was given, since the selector only keeps the password
/// when Trezor or KeepKey is built in.
pub struct DeviceManager {
    manager: bhwi_async_transport::DeviceManager<NativeSource>,
    password_given: bool,
}

impl Deref for DeviceManager {
    type Target = bhwi_async_transport::DeviceManager<NativeSource>;

    fn deref(&self) -> &Self::Target {
        &self.manager
    }
}

impl DeviceManager {
    pub fn password_given(&self) -> bool {
        self.password_given
    }

    /// BitBox02 only takes a passphrase entered on the device.
    pub fn refuse_password(&self, device_type: DeviceType) -> Result<(), SelectError<NativeError>> {
        #[cfg(feature = "bitbox")]
        if self.password_given && device_type == DeviceType::BitBox02 {
            return Err(SelectError::HostPassphraseRejected);
        }
        let _ = device_type;
        Ok(())
    }
}

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

/// The outer `None` omits a key, `Some(None)` writes `null`.
#[derive(Serialize)]
struct InfoJson<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    networks: &'a [Network],
    #[serde(skip_serializing_if = "Option::is_none")]
    firmware: Option<Option<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
}

impl<'a> InfoJson<'a> {
    fn new(device_type: DeviceType, info: &'a Info) -> Self {
        // Specter-DIY reports no firmware, so it has neither key.
        let reports_firmware = device_type != DeviceType::Specter;
        Self {
            version: reports_firmware.then_some(info.version.as_str()),
            networks: &info.networks,
            firmware: reports_firmware.then_some(info.firmware.as_deref()),
            label: info.label.as_deref(),
        }
    }
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
            info: device
                .cached_info()
                .map(|info| InfoJson::new(device.device_type(), info)),
        }
    }
}

fn serialize_device_type<S>(device_type: &DeviceType, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_str(device_type.as_str())
}

pub fn device_manager(selector: DeviceSelector, password_given: bool) -> DeviceManager {
    manager_over(NativeSource::default(), selector, password_given)
}

/// Python HWI has no Specter-DIY compatibility contract.
pub fn python_hwi_device_manager(selector: DeviceSelector, password_given: bool) -> DeviceManager {
    manager_over(
        NativeSource::excluding([DeviceType::Specter]),
        selector,
        password_given,
    )
}

fn manager_over(
    source: NativeSource,
    selector: DeviceSelector,
    password_given: bool,
) -> DeviceManager {
    let manager = bhwi_async_transport::DeviceManager::new(source, selector)
        .with_pairing_code_prompt(Rc::new(|code| {
            eprintln!("\nBitBox02 pairing code — confirm on device:\n\n{code}\n");
        }));
    #[cfg(feature = "keepkey")]
    let manager = manager.with_host_interaction(host::cli_host_interaction());
    DeviceManager {
        manager,
        password_given,
    }
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
    manager.refuse_password(device.device_type())?;
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
    Specter,
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
            DeviceTypeArg::Specter => DeviceType::Specter,
            DeviceTypeArg::Trezor => DeviceType::Trezor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_given_password_is_refused_only_for_bitbox02() {
        let given = device_manager(DeviceSelector::default(), true);
        let not_given = device_manager(DeviceSelector::default(), false);
        for device_type in DeviceType::ALL {
            assert_eq!(
                given.refuse_password(device_type).is_err(),
                cfg!(feature = "bitbox") && device_type == DeviceType::BitBox02,
                "{device_type}"
            );
            assert!(not_given.refuse_password(device_type).is_ok());
        }
    }

    #[test]
    fn ordinary_info_keeps_the_firmware_null_json_contract() {
        let info = Info::default();
        let value = serde_json::to_value(InfoJson::new(DeviceType::Ledger, &info)).unwrap();
        assert!(value.get("version").is_some());
        assert!(value.get("firmware").is_some_and(|value| value.is_null()));
    }

    #[test]
    fn specter_info_omits_unavailable_firmware_from_json() {
        let info = Info {
            version: "unavailable".into(),
            ..Info::default()
        };
        let value = serde_json::to_value(InfoJson::new(DeviceType::Specter, &info)).unwrap();
        assert!(value.get("version").is_none());
        assert!(value.get("firmware").is_none());
        assert!(value.get("networks").is_some());
    }
}
