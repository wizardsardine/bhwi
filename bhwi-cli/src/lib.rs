//! Native command-line device selection, output helpers, and Python HWI compatibility.
//!
//! Address and descriptor helpers print to stdout; [`hwi::process_request`] returns
//! a serializable response. Selection warnings and device-interaction prompts use stderr.
//! On Unix, `hwi`'s `--stdinpass` password prompt uses the controlling terminal when
//! available, falling back to a stderr prompt and stdin input if password reading fails.
//!
//! Native discovery types and shared selection helpers are reexported here;
//! Linux builds also reexport udev-rule installation through `udev`.

use std::{ops::Deref, rc::Rc};

#[cfg(target_os = "linux")]
pub use bhwi_async_transport::udev;
pub use bhwi_async_transport::{
    Device, DeviceSelector, DeviceType, Info, NativeError, NativeSource, SelectError,
    SkippedDevice, can_sign_taproot, is_user_cancelled, networks_string, no_device,
    reports_device_info,
};
use bitcoin::{Network, bip32::Fingerprint};
use clap::ValueEnum;
use serde::{Serialize, Serializer};

/// A native device manager with CLI pairing and host-interaction prompts.
///
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
    /// Returns whether a password argument was supplied, including an empty one.
    pub fn password_given(&self) -> bool {
        self.password_given
    }

    /// Rejects a supplied host password for BitBox02, which requires on-device entry.
    pub fn refuse_password(&self, device_type: DeviceType) -> Result<(), SelectError<NativeError>> {
        #[cfg(feature = "bitbox")]
        if self.password_given && device_type == DeviceType::BitBox02 {
            return Err(SelectError::HostPassphraseRejected);
        }
        let _ = device_type;
        Ok(())
    }
}

/// The `bhwi` frontend's serializable view of cached device metadata.
///
/// Conversion from [`Device`] performs no I/O. The device family uses the
/// `device_type` key, unlike [`hwi::HwiEnumeratedDevice`]'s `type` key.
/// Uncached info is omitted and an uncached fingerprint is `null`. Absent labels
/// are omitted; missing firmware is `null`, except Specter omits firmware and
/// version keys altogether.
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

/// Creates a native manager with stderr pairing prompts and CLI host interaction.
///
/// `password_given` records whether a password argument was supplied, even if empty.
pub fn device_manager(selector: DeviceSelector, password_given: bool) -> DeviceManager {
    manager_over(NativeSource::default(), selector, password_given)
}

/// Creates a CLI manager that excludes Specter-DIY from broad HWI discovery.
///
/// Python HWI has no Specter-DIY compatibility contract. The exclusion does not
/// prevent explicitly selecting a Specter device.
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

/// Prints a skipped-device warning to stderr.
pub fn warn_skipped(entry: &SkippedDevice) {
    eprintln!(
        "Warning: skipping {} at {}: {}",
        entry.device_type, entry.path, entry.error
    );
}

/// Selects a device and prints skipped-device and network-mismatch warnings to stderr.
///
/// Returns `None` when no device and no skipped candidate are found. If selection
/// finds only skipped candidates, returns the first candidate's error. A network
/// mismatch warns rather than rejecting the device; querying the network may
/// perform I/O. The `hwi` frontend deliberately does not use this warning path.
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

/// An output format for CLI tables and descriptor records.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable tabular output.
    Pretty,
    /// Serialized JSON output.
    Json,
}

/// A device-family argument accepted by Clap, independent of compiled device support.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DeviceTypeArg {
    /// A BitBox02, accepted as `bitbox02` or `bit-box02`.
    #[value(name = "bitbox02", alias = "bit-box02")]
    BitBox02,
    /// A Coldcard.
    Coldcard,
    /// A Blockstream Jade.
    Jade,
    /// A KeepKey, accepted as `keepkey` or `keep-key`.
    #[value(name = "keepkey", alias = "keep-key")]
    KeepKey,
    /// A Ledger.
    Ledger,
    /// A Specter-DIY.
    Specter,
    /// A Trezor.
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
