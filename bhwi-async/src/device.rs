use core::fmt;
use std::rc::Rc;

use async_trait::async_trait;
use bhwi::bitcoin::{Network, bip32::Fingerprint};
use bhwi::passphrase::HostPassphrase;

use crate::{HWIDevice, HWIDeviceError, Info};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DeviceType {
    BitBox02,
    Coldcard,
    Jade,
    Ledger,
    Trezor,
}

impl DeviceType {
    pub const ALL: [DeviceType; 5] = [
        DeviceType::BitBox02,
        DeviceType::Coldcard,
        DeviceType::Jade,
        DeviceType::Ledger,
        DeviceType::Trezor,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DeviceType::BitBox02 => "bitbox02",
            DeviceType::Coldcard => "coldcard",
            DeviceType::Jade => "jade",
            DeviceType::Ledger => "ledger",
            DeviceType::Trezor => "trezor",
        }
    }
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

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

pub type PairingCodePrompt = Rc<dyn Fn(&str)>;

#[async_trait(?Send)]
pub trait DeviceSource {
    type Error: std::error::Error + 'static;

    async fn enumerate(
        &self,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
    ) -> Result<DeviceScan, Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum SelectError<E> {
    #[error(transparent)]
    Source(E),

    #[error(transparent)]
    Device(#[from] HWIDeviceError),

    #[error(transparent)]
    NoUsableDevice(#[from] NoUsableDevice),

    #[cfg(feature = "bitbox")]
    #[error("{}", crate::bitbox::HOST_PASSPHRASE_REJECTED)]
    HostPassphraseRejected,
}

pub struct DeviceManager<S> {
    pub selector: DeviceSelector,
    source: S,
    pairing_code: Option<PairingCodePrompt>,
}

impl<S: DeviceSource> DeviceManager<S> {
    pub fn new(source: S, selector: DeviceSelector) -> Self {
        Self {
            selector,
            source,
            pairing_code: None,
        }
    }

    pub fn with_pairing_code_prompt(mut self, prompt: PairingCodePrompt) -> Self {
        self.pairing_code = Some(prompt);
        self
    }

    pub async fn enumerate(&self) -> Result<DeviceScan, S::Error> {
        self.source
            .enumerate(&self.selector, self.pairing_code.as_ref())
            .await
    }

    pub async fn select(
        &self,
    ) -> Result<(Option<Device>, Vec<SkippedDevice>), SelectError<S::Error>> {
        let scan = self.enumerate().await.map_err(SelectError::Source)?;
        let mut skipped = scan.skipped;
        let mut target_dev = None;
        for mut d in scan.devices {
            let (device_type, model, path) =
                (d.device_type(), d.model().to_string(), d.path().to_string());

            if let Err(err) = d.device().unlock(self.selector.network).await {
                if is_user_cancelled(&err) {
                    return Err(err.into());
                }
                skipped.push(SkippedDevice::new(device_type, model, path, &err));
                continue;
            }

            let Some(fingerprint) = self.selector.fingerprint else {
                target_dev = Some(d);
                break;
            };
            match d.fingerprint().await {
                Ok(found) if found == fingerprint => {
                    target_dev = Some(d);
                    break;
                }
                Ok(_) => {}
                Err(err) => {
                    if is_user_cancelled(&err) {
                        return Err(err.into());
                    }
                    skipped.push(SkippedDevice::new(device_type, model, path, &err));
                }
            }
        }
        let Some(dev) = target_dev else {
            return Ok((None, skipped));
        };
        #[cfg(feature = "bitbox")]
        if self.selector.passphrase.is_some() && dev.device_type() == DeviceType::BitBox02 {
            return Err(SelectError::HostPassphraseRejected);
        }
        Ok((Some(dev), skipped))
    }

    pub async fn get_device_with_fingerprint(
        &self,
    ) -> Result<Option<Device>, SelectError<S::Error>> {
        let (device, skipped) = self.select().await?;
        match device {
            Some(device) => Ok(Some(device)),
            None => Ok(no_device(skipped)?),
        }
    }

    /// Selects a device without sending it anything: an `Initialize` would clear the
    /// keypad a device is waiting on.
    pub async fn get_device_without_contacting(
        &self,
    ) -> Result<Option<Device>, SelectError<S::Error>> {
        let scan = self.enumerate().await.map_err(SelectError::Source)?;
        match scan.devices.into_iter().next() {
            Some(device) => Ok(Some(device)),
            None => Ok(no_device(scan.skipped)?),
        }
    }
}

#[derive(Debug)]
pub struct NoUsableDevice {
    pub skipped: Vec<SkippedDevice>,
}

impl fmt::Display for NoUsableDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reasons = self
            .skipped
            .iter()
            .map(|s| format!("{} at {}: {}", s.device_type, s.path, s.error))
            .collect::<Vec<_>>()
            .join("; ");
        write!(f, "no usable device found, could not open: {reasons}")
    }
}

impl std::error::Error for NoUsableDevice {}

pub fn no_device(skipped: Vec<SkippedDevice>) -> Result<Option<Device>, NoUsableDevice> {
    if skipped.is_empty() {
        return Ok(None);
    }
    Err(NoUsableDevice { skipped })
}

/// `UserCancelled` reaches callers nested inside `HWIDeviceError`, so downcasting the
/// outer error never matches it.
pub fn is_user_cancelled(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(err);
    while let Some(current) = source {
        if matches!(
            current.downcast_ref::<bhwi::common::Error>(),
            Some(bhwi::common::Error::UserCancelled)
        ) {
            return true;
        }
        source = current.source();
    }
    false
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DeviceErrorKind {
    UserCancelled,
    UnsupportedCommand,
    InvalidInput,
    NotReady,
    AlreadyUnlocked,
    Unclassified,
}

#[derive(Debug, Clone)]
pub struct ClassifiedDeviceError {
    pub kind: DeviceErrorKind,
    pub message: String,
}

pub fn classify_error(err: &(dyn std::error::Error + 'static)) -> ClassifiedDeviceError {
    let mut source = Some(err);
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<bhwi::common::Error>() {
            use bhwi::common::Error as CommonError;
            let kind = match error {
                CommonError::UserCancelled => DeviceErrorKind::UserCancelled,
                CommonError::MissingCommandInfo(_) | CommonError::UnsupportedDisplayAddress(_) => {
                    DeviceErrorKind::UnsupportedCommand
                }
                CommonError::InvalidInput(_) | CommonError::Device(_) => {
                    DeviceErrorKind::InvalidInput
                }
                _ => break,
            };
            return ClassifiedDeviceError {
                kind,
                message: error.to_string(),
            };
        }
        // KeepKey re-exports this type, so both devices land here.
        #[cfg(feature = "trezor")]
        if let Some(error) = current.downcast_ref::<bhwi::trezor::TrezorError>() {
            use bhwi::trezor::TrezorError;
            if matches!(
                error,
                TrezorError::NonNumericPin
                    | TrezorError::PassphraseTooLong
                    | TrezorError::InvalidInput(_)
            ) {
                return ClassifiedDeviceError {
                    kind: DeviceErrorKind::InvalidInput,
                    message: error.to_string(),
                };
            }
        }
        source = current.source();
    }
    classify_message(err.to_string())
}

/// A locked Trezor stops answering and says so only in the message text.
pub fn classify_message(message: String) -> ClassifiedDeviceError {
    #[cfg(feature = "trezor")]
    if message.contains(LOCKED_MESSAGE) {
        return ClassifiedDeviceError {
            kind: DeviceErrorKind::NotReady,
            message: LOCKED_MESSAGE.to_owned(),
        };
    }
    #[cfg(feature = "keepkey")]
    if message.contains(KEEPKEY_LOCKED_MESSAGE) {
        return ClassifiedDeviceError {
            kind: DeviceErrorKind::NotReady,
            message: KEEPKEY_LOCKED_MESSAGE.to_owned(),
        };
    }
    #[cfg(feature = "trezor")]
    for unlocked in [
        bhwi::trezor::TrezorError::NO_PIN_NEEDED,
        bhwi::trezor::TrezorError::PIN_ALREADY_SENT,
    ] {
        if message.contains(unlocked) {
            return ClassifiedDeviceError {
                kind: DeviceErrorKind::AlreadyUnlocked,
                message: unlocked.to_owned(),
            };
        }
    }
    ClassifiedDeviceError {
        kind: DeviceErrorKind::Unclassified,
        message,
    }
}

#[cfg(feature = "trezor")]
pub const LOCKED_MESSAGE: &str = bhwi::trezor::TrezorError::LOCKED;

#[cfg(feature = "keepkey")]
pub const KEEPKEY_LOCKED_MESSAGE: &str = bhwi::keepkey::KEEPKEY_LOCKED;

#[derive(Debug, Clone)]
pub struct SkippedDevice {
    pub device_type: DeviceType,
    pub model: String,
    pub path: String,
    pub error: String,
    pub kind: DeviceErrorKind,
}

pub enum ScanEntry {
    Found(Device),
    Skipped(SkippedDevice),
}

impl SkippedDevice {
    pub fn new(
        device_type: DeviceType,
        model: impl Into<String>,
        path: impl Into<String>,
        error: &(dyn std::error::Error + 'static),
    ) -> Self {
        let ClassifiedDeviceError { kind, .. } = classify_error(error);
        Self {
            device_type,
            model: model.into(),
            path: path.into(),
            error: error.to_string(),
            kind,
        }
    }
}

impl ScanEntry {
    pub fn skipped(
        device_type: DeviceType,
        model: impl Into<String>,
        path: impl Into<String>,
        error: &(dyn std::error::Error + 'static),
    ) -> Self {
        Self::Skipped(SkippedDevice::new(device_type, model, path, error))
    }
}

#[derive(Default)]
pub struct DeviceScan {
    pub devices: Vec<Device>,
    pub skipped: Vec<SkippedDevice>,
}

impl Extend<ScanEntry> for DeviceScan {
    fn extend<I: IntoIterator<Item = ScanEntry>>(&mut self, iter: I) {
        for entry in iter {
            match entry {
                ScanEntry::Found(device) => self.devices.push(device),
                ScanEntry::Skipped(skipped) => self.skipped.push(skipped),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkMismatch {
    pub expected: Network,
    pub reported: Vec<Network>,
}

pub fn networks_string(networks: &[Network]) -> String {
    networks
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub struct Device {
    name: String,
    device_type: DeviceType,
    path: String,
    model: String,
    device: Box<dyn HWIDevice>,
    is_emulated: bool,
    fingerprint: Option<Fingerprint>,
    info: Option<Info>,
}

impl Device {
    pub fn new(
        name: &str,
        device_type: DeviceType,
        path: impl Into<String>,
        model: impl Into<String>,
        device: Box<dyn HWIDevice>,
        is_emulated: bool,
    ) -> Self {
        Self {
            name: name.into(),
            device_type,
            path: path.into(),
            model: model.into(),
            device,
            is_emulated,
            fingerprint: None,
            info: None,
        }
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

    pub fn cached_fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprint
    }

    pub fn cached_info(&self) -> Option<&Info> {
        self.info.as_ref()
    }

    pub async fn fingerprint(&mut self) -> Result<Fingerprint, HWIDeviceError> {
        if let Some(fingerprint) = self.fingerprint {
            Ok(fingerprint)
        } else {
            let fingerprint = self.device.get_master_fingerprint().await?;
            self.fingerprint = Some(fingerprint);
            Ok(fingerprint)
        }
    }

    pub async fn network_mismatch(
        &mut self,
        expected: Network,
    ) -> Result<Option<NetworkMismatch>, HWIDeviceError> {
        let info = self.info().await?;
        if info.networks.is_empty() || info.networks.contains(&expected) {
            return Ok(None);
        }
        Ok(Some(NetworkMismatch {
            expected,
            reported: info.networks,
        }))
    }

    pub async fn info(&mut self) -> Result<Info, HWIDeviceError> {
        if let Some(ref info) = self.info {
            Ok(info.clone())
        } else {
            let info = self.device.get_info().await?;
            self.info = Some(info.clone());
            Ok(info)
        }
    }
}
