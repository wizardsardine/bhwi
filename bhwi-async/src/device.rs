use core::fmt;
use std::rc::Rc;

use async_trait::async_trait;
use bhwi::bitcoin::{Network, bip32::Fingerprint};
#[cfg(any(feature = "trezor", feature = "keepkey"))]
use bhwi::passphrase::HostPassphrase;

use crate::{HWIDevice, HWIDeviceError, Info};

/// A supported hardware-wallet family, independent of enabled backend features.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DeviceType {
    /// A BitBox02.
    BitBox02,
    /// A Coldcard.
    Coldcard,
    /// A Blockstream Jade.
    Jade,
    /// A KeepKey.
    KeepKey,
    /// A Ledger running the Bitcoin application.
    Ledger,
    /// A Specter-DIY.
    Specter,
    /// A Trezor.
    Trezor,
}

impl DeviceType {
    /// All recognized wallet families, including backends not compiled in.
    pub const ALL: [DeviceType; 7] = [
        DeviceType::BitBox02,
        DeviceType::Coldcard,
        DeviceType::Jade,
        DeviceType::KeepKey,
        DeviceType::Ledger,
        DeviceType::Specter,
        DeviceType::Trezor,
    ];

    /// Returns the lowercase device-family identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceType::BitBox02 => "bitbox02",
            DeviceType::Coldcard => "coldcard",
            DeviceType::Jade => "jade",
            DeviceType::KeepKey => "keepkey",
            DeviceType::Ledger => "ledger",
            DeviceType::Specter => "specter",
            DeviceType::Trezor => "trezor",
        }
    }
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returns whether the family accepts multisig descriptors directly at display time.
pub fn supports_multisig_display_address(device_type: DeviceType) -> bool {
    matches!(
        device_type,
        DeviceType::Coldcard | DeviceType::Jade | DeviceType::KeepKey | DeviceType::Trezor
    )
}

/// Returns the known Taproot-signing capability for a family and model string.
pub fn can_sign_taproot(device_type: DeviceType, model: &str) -> bool {
    match device_type {
        DeviceType::BitBox02 => false,
        DeviceType::Ledger => true,
        DeviceType::Jade => false,
        DeviceType::KeepKey => false,
        DeviceType::Coldcard => model.contains("edge"),
        DeviceType::Specter => false,
        DeviceType::Trezor => model != "trezor_one",
    }
}

/// Returns whether the family reports the management metadata used by discovery.
pub fn reports_device_info(device_type: DeviceType) -> bool {
    matches!(device_type, DeviceType::KeepKey | DeviceType::Trezor)
}

/// Filters discovery candidates and optionally selects a wallet by fingerprint.
#[derive(Debug, Clone)]
pub struct DeviceSelector {
    /// The network used when opening a device and running its unlock handshake.
    pub network: Network,
    /// A wallet fingerprint to query after the unlock handshake; `None` accepts any.
    pub fingerprint: Option<Fingerprint>,
    /// A device-family filter; `None` accepts any family.
    pub device_type: Option<DeviceType>,
    /// An exact discovery-path filter; `None` accepts any path.
    pub device_path: Option<String>,
    /// Whether discovery should include emulator candidates.
    pub include_emulators: bool,
    /// An optional host passphrase, supported only by Trezor and KeepKey.
    #[cfg(any(feature = "trezor", feature = "keepkey"))]
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
            #[cfg(any(feature = "trezor", feature = "keepkey"))]
            passphrase: None,
        }
    }
}

impl DeviceSelector {
    /// Returns whether the family and path match, without probing a fingerprint.
    ///
    /// This does not check emulator inclusion, the network, or the passphrase.
    pub fn matches(&self, device_type: DeviceType, path: &str) -> bool {
        self.device_type.is_none_or(|target| target == device_type)
            && self
                .device_path
                .as_ref()
                .is_none_or(|target| target == path)
    }
}

/// A callback that presents a BitBox02 pairing code to the user.
pub type PairingCodePrompt = Rc<dyn Fn(&str)>;

/// A device found on a bus but not yet opened.
#[derive(Debug, Clone)]
pub struct DeviceCandidate {
    /// The device family.
    pub device_type: DeviceType,
    /// The discovery source's display name.
    pub name: String,
    /// The discovery source's model identifier.
    pub model: String,
    /// The source-specific path used to open this candidate.
    pub path: String,
    /// Whether this candidate represents an emulator.
    pub is_emulated: bool,
}

/// Creates host-input handlers before a device is boxed, including mid-command prompts.
pub type HostInteractionFactory = Rc<dyn Fn() -> Box<dyn crate::HostInteraction>>;

/// Discovers and opens devices using source-specific I/O.
///
/// Futures need not be `Send`; implementations choose their I/O runtime.
#[async_trait(?Send)]
pub trait DeviceSource {
    /// A discovery or device-opening failure.
    type Error: std::error::Error + 'static;

    /// Lists matching candidates, potentially probing emulators with I/O.
    async fn list(&self, selector: &DeviceSelector) -> Result<Vec<DeviceCandidate>, Self::Error>;

    /// Opens a candidate and attaches the supplied pairing and host-input callbacks.
    ///
    /// Opening may perform I/O, but does not by itself promise an unlocked wallet.
    async fn open(
        &self,
        candidate: &DeviceCandidate,
        selector: &DeviceSelector,
        pairing_code: Option<&PairingCodePrompt>,
        host_interaction: Option<&HostInteractionFactory>,
    ) -> Result<Device, Self::Error>;
}

/// A discovery, opening, or wallet-selection failure.
#[derive(Debug, thiserror::Error)]
pub enum SelectError<E> {
    /// The source could not list candidates.
    #[error(transparent)]
    Source(
        /// The source error.
        E,
    ),

    /// A wallet operation failed or was cancelled.
    #[error(transparent)]
    Device(
        /// The wallet-operation error.
        #[from]
        HWIDeviceError,
    ),

    /// Candidates were found but none could be used.
    #[error(transparent)]
    NoUsableDevice(
        /// The rejected candidates and their errors.
        #[from]
        NoUsableDevice,
    ),

    /// A host passphrase was supplied for a BitBox02.
    #[cfg(feature = "bitbox")]
    #[error("{}", crate::bitbox::HOST_PASSPHRASE_REJECTED)]
    HostPassphraseRejected,
}

/// Discovers, opens, and selects wallets through a [`DeviceSource`].
pub struct DeviceManager<S> {
    /// The discovery filters and wallet-selection requirements.
    pub selector: DeviceSelector,
    source: S,
    pairing_code: Option<PairingCodePrompt>,
    host_interaction: Option<HostInteractionFactory>,
}

impl<S: DeviceSource> DeviceManager<S> {
    /// Creates a manager with no pairing or host-input callbacks.
    pub fn new(source: S, selector: DeviceSelector) -> Self {
        Self {
            selector,
            source,
            pairing_code: None,
            host_interaction: None,
        }
    }

    /// Sets the callback used to present BitBox02 pairing codes.
    pub fn with_pairing_code_prompt(mut self, prompt: PairingCodePrompt) -> Self {
        self.pairing_code = Some(prompt);
        self
    }

    /// Sets the factory used to attach host-input handlers to opened devices.
    pub fn with_host_interaction(mut self, factory: HostInteractionFactory) -> Self {
        self.host_interaction = Some(factory);
        self
    }

    /// Lists candidates using the selector, potentially probing emulators.
    pub async fn list(&self) -> Result<Vec<DeviceCandidate>, S::Error> {
        self.source.list(&self.selector).await
    }

    /// Opens a candidate using the selector and configured callbacks.
    pub async fn open(&self, candidate: &DeviceCandidate) -> Result<Device, S::Error> {
        self.source
            .open(
                candidate,
                &self.selector,
                self.pairing_code.as_ref(),
                self.host_interaction.as_ref(),
            )
            .await
    }

    /// Opens listed candidates without additional unlock or metadata requests.
    ///
    /// Source-specific opening may still send wallet commands, such as native
    /// Specter's fingerprint probe. Opening errors are collected in
    /// [`DeviceScan::skipped`].
    pub async fn enumerate(&self) -> Result<DeviceScan, S::Error> {
        let mut scan = DeviceScan::default();
        for candidate in self.list().await? {
            match self.open(&candidate).await {
                Ok(device) => scan.devices.push(device),
                Err(err) => scan.skipped.push(skipped_candidate(&candidate, &err)),
            }
        }
        Ok(scan)
    }

    /// Opens candidates and runs their unlock handshake until the optional fingerprint matches.
    ///
    /// Successful Trezor or KeepKey initialization can leave the wallet PIN-locked.
    /// A common [`bhwi::common::ErrorKind::UserCancelled`] from unlock or fingerprint
    /// queries aborts selection. Without a fingerprint filter, any unlock failure
    /// is returned rather than silently selecting another wallet. Other failures
    /// are collected as skipped devices. Trezor and KeepKey device-side cancellations
    /// become authentication refusals and may be skipped when filtering by fingerprint.
    pub async fn select(
        &self,
    ) -> Result<(Option<Device>, Vec<SkippedDevice>), SelectError<S::Error>> {
        let candidates = self.list().await.map_err(SelectError::Source)?;
        let mut skipped = Vec::new();
        let mut target_dev = None;
        for candidate in candidates {
            let mut d = match self.open(&candidate).await {
                Ok(device) => device,
                Err(err) => {
                    skipped.push(skipped_candidate(&candidate, &err));
                    continue;
                }
            };

            if let Err(err) = d.device().unlock(self.selector.network).await {
                // Without a fingerprint, skipping would hand back the next wallet instead.
                if is_user_cancelled(&err) || self.selector.fingerprint.is_none() {
                    return Err(err.into());
                }
                skipped.push(skipped_candidate(&candidate, &err));
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
                    skipped.push(skipped_candidate(&candidate, &err));
                }
            }
        }
        let Some(dev) = target_dev else {
            return Ok((None, skipped));
        };
        #[cfg(all(feature = "bitbox", any(feature = "trezor", feature = "keepkey")))]
        if self.selector.passphrase.is_some() && dev.device_type() == DeviceType::BitBox02 {
            return Err(SelectError::HostPassphraseRejected);
        }
        Ok((Some(dev), skipped))
    }

    /// Opens and probes candidates, caching information and initialized-wallet fingerprints.
    ///
    /// A common [`bhwi::common::ErrorKind::UserCancelled`] from unlock or probe commands
    /// aborts the scan. Other per-device failures, including Trezor and KeepKey
    /// device-side cancellations mapped to authentication refusals, are collected
    /// as skipped devices.
    pub async fn scan(&self) -> Result<DeviceScan, SelectError<S::Error>> {
        let candidates = self.list().await.map_err(SelectError::Source)?;
        let mut scan = DeviceScan::default();
        for candidate in candidates {
            let mut device = match self.open(&candidate).await {
                Ok(device) => device,
                Err(err) => {
                    scan.skipped.push(skipped_candidate(&candidate, &err));
                    continue;
                }
            };
            match probe(&mut device, self.selector.network).await {
                Ok(()) => scan.devices.push(device),
                Err(err) if is_user_cancelled(&err) => return Err(err.into()),
                Err(err) => scan.skipped.push(skipped_candidate(&candidate, &err)),
            }
        }
        Ok(scan)
    }

    /// Selects a wallet, returning an error if all candidates were skipped.
    ///
    /// With no fingerprint filter, the first successful unlock handshake is accepted;
    /// Trezor and KeepKey may still require a PIN. Uses the rules of [`Self::select`].
    pub async fn get_device_with_fingerprint(
        &self,
    ) -> Result<Option<Device>, SelectError<S::Error>> {
        let (device, skipped) = self.select().await?;
        match device {
            Some(device) => Ok(Some(device)),
            None => Ok(no_device(skipped)?),
        }
    }

    /// Returns the first usable candidate from [`Self::enumerate`].
    ///
    /// The manager makes no additional unlock or metadata request. Discovery and
    /// source-specific opening may still perform protocol I/O, including native
    /// Specter's fingerprint probe.
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

/// A scan in which every candidate was rejected.
#[derive(Debug)]
pub struct NoUsableDevice {
    /// The rejected candidates and their classified errors.
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

fn skipped_candidate(
    candidate: &DeviceCandidate,
    error: &(dyn std::error::Error + 'static),
) -> SkippedDevice {
    SkippedDevice::new(
        candidate.device_type,
        &candidate.model,
        &candidate.path,
        error,
    )
}

async fn probe(device: &mut Device, network: Network) -> Result<(), HWIDeviceError> {
    // XXX: Coldcard always needs unlocking
    device.device().unlock(network).await?;
    let info = device.info().await?;
    if info.initialized != Some(false) {
        device.fingerprint().await?;
    }
    Ok(())
}

/// Returns `None` for an empty scan or an error containing rejected candidates.
pub fn no_device(skipped: Vec<SkippedDevice>) -> Result<Option<Device>, NoUsableDevice> {
    if skipped.is_empty() {
        return Ok(None);
    }
    Err(NoUsableDevice { skipped })
}

/// Returns whether an error chain contains a common user-cancellation error.
pub fn is_user_cancelled(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(err);
    while let Some(current) = source {
        if current
            .downcast_ref::<bhwi::common::Error>()
            .is_some_and(|error| error.kind() == bhwi::common::ErrorKind::UserCancelled)
        {
            return true;
        }
        source = current.source();
    }
    false
}

/// A caller-facing classification of a device-operation failure.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DeviceErrorKind {
    /// The user cancelled the operation.
    UserCancelled,
    /// Required command information is absent or address display is unsupported.
    UnsupportedCommand,
    /// Input or a reported device error was classified as invalid.
    InvalidInput,
    /// The device reports that it is locked.
    NotReady,
    /// The device reports that PIN submission is unnecessary or already complete.
    AlreadyUnlocked,
    /// No recognized typed error or message was found.
    Unclassified,
}

/// A device error's classification and display message.
#[derive(Debug, Clone)]
pub struct ClassifiedDeviceError {
    /// The recognized error category.
    pub kind: DeviceErrorKind,
    /// The selected error message.
    pub message: String,
}

/// Classifies recognized errors in the source chain, then falls back to message matching.
pub fn classify_error(err: &(dyn std::error::Error + 'static)) -> ClassifiedDeviceError {
    let mut source = Some(err);
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<bhwi::common::Error>() {
            use bhwi::common::ErrorKind;
            let kind = match error.kind() {
                ErrorKind::UserCancelled => DeviceErrorKind::UserCancelled,
                ErrorKind::Unsupported
                | ErrorKind::MissingContext
                | ErrorKind::UnsupportedDisplayAddress => DeviceErrorKind::UnsupportedCommand,
                ErrorKind::InvalidInput | ErrorKind::Rejected => DeviceErrorKind::InvalidInput,
                _ => break,
            };
            return ClassifiedDeviceError {
                kind,
                message: error.to_string(),
            };
        }
        // KeepKey re-exports this type, so both devices land here.
        #[cfg(any(feature = "keepkey", feature = "trezor"))]
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

/// Classifies known locked or already-unlocked messages, preserving other messages.
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
    #[cfg(any(feature = "keepkey", feature = "trezor"))]
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

/// The Trezor locked-device message recognized by [`classify_message`].
#[cfg(feature = "trezor")]
pub const LOCKED_MESSAGE: &str = bhwi::trezor::TrezorError::LOCKED;

/// The KeepKey locked-device message recognized by [`classify_message`].
#[cfg(feature = "keepkey")]
pub const KEEPKEY_LOCKED_MESSAGE: &str = bhwi::keepkey::KEEPKEY_LOCKED;

/// A candidate rejected during opening, selection, or probing.
#[derive(Debug, Clone)]
pub struct SkippedDevice {
    /// The rejected device family.
    pub device_type: DeviceType,
    /// The discovery model identifier.
    pub model: String,
    /// The discovery path.
    pub path: String,
    /// The classified error's display message.
    pub error: String,
    /// The classified error category.
    pub kind: DeviceErrorKind,
}

/// A successfully opened device or a rejected candidate.
pub enum ScanEntry {
    /// An opened device.
    Found(
        /// The opened device.
        Device,
    ),
    /// A rejected candidate.
    Skipped(
        /// The candidate and its classified error.
        SkippedDevice,
    ),
}

impl SkippedDevice {
    /// Creates a rejected-candidate record by classifying an error.
    pub fn new(
        device_type: DeviceType,
        model: impl Into<String>,
        path: impl Into<String>,
        error: &(dyn std::error::Error + 'static),
    ) -> Self {
        let ClassifiedDeviceError { kind, message } = classify_error(error);
        Self {
            device_type,
            model: model.into(),
            path: path.into(),
            error: message,
            kind,
        }
    }
}

impl ScanEntry {
    /// Creates a skipped scan entry from candidate metadata and an error.
    pub fn skipped(
        device_type: DeviceType,
        model: impl Into<String>,
        path: impl Into<String>,
        error: &(dyn std::error::Error + 'static),
    ) -> Self {
        Self::Skipped(SkippedDevice::new(device_type, model, path, error))
    }
}

/// Opened devices and rejected candidates collected by a scan.
#[derive(Default)]
pub struct DeviceScan {
    /// Successfully opened devices; metadata availability depends on the scan operation.
    pub devices: Vec<Device>,
    /// Candidates rejected during the scan.
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

/// A requested network absent from the device's nonempty reported network list.
#[derive(Debug, Clone)]
pub struct NetworkMismatch {
    /// The requested network.
    pub expected: Network,
    /// The networks reported by the device.
    pub reported: Vec<Network>,
}

/// Formats network names as a comma-separated string.
pub fn networks_string(networks: &[Network]) -> String {
    networks
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// An opened wallet with discovery metadata and cached successful query results.
///
/// Cached information and fingerprints are not automatically invalidated when
/// callers change the wallet or session through [`Self::device`].
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
    /// Wraps an opened wallet with discovery metadata and empty query caches.
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

    /// Returns the discovery display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the device family.
    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    /// Returns the source-specific discovery path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the discovery model identifier.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Returns the underlying wallet interface without invalidating query caches.
    pub fn device(&mut self) -> &mut Box<dyn HWIDevice> {
        &mut self.device
    }

    /// Returns whether discovery identified this device as an emulator.
    pub fn is_emulated(&self) -> bool {
        self.is_emulated
    }

    /// Returns the last successfully queried fingerprint, without performing I/O.
    pub fn cached_fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprint
    }

    /// Returns cached information, without performing I/O.
    pub fn cached_info(&self) -> Option<&Info> {
        self.info.as_ref()
    }

    /// Returns the cached fingerprint or queries the wallet and caches success.
    pub async fn fingerprint(&mut self) -> Result<Fingerprint, HWIDeviceError> {
        if let Some(fingerprint) = self.fingerprint {
            Ok(fingerprint)
        } else {
            let fingerprint = self.device.get_master_fingerprint().await?;
            self.fingerprint = Some(fingerprint);
            Ok(fingerprint)
        }
    }

    /// Returns a mismatch when nonempty reported networks exclude `expected`.
    ///
    /// This may query information; an empty network list is treated as unknown.
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

    /// Returns cached information or queries the device and caches success.
    ///
    /// Specter-DIY instead receives synthetic default information with version
    /// `"unavailable"`, because it has no version command.
    pub async fn info(&mut self) -> Result<Info, HWIDeviceError> {
        if let Some(ref info) = self.info {
            Ok(info.clone())
        } else if self.device_type == DeviceType::Specter {
            // Specter-DIY has no version command, so asking would fail the call.
            let info = Info {
                version: "unavailable".into(),
                ..Info::default()
            };
            self.info = Some(info.clone());
            Ok(info)
        } else {
            let info = self.device.get_info().await?;
            self.info = Some(info.clone());
            Ok(info)
        }
    }
}

#[cfg(test)]
mod tests {
    use bhwi::bitcoin::{
        bip32::{DerivationPath, Xpub},
        psbt::Psbt,
        secp256k1::ecdsa::Signature,
    };
    use futures::executor::block_on;

    use super::*;
    use crate::{
        DeviceBackup, DeviceContext, DisplayAddress, RestoreOptions, SetupOptions,
        WalletRegistration,
    };

    /// Answers only what `select` asks: unlock and the master fingerprint.
    struct Wallet {
        fingerprint: Fingerprint,
        refuses_unlock: bool,
    }

    #[async_trait(?Send)]
    impl HWIDevice for Wallet {
        async fn backup_device(&mut self) -> Result<DeviceBackup, HWIDeviceError> {
            unimplemented!()
        }
        async fn setup_device(
            &mut self,
            _: SetupOptions,
            _: Option<DeviceContext>,
        ) -> Result<bool, HWIDeviceError> {
            unimplemented!()
        }
        async fn wipe_device(&mut self) -> Result<bool, HWIDeviceError> {
            unimplemented!()
        }
        async fn restore_device(
            &mut self,
            _: RestoreOptions,
            _: Option<DeviceContext>,
        ) -> Result<bool, HWIDeviceError> {
            unimplemented!()
        }
        async fn toggle_passphrase(&mut self) -> Result<bool, HWIDeviceError> {
            unimplemented!()
        }
        async fn prompt_pin(&mut self) -> Result<bool, HWIDeviceError> {
            unimplemented!()
        }
        async fn send_pin(&mut self, _: Option<DeviceContext>) -> Result<bool, HWIDeviceError> {
            unimplemented!()
        }
        async fn unlock(&mut self, _: Network) -> Result<(), HWIDeviceError> {
            if self.refuses_unlock {
                let refusal: Box<dyn std::error::Error + Send + Sync> =
                    "authentication refused".into();
                return Err(refusal.into());
            }
            Ok(())
        }
        async fn get_info(&mut self) -> Result<Info, HWIDeviceError> {
            unimplemented!()
        }
        async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, HWIDeviceError> {
            Ok(self.fingerprint)
        }
        async fn get_extended_pubkey(
            &mut self,
            _: DerivationPath,
            _: bool,
        ) -> Result<Xpub, HWIDeviceError> {
            unimplemented!()
        }
        async fn sign_message(
            &mut self,
            _: &[u8],
            _: DerivationPath,
        ) -> Result<(u8, Signature), HWIDeviceError> {
            unimplemented!()
        }
        async fn display_address(
            &mut self,
            _: DisplayAddress,
            _: Option<DeviceContext>,
        ) -> Result<String, HWIDeviceError> {
            unimplemented!()
        }
        async fn register_wallet(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<WalletRegistration, HWIDeviceError> {
            unimplemented!()
        }
        async fn sign_tx(
            &mut self,
            _: Psbt,
            _: Option<DeviceContext>,
        ) -> Result<Psbt, HWIDeviceError> {
            unimplemented!()
        }
    }

    const REFUSING: [u8; 4] = [0xaa; 4];
    const UNLOCKED: [u8; 4] = [0xbb; 4];

    /// A wallet that refuses authentication, then one that unlocks.
    struct Wallets(DeviceType);

    #[async_trait(?Send)]
    impl DeviceSource for Wallets {
        type Error = std::io::Error;

        async fn list(&self, _: &DeviceSelector) -> Result<Vec<DeviceCandidate>, Self::Error> {
            Ok(["refusing", "unlocked"]
                .into_iter()
                .map(|path| DeviceCandidate {
                    device_type: self.0,
                    name: "wallet".to_owned(),
                    model: "wallet".to_owned(),
                    path: path.to_owned(),
                    is_emulated: true,
                })
                .collect())
        }

        async fn open(
            &self,
            candidate: &DeviceCandidate,
            _: &DeviceSelector,
            _: Option<&PairingCodePrompt>,
            _: Option<&HostInteractionFactory>,
        ) -> Result<Device, Self::Error> {
            let refuses_unlock = candidate.path == "refusing";
            let wallet = Wallet {
                fingerprint: Fingerprint::from(if refuses_unlock { REFUSING } else { UNLOCKED }),
                refuses_unlock,
            };
            Ok(Device::new(
                &candidate.name,
                candidate.device_type,
                &candidate.path,
                &candidate.model,
                Box::new(wallet),
                candidate.is_emulated,
            ))
        }
    }

    fn manager(fingerprint: Option<Fingerprint>) -> DeviceManager<Wallets> {
        let selector = DeviceSelector {
            fingerprint,
            ..DeviceSelector::default()
        };
        DeviceManager::new(Wallets(DeviceType::Trezor), selector)
    }

    #[cfg(all(feature = "bitbox", any(feature = "trezor", feature = "keepkey")))]
    #[test]
    fn a_bitbox02_refuses_any_supplied_passphrase() {
        for passphrase in [Some("secret"), Some(""), None] {
            let selector = DeviceSelector {
                fingerprint: Some(Fingerprint::from(UNLOCKED)),
                passphrase: passphrase.map(|p| HostPassphrase::new(p.to_owned())),
                ..DeviceSelector::default()
            };
            let result =
                block_on(DeviceManager::new(Wallets(DeviceType::BitBox02), selector).select());
            assert_eq!(
                matches!(result, Err(SelectError::HostPassphraseRejected)),
                passphrase.is_some()
            );
        }
    }

    #[test]
    fn a_refused_unlock_ends_selection_when_no_fingerprint_was_named() {
        let err = block_on(manager(None).select())
            .err()
            .expect("the refusal is reported");
        assert!(matches!(err, SelectError::Device(_)));
    }

    #[test]
    fn a_refused_unlock_is_skipped_while_looking_for_a_named_fingerprint() {
        let unlocked = Fingerprint::from(UNLOCKED);
        let (device, skipped) =
            block_on(manager(Some(unlocked)).select()).expect("the named wallet is found");
        assert_eq!(
            device.expect("a wallet").cached_fingerprint(),
            Some(unlocked)
        );
        assert_eq!(skipped.len(), 1);
    }

    #[test]
    fn taproot_support_matches_python_hwi() {
        assert!(can_sign_taproot(
            DeviceType::Ledger,
            "ledger_nano_s_simulator"
        ));
        assert!(!can_sign_taproot(
            DeviceType::BitBox02,
            "bitbox02_simulator"
        ));
        assert!(!can_sign_taproot(DeviceType::Jade, "jade_simulator"));
        assert!(can_sign_taproot(
            DeviceType::Coldcard,
            "coldcard_simulator_edge"
        ));
        assert!(!can_sign_taproot(
            DeviceType::Coldcard,
            "coldcard_simulator"
        ));
        assert!(can_sign_taproot(DeviceType::Trezor, "trezor_t"));
        assert!(!can_sign_taproot(DeviceType::Trezor, "trezor_one"));
    }

    #[test]
    fn an_interpreter_error_reads_as_its_cause() {
        let wrapped: crate::Error<std::io::Error, std::io::Error> = crate::Error::Interpreter(
            bhwi::common::Error::new(bhwi::common::ErrorKind::InvalidInput, "Passphrase too long"),
        );
        assert_eq!(wrapped.to_string(), "[InvalidInput] Passphrase too long");
        assert_eq!(
            std::error::Error::source(&wrapped)
                .expect("the cause is kept")
                .to_string(),
            "[InvalidInput] Passphrase too long"
        );

        let skipped = SkippedDevice::new(DeviceType::KeepKey, "keepkey", "udp:11044", &wrapped);
        assert_eq!(skipped.error, "[InvalidInput] Passphrase too long");
        assert!(matches!(skipped.kind, DeviceErrorKind::InvalidInput));
    }

    #[cfg(any(feature = "keepkey", feature = "trezor"))]
    #[test]
    fn a_raw_pin_error_is_classified_without_the_trezor_feature() {
        let error = bhwi::trezor::TrezorError::NonNumericPin;
        let classified = classify_error(&error);
        assert_eq!(classified.message, error.to_string());
        assert!(matches!(classified.kind, DeviceErrorKind::InvalidInput));
    }

    #[test]
    fn a_transport_error_keeps_the_layer_that_carries_its_meaning() {
        let wrapped: crate::Error<std::io::Error, std::io::Error> =
            crate::Error::Transport(std::io::Error::other("Broken pipe"));

        let skipped = SkippedDevice::new(DeviceType::KeepKey, "keepkey", "udp:11044", &wrapped);
        assert_eq!(skipped.error, "transport error: Broken pipe");
        assert!(matches!(skipped.kind, DeviceErrorKind::Unclassified));
    }

    #[test]
    fn multisig_display_address_needs_a_descriptor_capable_device() {
        for device_type in DeviceType::ALL {
            assert_eq!(
                supports_multisig_display_address(device_type),
                matches!(
                    device_type,
                    DeviceType::Coldcard
                        | DeviceType::Jade
                        | DeviceType::KeepKey
                        | DeviceType::Trezor
                ),
                "{device_type}"
            );
        }
    }
}
