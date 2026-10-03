use bhwi::{
    bitcoin::{
        Network,
        bip32::{self, ChildNumber, DerivationPath, Fingerprint},
    },
    miniscript::{
        self, Descriptor, DescriptorPublicKey,
        descriptor::{DescriptorType, DescriptorXKey, Wildcard, Wpkh},
    },
};

use crate::{HWIDevice, HWIDeviceError};

/// A device-query, derivation, or descriptor-construction failure.
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    /// A wallet query failed.
    #[error("{0}")]
    Device(
        /// The wallet-operation error.
        #[from]
        HWIDeviceError,
    ),

    /// A BIP32 derivation index is invalid.
    #[error("{0}")]
    Bip32(
        /// The derivation error.
        #[from]
        bip32::Error,
    ),

    /// A descriptor could not be constructed.
    #[error("{0}")]
    Miniscript(
        /// The descriptor-construction error.
        #[from]
        miniscript::Error,
    ),

    /// The requested descriptor type is unsupported.
    #[error("Unsupported descriptor type {0:?}")]
    UnsupportedDescriptorType(
        /// The unsupported script type.
        DescriptorType,
    ),

    /// A bare public-key descriptor has no supported account purpose.
    #[error("Bare PK descriptors aren't supported")]
    BarePk,

    /// The keypool's first index exceeds its last index.
    #[error("keypool start index must be less than or equal to end index")]
    KeypoolRange,

    /// A hardened child follows an unhardened child in a keypool path.
    #[error("keypool path cannot contain hardened children after an unhardened child")]
    HardenedAfterUnhardened,
}

/// Parameters for deriving a single-key wildcard descriptor.
#[derive(Debug, Clone)]
pub struct GetDescriptorOptions {
    /// The device's master fingerprint to include in the key origin.
    pub master_fingerprint: Fingerprint,
    /// The path or account used to derive the descriptor key.
    pub target: DescriptorTarget,
    /// Whether account-based derivation selects the change branch.
    pub is_change: bool,
    /// The requested script type.
    pub descriptor_type: DescriptorType,
    /// The network used for account derivation: Bitcoin uses coin type 0, others 1.
    pub network: Network,
}

/// The path or account used to derive a descriptor key.
#[derive(Debug, Clone)]
pub enum DescriptorTarget {
    /// An explicit derivation path preceding the wildcard.
    Path(
        /// The requested derivation path.
        DerivationPath,
    ),
    /// An account index for script-specific BIP44-style derivation.
    Account(
        /// The unhardened account index, hardened during derivation.
        u32,
    ),
}

/// Parameters for a wildcard descriptor and an inclusive keypool range.
#[derive(Debug, Clone)]
pub struct GetKeypoolOptions {
    /// The account or parent path to which the receive/change branch is appended.
    pub path: DerivationPath,
    /// The first child index in the inclusive range.
    pub start: u32,
    /// The last child index in the inclusive range.
    pub end: u32,
    /// Whether to append the change branch (1) rather than the receive branch (0).
    pub internal: bool,
    /// The requested script type.
    pub descriptor_type: DescriptorType,
    /// The network used for descriptor construction.
    pub network: Network,
}

impl GetDescriptorOptions {
    /// Creates options using an explicit path preceding the descriptor wildcard.
    pub fn with_path(
        master_fingerprint: Fingerprint,
        path: DerivationPath,
        is_change: bool,
        descriptor_type: DescriptorType,
        network: Network,
    ) -> Self {
        Self {
            master_fingerprint,
            target: DescriptorTarget::Path(path),
            is_change,
            descriptor_type,
            network,
        }
    }

    /// Creates options using a script-specific account and receive/change branch.
    pub fn with_account(
        master_fingerprint: Fingerprint,
        account: u32,
        is_change: bool,
        descriptor_type: DescriptorType,
        network: Network,
    ) -> Self {
        Self {
            master_fingerprint,
            target: DescriptorTarget::Account(account),
            is_change,
            descriptor_type,
            network,
        }
    }
}

impl GetKeypoolOptions {
    fn descriptor_options(
        &self,
        master_fingerprint: Fingerprint,
    ) -> Result<GetDescriptorOptions, DescriptorError> {
        validate_keypool_range(self.start, self.end)?;
        let path = keypool_descriptor_path(&self.path, self.internal)?;
        Ok(GetDescriptorOptions::with_path(
            master_fingerprint,
            path,
            self.internal,
            self.descriptor_type,
            self.network,
        ))
    }
}

/// Queries a device key and constructs a single-key wildcard descriptor.
///
/// Supports P2PKH, P2WPKH, P2SH-P2WPKH, and key-path Taproot. Account targets
/// choose the corresponding purpose and use coin type 0 for Bitcoin, 1 otherwise.
/// This does not check whether the device can sign the requested script type.
// reference: https://github.com/bitcoin-core/HWI/blob/master/hwilib/commands.py#L274
pub async fn get_descriptor(
    device: &mut dyn HWIDevice,
    options: GetDescriptorOptions,
) -> Result<Descriptor<DescriptorPublicKey>, DescriptorError> {
    let GetDescriptorOptions {
        master_fingerprint,
        target,
        is_change,
        descriptor_type,
        network,
    } = options;
    let path = match target {
        DescriptorTarget::Path(path) => path,
        DescriptorTarget::Account(account) => {
            let purpose = ChildNumber::from_hardened_idx(bip44_purpose(descriptor_type)?)?;
            let chain = ChildNumber::from_hardened_idx(bip44_chain(network))?;
            let account = ChildNumber::from_hardened_idx(account)?;
            let change = ChildNumber::from_normal_idx(is_change.into())?;

            [purpose, chain, account, change].as_ref().into()
        }
    };

    let split = path
        .into_iter()
        .rposition(ChildNumber::is_hardened)
        .map(|i| i + 1)
        .unwrap_or(0);
    let (origin, suffix) = (&path[..split], &path[split..]);

    let xpub = device.get_extended_pubkey(origin.into(), false).await?;
    let pk = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((master_fingerprint, origin.into())),
        xkey: xpub,
        derivation_path: suffix.into(),
        wildcard: Wildcard::Unhardened,
    });
    Ok(match descriptor_type {
        DescriptorType::Pkh => Descriptor::new_pkh(pk)?,
        DescriptorType::Wpkh => Descriptor::new_wpkh(pk)?,
        DescriptorType::ShWpkh => {
            Descriptor::new_sh_with_wpkh(Wpkh::new(pk).map_err(miniscript::Error::from)?)
        }
        // TODO: check if device supports Taproot
        DescriptorType::Tr => Descriptor::new_tr(pk, None)?,
        _ => return Err(DescriptorError::UnsupportedDescriptorType(descriptor_type)),
    })
}

/// The single-key script types included in the standard receive/change descriptor set.
pub const PUBKEY_DESCRIPTOR_TYPES: [DescriptorType; 4] = [
    DescriptorType::Pkh,
    DescriptorType::Wpkh,
    DescriptorType::ShWpkh,
    DescriptorType::Tr,
];

/// Receive and internal descriptors for every type in [`PUBKEY_DESCRIPTOR_TYPES`].
#[derive(Debug, Clone)]
pub struct PubkeyDescriptors {
    /// Wildcard receive descriptors in [`PUBKEY_DESCRIPTOR_TYPES`] order.
    pub receive: Vec<Descriptor<DescriptorPublicKey>>,
    /// Wildcard change descriptors in [`PUBKEY_DESCRIPTOR_TYPES`] order.
    pub internal: Vec<Descriptor<DescriptorPublicKey>>,
}

/// Derives the descriptor set a standard wallet needs for one account.
pub async fn get_pubkey_descriptors(
    device: &mut dyn HWIDevice,
    master_fingerprint: Fingerprint,
    account: u32,
    network: Network,
) -> Result<PubkeyDescriptors, DescriptorError> {
    let mut descriptors = PubkeyDescriptors {
        receive: Vec::with_capacity(PUBKEY_DESCRIPTOR_TYPES.len()),
        internal: Vec::with_capacity(PUBKEY_DESCRIPTOR_TYPES.len()),
    };
    for descriptor_type in PUBKEY_DESCRIPTOR_TYPES {
        for (is_change, out) in [
            (false, &mut descriptors.receive),
            (true, &mut descriptors.internal),
        ] {
            let options = GetDescriptorOptions::with_account(
                master_fingerprint,
                account,
                is_change,
                descriptor_type,
                network,
            );
            out.push(get_descriptor(device, options).await?);
        }
    }
    Ok(descriptors)
}

/// Queries a wildcard keypool descriptor from an account or parent path.
///
/// `start` and `end` are inclusive bounds validated for ordering only. They do
/// not replace the returned descriptor's wildcard or constrain its derivation range.
pub async fn get_keypool_descriptor(
    device: &mut dyn HWIDevice,
    master_fingerprint: Fingerprint,
    options: &GetKeypoolOptions,
) -> Result<Descriptor<DescriptorPublicKey>, DescriptorError> {
    let descriptor_options = options.descriptor_options(master_fingerprint)?;
    get_descriptor(device, descriptor_options).await
}

fn validate_keypool_range(start: u32, end: u32) -> Result<(), DescriptorError> {
    if start > end {
        return Err(DescriptorError::KeypoolRange);
    }
    Ok(())
}

fn keypool_descriptor_path(
    path: &DerivationPath,
    internal: bool,
) -> Result<DerivationPath, DescriptorError> {
    if has_hardened_child_after_unhardened(path) {
        return Err(DescriptorError::HardenedAfterUnhardened);
    }

    let branch = ChildNumber::from_normal_idx(internal.into())?;
    let mut children = path.as_ref().to_vec();
    children.push(branch);
    Ok(children.into())
}

fn has_hardened_child_after_unhardened(path: &DerivationPath) -> bool {
    let mut seen_unhardened = false;
    path.as_ref().iter().any(|child| {
        seen_unhardened |= !child.is_hardened();
        seen_unhardened && child.is_hardened()
    })
}

fn bip44_purpose(desc_type: DescriptorType) -> Result<u32, DescriptorError> {
    Ok(match desc_type {
        DescriptorType::Sh | DescriptorType::Pkh => 44,
        DescriptorType::Wpkh | DescriptorType::Wsh => 84,
        DescriptorType::ShWsh | DescriptorType::ShWpkh => 49,
        DescriptorType::Tr => 86,
        DescriptorType::Bare => return Err(DescriptorError::BarePk),
    })
}

fn bip44_chain(network: Network) -> u32 {
    if let Network::Bitcoin = network { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bhwi::bitcoin::bip32::DerivationPath;

    use super::{keypool_descriptor_path, validate_keypool_range};

    #[test]
    fn device_errors_are_not_double_prefixed() {
        use crate::{HWIDeviceError, descriptors::DescriptorError};

        let inner = HWIDeviceError::new(std::io::Error::other("boom"));

        assert_eq!(DescriptorError::Device(inner).to_string(), "boom");
    }

    #[test]
    fn derivation_errors_are_not_prefixed() {
        use bhwi::bitcoin::bip32::ChildNumber;

        use crate::descriptors::DescriptorError;

        let inner = ChildNumber::from_hardened_idx(4_000_000_000).unwrap_err();
        let expected = inner.to_string();

        assert_eq!(DescriptorError::Bip32(inner).to_string(), expected);
    }

    #[test]
    fn keypool_path_appends_receive_branch() {
        let path = DerivationPath::from_str("m/84'/0'/0'").unwrap();

        let path = keypool_descriptor_path(&path, false).unwrap();

        assert_eq!(path.to_string(), "84'/0'/0'/0");
    }

    #[test]
    fn keypool_path_appends_internal_branch() {
        let path = DerivationPath::from_str("m/84'/0'/0'").unwrap();

        let path = keypool_descriptor_path(&path, true).unwrap();

        assert_eq!(path.to_string(), "84'/0'/0'/1");
    }

    #[test]
    fn keypool_range_rejects_start_after_end() {
        let err = validate_keypool_range(10, 9).unwrap_err();

        assert!(err.to_string().contains("start index"));
    }

    #[test]
    fn keypool_path_rejects_hardened_children_after_unhardened() {
        let path = DerivationPath::from_str("m/84'/0'/0'/0/1'").unwrap();

        let err = keypool_descriptor_path(&path, false).unwrap_err();

        assert!(err.to_string().contains("hardened children"));
    }
}
