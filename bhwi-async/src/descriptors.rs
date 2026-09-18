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

#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("{0}")]
    Device(#[from] HWIDeviceError),

    #[error("{0}")]
    Bip32(#[from] bip32::Error),

    #[error("{0}")]
    Miniscript(#[from] miniscript::Error),

    #[error("Unsupported descriptor type {0:?}")]
    UnsupportedDescriptorType(DescriptorType),

    #[error("Bare PK descriptors aren't supported")]
    BarePk,

    #[error("keypool start index must be less than or equal to end index")]
    KeypoolRange,

    #[error("keypool path cannot contain hardened children after an unhardened child")]
    HardenedAfterUnhardened,
}

#[derive(Debug, Clone)]
pub struct GetDescriptorOptions {
    /// The device's master fingerprint to use in the descriptor
    pub master_fingerprint: Fingerprint,
    /// The method used to derive the keys for the descriptor
    pub target: DescriptorTarget,
    /// Is this descriptor used for a change address?
    pub is_change: bool,
    /// The address type to use for the descriptor
    pub descriptor_type: DescriptorType,
    /// The Bitcoin network to use in descriptor paths
    pub network: Network,
}

#[derive(Debug, Clone)]
/// The method used to derive the keys for the descriptor
pub enum DescriptorTarget {
    /// Derivation path to derive keys
    Path(DerivationPath),
    /// BIP-44 account index
    Account(u32),
}

#[derive(Debug, Clone)]
pub struct GetKeypoolOptions {
    /// BIP account or parent path to derive the keypool branch from
    pub path: DerivationPath,
    /// First child index included in this keypool range
    pub start: u32,
    /// Last child index included in this keypool range
    pub end: u32,
    /// Whether this keypool is for change/internal addresses
    pub internal: bool,
    /// The address type to use for the descriptor
    pub descriptor_type: DescriptorType,
    /// The Bitcoin network to use in descriptor paths
    pub network: Network,
}

impl GetDescriptorOptions {
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

/// Gets a descriptor with the given parameters
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

/// The descriptor types a standard wallet is made of, receive and change.
pub const PUBKEY_DESCRIPTOR_TYPES: [DescriptorType; 4] = [
    DescriptorType::Pkh,
    DescriptorType::Wpkh,
    DescriptorType::ShWpkh,
    DescriptorType::Tr,
];

/// Receive and internal descriptors for every type in [`PUBKEY_DESCRIPTOR_TYPES`].
#[derive(Debug, Clone)]
pub struct PubkeyDescriptors {
    pub receive: Vec<Descriptor<DescriptorPublicKey>>,
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

/// Gets a ranged keypool descriptor from an account/parent path.
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
