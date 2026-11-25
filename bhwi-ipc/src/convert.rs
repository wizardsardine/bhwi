use std::str::FromStr;

use bhwi_async::Info as DeviceInfo;
use bhwi_async::device::{
    Device as HwiDevice, DeviceSelector, DeviceType as HwiDeviceType, NetworkMismatch,
    SkippedDevice, can_sign_taproot,
};
use bitcoin::{
    Network as BitcoinNetwork,
    address::AddressType,
    bip32::{DerivationPath, Fingerprint},
};
use miniscript::descriptor::DescriptorType;

use crate::bhwi_capnp::{
    AddressFormat, DeviceType, Network, device_info, device_type_filter, info, network_mismatch,
    optional_bool, selector, skipped_device,
};
use crate::error::{self, Failure};

/// Converts a wire network to a Bitcoin network.
pub fn network(wire: Network) -> BitcoinNetwork {
    match wire {
        Network::Bitcoin => BitcoinNetwork::Bitcoin,
        Network::Testnet => BitcoinNetwork::Testnet,
        Network::Testnet4 => BitcoinNetwork::Testnet4,
        Network::Signet => BitcoinNetwork::Signet,
        Network::Regtest => BitcoinNetwork::Regtest,
    }
}

/// Converts a Bitcoin network to its wire value.
pub fn wire_network(network: BitcoinNetwork) -> Network {
    match network {
        BitcoinNetwork::Bitcoin => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Testnet4 => Network::Testnet4,
        BitcoinNetwork::Signet => Network::Signet,
        BitcoinNetwork::Regtest => Network::Regtest,
    }
}

/// Converts a wire device type to a bhwi device type.
pub fn device_type(wire: DeviceType) -> HwiDeviceType {
    match wire {
        DeviceType::Bitbox02 => HwiDeviceType::BitBox02,
        DeviceType::Coldcard => HwiDeviceType::Coldcard,
        DeviceType::Jade => HwiDeviceType::Jade,
        DeviceType::Keepkey => HwiDeviceType::KeepKey,
        DeviceType::Ledger => HwiDeviceType::Ledger,
        DeviceType::Trezor => HwiDeviceType::Trezor,
        DeviceType::Specter => HwiDeviceType::Specter,
    }
}

/// Converts a bhwi device type to its wire value.
pub fn wire_device_type(device_type: HwiDeviceType) -> DeviceType {
    match device_type {
        HwiDeviceType::BitBox02 => DeviceType::Bitbox02,
        HwiDeviceType::Coldcard => DeviceType::Coldcard,
        HwiDeviceType::Jade => DeviceType::Jade,
        HwiDeviceType::KeepKey => DeviceType::Keepkey,
        HwiDeviceType::Ledger => DeviceType::Ledger,
        HwiDeviceType::Trezor => DeviceType::Trezor,
        HwiDeviceType::Specter => DeviceType::Specter,
    }
}

/// Converts a wire address format; `unspecified` leaves the choice to the device.
pub fn address_format(wire: AddressFormat) -> Option<AddressType> {
    match wire {
        AddressFormat::Unspecified => None,
        AddressFormat::P2pkh => Some(AddressType::P2pkh),
        AddressFormat::P2sh => Some(AddressType::P2sh),
        AddressFormat::P2wpkh => Some(AddressType::P2wpkh),
        AddressFormat::P2wsh => Some(AddressType::P2wsh),
        AddressFormat::P2tr => Some(AddressType::P2tr),
    }
}

/// The keypool descriptor is built from a script type, so an unset or
/// script-hash-only format has no answer.
pub fn descriptor_type(wire: AddressFormat) -> Result<DescriptorType, Failure> {
    match wire {
        AddressFormat::P2pkh => Ok(DescriptorType::Pkh),
        AddressFormat::P2sh => Ok(DescriptorType::ShWpkh),
        AddressFormat::P2wpkh => Ok(DescriptorType::Wpkh),
        AddressFormat::P2tr => Ok(DescriptorType::Tr),
        other => Err(error::bad_argument(format!(
            "{other:?} is not a keypool address format"
        ))),
    }
}

/// Parses a derivation path; an unreadable one is `badArgument`.
pub fn derivation_path(path: &str) -> Result<DerivationPath, Failure> {
    DerivationPath::from_str(path).map_err(error::bad_argument)
}

/// Reads a wallet-policy HMAC, which must be 32 bytes.
pub fn hmac(bytes: &[u8]) -> Result<[u8; 32], Failure> {
    bytes
        .try_into()
        .map_err(|_| error::bad_argument(format!("hmac must be 32 bytes, got {}", bytes.len())))
}

/// Raw, because `HostPassphrase` exists only in builds with Trezor or KeepKey.
pub enum PassphraseSource {
    /// No host passphrase.
    None,
    /// A passphrase given in the selector.
    Value(String),
    /// Ask the client's `Prompter` before enumerating.
    AskPrompter,
}

/// Reads how the selector supplies the passphrase.
pub fn passphrase_source(reader: selector::Reader<'_>) -> Result<PassphraseSource, Failure> {
    use crate::bhwi_capnp::selector::passphrase::Which;
    Ok(match reader.get_passphrase().which()? {
        Which::None(()) => PassphraseSource::None,
        Which::Value(value) => PassphraseSource::Value(value?.to_string()?),
        Which::AskPrompter(()) => PassphraseSource::AskPrompter,
    })
}

/// Converts a wire selector to a device selector.
pub fn selector(reader: selector::Reader<'_>) -> Result<DeviceSelector, Failure> {
    let fingerprint = reader.get_fingerprint()?.to_str()?;
    let fingerprint = if fingerprint.is_empty() {
        None
    } else {
        Some(Fingerprint::from_str(fingerprint).map_err(error::bad_argument)?)
    };
    let device_path = reader.get_device_path()?.to_str()?;
    let device_type = match reader.get_device_type()?.which()? {
        device_type_filter::Which::Any(()) => None,
        device_type_filter::Which::Only(only) => Some(device_type(only?)),
    };
    Ok(DeviceSelector {
        network: network(reader.get_network()?),
        fingerprint,
        device_type,
        device_path: (!device_path.is_empty()).then(|| device_path.to_owned()),
        include_emulators: reader.get_include_emulators(),
        ..DeviceSelector::default()
    })
}

fn set_optional_bool(mut builder: optional_bool::Builder<'_>, value: Option<bool>) {
    match value {
        Some(value) => builder.set_value(value),
        None => builder.set_unknown(()),
    }
}

/// Writes device information to the wire.
pub fn fill_info(source: &DeviceInfo, mut builder: info::Builder<'_>) -> Result<(), capnp::Error> {
    builder.set_version(&source.version);
    builder.set_firmware(source.firmware.as_deref().unwrap_or_default());
    builder.set_label(source.label.as_deref().unwrap_or_default());
    {
        let mut networks = builder
            .reborrow()
            .init_networks(source.networks.len() as u32);
        for (index, value) in source.networks.iter().enumerate() {
            networks.set(index as u32, wire_network(*value));
        }
    }
    set_optional_bool(builder.reborrow().init_initialized(), source.initialized);
    set_optional_bool(
        builder.reborrow().init_on_device_passphrase_entry(),
        source.on_device_passphrase_entry,
    );
    set_optional_bool(
        builder.reborrow().init_needs_pin_sent(),
        source.needs_pin_sent,
    );
    set_optional_bool(
        builder.reborrow().init_needs_passphrase_sent(),
        source.needs_passphrase_sent,
    );
    Ok(())
}

/// Writes a skipped device to the wire with its error code and message.
pub fn fill_skipped(source: &SkippedDevice, mut builder: skipped_device::Builder<'_>) {
    builder.set_device_type(wire_device_type(source.device_type));
    builder.set_model(&source.model);
    builder.set_path(&source.path);
    builder.set_error(source.error.message());
    builder.set_code(error::kind_code(source.error.kind()));
}

/// Writes a network mismatch to the wire; `None` leaves it unset.
pub fn fill_network_mismatch(
    source: Option<&NetworkMismatch>,
    mut builder: network_mismatch::Builder<'_>,
) {
    let Some(source) = source else {
        return;
    };
    builder.set_expected(wire_network(source.expected));
    let mut reported = builder.init_reported(source.reported.len() as u32);
    for (index, network) in source.reported.iter().enumerate() {
        reported.set(index as u32, wire_network(*network));
    }
}

/// Writes an opened device and any network mismatch to the wire.
pub fn fill_device(
    device: &HwiDevice,
    mismatch: Option<&NetworkMismatch>,
    mut builder: device_info::Builder<'_>,
) -> Result<(), capnp::Error> {
    fill_network_mismatch(mismatch, builder.reborrow().init_network_mismatch());
    builder.set_name(device.name());
    builder.set_device_type(wire_device_type(device.device_type()));
    builder.set_path(device.path());
    builder.set_model(device.model());
    builder.set_is_emulated(device.is_emulated());
    builder.set_fingerprint(
        device
            .cached_fingerprint()
            .map(|fingerprint| fingerprint.to_string())
            .unwrap_or_default(),
    );
    builder.set_can_sign_taproot(can_sign_taproot(device.device_type(), device.model()));
    if let Some(info) = device.cached_info() {
        fill_info(info, builder.reborrow().init_info())?;
    }
    Ok(())
}
