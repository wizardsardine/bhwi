use anyhow::Result;
#[cfg(feature = "ledger")]
use bhwi::ledger::{LedgerWalletPolicy, Version};
#[cfg(any(feature = "trezor", feature = "keepkey"))]
use bhwi::passphrase::HostPassphrase;
use bhwi_async::{DeviceBackup, DeviceContext, RestoreOptions, SetupOptions, WalletRegistration};
#[cfg(feature = "bitbox")]
use bhwi_cli::management::{bitbox_restore_context, bitbox_setup_context};
#[cfg(feature = "keepkey")]
use bhwi_cli::management::{keepkey_pin_context, keepkey_restore_context, keepkey_setup_context};
#[cfg(feature = "trezor")]
use bhwi_cli::management::{trezor_pin_context, trezor_restore_context, trezor_setup_context};
use bhwi_cli::udev::{UdevRuleSelection, install_udev_rules};
use bhwi_cli::{
    DeviceJson, DeviceManager, DeviceSelector, DeviceType, DeviceTypeArg, OutputFormat,
    SkippedDevice,
    address::AddressTarget,
    device_manager,
    get_descriptors::GetKeypoolOptions,
    hwi::{PIN_MATRIX_DESCRIPTION, SEND_PIN_INSTRUCTION},
    networks_string, select_device, warn_skipped,
};
use bhwi_cli::{address::AddressOutput, get_descriptors::DescriptorOutput};

use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::base64::prelude::{BASE64_STANDARD, Engine as _};
use bitcoin::{
    Network,
    address::AddressType,
    bip32::{DerivationPath, Fingerprint},
    psbt::Psbt,
};
use clap::{Parser, Subcommand, ValueEnum};
use miniscript::descriptor::{DescriptorType, WalletPolicy};

#[derive(Parser, Debug)]
#[command(author, version, about = "Bitcoin hardware wallet commands", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    /// Select a device by master fingerprint (default: first available device)
    #[arg(long, alias = "fg", global = true, value_parser = clap::value_parser!(bitcoin::bip32::Fingerprint))]
    fingerprint: Option<Fingerprint>,
    /// select a device implementation by type
    #[arg(long, value_enum, global = true)]
    device_type: Option<DeviceTypeArg>,
    /// select a device by transport path
    #[arg(long, global = true)]
    device_path: Option<String>,
    /// Bitcoin network
    #[arg(long, short, global = true, value_parser = clap::value_parser!(bitcoin::Network), default_value_t = bitcoin::Network::Bitcoin)]
    network: Network,
    /// Output format where supported (default: plain)
    #[arg(long, short, global = true)]
    format: Option<OutputFormat>,
    /// passphrase for devices that take one from the host
    #[arg(long, short, global = true)]
    passphrase: Option<String>,
}

impl Args {
    fn device_selector(&self) -> DeviceSelector {
        // Whether `passphrase` exists follows bhwi-async's features, which another
        // crate in the build can widen past this one's.
        let selector = DeviceSelector {
            network: self.network,
            fingerprint: self.fingerprint,
            device_type: self.device_type.map(DeviceType::from),
            device_path: self.device_path.clone(),
            include_emulators: true,
            ..DeviceSelector::default()
        };
        #[cfg(any(feature = "trezor", feature = "keepkey"))]
        let selector = DeviceSelector {
            passphrase: self.passphrase.clone().map(HostPassphrase::new),
            ..selector
        };
        selector
    }

    fn manager(&self) -> DeviceManager {
        device_manager(self.device_selector(), self.passphrase.is_some())
    }
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    /// Get and display device addresses
    #[command(subcommand)]
    Address(AddressCommands),
    /// Get descriptors and register wallet policies
    #[command(subcommand)]
    Descriptor(DescriptorCommands),
    /// List and manage hardware wallets
    #[command(subcommand)]
    Device(DeviceCommands),
    /// Get extended public keys
    #[command(subcommand)]
    Xpub(XpubCommands),
    /// Work with partially signed Bitcoin transactions
    #[command(subcommand)]
    Psbt(PsbtCommands),
    /// Work with Bitcoin signed messages
    #[command(subcommand)]
    Message(MessageCommands),
}

#[derive(Debug, Clone, Subcommand)]
enum PsbtCommands {
    /// Sign a PSBT with the selected device
    Sign {
        /// PSBT file in base64 text format
        #[arg(long)]
        psbt: PathBuf,
        /// Wallet name
        #[arg(long, alias = "wallet-name")]
        name: Option<String>,
        /// Miniscript wallet policy descriptor
        #[arg(long, value_parser = clap::value_parser!(WalletPolicy))]
        descriptor: Option<WalletPolicy>,
        /// HMAC from wallet registration (hex-encoded 64 chars)
        #[arg(long)]
        hmac: Option<String>,
        /// Output file for the signed base64 PSBT (default: stdout; --format does not change PSBT output)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum MessageCommands {
    /// Sign a message with the selected device
    Sign {
        /// Message to sign
        #[arg(long)]
        message: String,
        /// BIP32 derivation path (e.g. m/44'/0'/0'/0/0)
        #[arg(long, value_parser = clap::value_parser!(DerivationPath))]
        path: DerivationPath,
        /// Output file for the signature in the selected format (default: stdout)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum AddressCommands {
    /// Get an address from the device
    Get {
        /// Derivation path (e.g. m/84'/0'/0'/0/0)
        #[arg(long, conflicts_with = "from_descriptor")]
        from_path: Option<String>,
        /// Miniscript descriptor name registered on device
        #[arg(long, conflicts_with = "from_path")]
        from_descriptor: Option<String>,
        /// Address index for descriptor-based retrieval (default: 0)
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Change address for descriptor-based retrieval
        #[arg(long, default_value_t = false)]
        change: bool,
        /// Display the address on the device screen
        #[arg(long, default_value_t = false)]
        display: bool,
        /// Address format for path-based retrieval (p2pkh, p2sh, p2wpkh, p2wsh, p2tr)
        #[arg(long, value_parser = clap::value_parser!(AddressType))]
        address_format: Option<AddressType>,
        /// HMAC from wallet registration (hex-encoded 64 chars), required for
        /// Ledger descriptor-based addresses.
        #[arg(long)]
        hmac: Option<String>,
        /// Miniscript wallet policy matching the selected wallet, required for
        /// Ledger and Specter-DIY descriptor-based addresses.
        #[arg(long, value_parser = clap::value_parser!(WalletPolicy))]
        wallet_descriptor: Option<WalletPolicy>,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum DeviceCommands {
    /// List all available devices
    #[command(alias = "enumerate")]
    List,
    /// Start a backup on the selected device
    Backup {
        /// Output file for devices that export encrypted backup bytes
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Initialize an unseeded device
    Setup {
        /// User-visible device name
        #[arg(long, short, default_value = "")]
        label: String,
    },
    /// Erase wallet material from the selected device
    Wipe,
    /// Restore an unseeded device using its on-device mnemonic flow
    Restore {
        /// User-visible device name
        #[arg(long, short, default_value = "")]
        label: String,
        /// Number of words in the recovery phrase
        #[arg(long, short, default_value_t = 24)]
        word_count: i32,
    },
    /// Toggle mnemonic-passphrase use on the selected device
    TogglePassphrase,
    /// Ask the selected device to show its PIN keypad
    PromptPin,
    /// Send the keypad positions shown on the device screen
    SendPin {
        /// Positions on the device's scrambled keypad, not the PIN digits themselves
        positions: String,
    },
    /// Install udev rules for hardware wallet device access
    InstallUdevRules {
        /// Device rule targets to install
        #[arg(value_enum)]
        targets: Vec<DeviceTypeArg>,
        /// Install rules for all BHWI-supported devices
        #[arg(long)]
        all: bool,
        /// Directory where udev rule files are copied
        #[arg(long, default_value = "/etc/udev/rules.d/")]
        location: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum KeypoolAddressFormat {
    P2pkh,
    P2sh,
    P2wpkh,
    P2tr,
}

impl From<KeypoolAddressFormat> for DescriptorType {
    fn from(format: KeypoolAddressFormat) -> Self {
        match format {
            KeypoolAddressFormat::P2pkh => DescriptorType::Pkh,
            KeypoolAddressFormat::P2sh => DescriptorType::ShWpkh,
            KeypoolAddressFormat::P2wpkh => DescriptorType::Wpkh,
            KeypoolAddressFormat::P2tr => DescriptorType::Tr,
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
enum XpubCommands {
    /// Get an extended public key at a derivation path
    Get {
        #[arg(value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        path: DerivationPath,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum DescriptorCommands {
    /// Get pubkey descriptors from device
    #[command()]
    Pubkeys {
        #[arg(long, short)]
        account: Option<u32>,
    },
    /// Get a ranged keypool descriptor from the selected device
    Keypool {
        /// BIP account or parent derivation path (e.g. m/84'/0'/0')
        #[arg(long, value_parser = clap::value_parser!(DerivationPath))]
        path: DerivationPath,
        /// First child index included in this keypool range
        #[arg(long)]
        start: u32,
        /// Last child index included in this keypool range
        #[arg(long)]
        end: u32,
        /// Address format for the descriptor (p2pkh, p2sh, p2wpkh, p2tr)
        #[arg(long, value_enum, default_value_t = KeypoolAddressFormat::P2wpkh)]
        address_format: KeypoolAddressFormat,
        /// Use the internal/change branch
        #[arg(long, default_value_t = false)]
        internal: bool,
    },
    /// Register a named wallet policy with the selected device
    Register {
        /// Name of the wallet
        #[arg(long)]
        name: String,
        /// Miniscript wallet policy descriptor
        #[arg(long)]
        descriptor: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let command = args.command.to_owned();
    let format = args.format;
    let dev_man = args.manager();
    match command {
        Commands::Address(AddressCommands::Get {
            from_path,
            from_descriptor,
            index,
            change,
            display,
            address_format,
            hmac,
            wallet_descriptor,
        }) => match (from_path, from_descriptor) {
            (Some(path), None) => {
                let target = AddressTarget::Path {
                    path,
                    display,
                    address_format,
                };
                dev_man.get_address(target).await?
            }
            (None, Some(descriptor_name)) => {
                let target = AddressTarget::Descriptor {
                    index,
                    change,
                    display,
                    descriptor_name,
                    hmac,
                    wallet_descriptor,
                };
                dev_man.get_address(target).await?
            }
            _ => anyhow::bail!("either --from-path or --from-descriptor must be specified"),
        },
        Commands::Descriptor(DescriptorCommands::Pubkeys { account }) => {
            dev_man.get_pubkey_descriptors(account, format).await?
        }
        Commands::Descriptor(DescriptorCommands::Keypool {
            path,
            start,
            end,
            address_format,
            internal,
        }) => {
            let options = GetKeypoolOptions {
                path,
                start,
                end,
                internal,
                descriptor_type: address_format.into(),
                network: dev_man.selector.network,
            };
            dev_man.get_keypool(options, format).await?;
        }
        Commands::Device(DeviceCommands::List) => {
            let mut scan = dev_man.enumerate().await?;
            for skipped in &scan.skipped {
                warn_skipped(skipped);
            }
            let mut listed = 0usize;
            let mut json_devices: Vec<DeviceJson> = Vec::new();
            for device in scan.devices.iter_mut() {
                // XXX: Coldcard always needs unlocking
                if let Err(err) = device.device().unlock(dev_man.selector.network).await {
                    warn_skipped(&SkippedDevice::new(
                        device.device_type(),
                        device.model(),
                        device.path(),
                        &err,
                    ));
                    continue;
                }
                let name = device.name().to_string();
                let is_emulated = device.is_emulated();
                let info = device.info().await?;
                let fingerprint = if info.initialized == Some(false) {
                    None
                } else {
                    Some(device.fingerprint().await?)
                };
                listed += 1;
                match format {
                    Some(OutputFormat::Pretty) => {
                        if listed == 1 {
                            println!(
                                "{:<18} | {:<8} | {:<15} | {:<12} | {:<8}",
                                "Name", "Emulated", "Fingerprint", "Network", "Version"
                            );
                        }
                        println!("{}", "-".repeat(80));
                        let network = networks_string(&info.networks);
                        let fingerprint = fingerprint
                            .map(|fingerprint| fingerprint.to_string())
                            .unwrap_or_else(|| "-".to_owned());
                        println!(
                            "{name:<18} | {is_emulated:<8} | {fingerprint:<15} | {network:<12} | {:<8}",
                            info.version
                        );
                        println!("{}", "-".repeat(80));
                    }
                    Some(OutputFormat::Json) => json_devices.push(DeviceJson::from(&*device)),
                    None => match fingerprint {
                        Some(fingerprint) => println!("{fingerprint}"),
                        None => println!("{}", device.path()),
                    },
                }
            }
            if let Some(OutputFormat::Json) = format {
                println!("{}", serde_json::json![json_devices])
            }
        }
        Commands::Device(DeviceCommands::Backup { output }) => {
            if let Some(mut d) = select_device(&dev_man).await? {
                let backup = d.device().backup_device().await?;
                match backup {
                    DeviceBackup::File(bytes) => {
                        let output = output.ok_or_else(|| {
                            anyhow::anyhow!(
                                "--output is required for devices that export backup files"
                            )
                        })?;
                        std::fs::write(&output, &bytes)?;
                        if let Some(OutputFormat::Json) = format {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "output": output,
                                    "bytes": bytes.len(),
                                })
                            );
                        }
                    }
                    DeviceBackup::Complete => {
                        if let Some(OutputFormat::Json) = format {
                            println!("{}", serde_json::json!({ "success": true }));
                        }
                    }
                }
            }
        }
        Commands::Device(DeviceCommands::Setup { label }) => {
            if let Some(mut device) = select_device(&dev_man).await? {
                let context = match device.device_type() {
                    #[cfg(feature = "bitbox")]
                    DeviceType::BitBox02 => bitbox_setup_context(device.is_emulated())?,
                    #[cfg(feature = "trezor")]
                    DeviceType::Trezor => trezor_setup_context(),
                    #[cfg(feature = "keepkey")]
                    DeviceType::KeepKey => keepkey_setup_context(),
                    other => anyhow::bail!("device setup is not supported for {other}"),
                };
                let success = device
                    .device()
                    .setup_device(
                        SetupOptions {
                            label,
                            backup_passphrase: String::new(),
                        },
                        Some(context),
                    )
                    .await?;
                if !success {
                    anyhow::bail!("device setup was not completed");
                }
                if let Some(OutputFormat::Json) = format {
                    println!("{}", serde_json::json!({ "success": true }));
                }
            }
        }
        Commands::Device(DeviceCommands::Wipe) => {
            if let Some(mut device) = select_device(&dev_man).await? {
                if !matches!(
                    device.device_type(),
                    DeviceType::BitBox02 | DeviceType::KeepKey | DeviceType::Trezor
                ) {
                    anyhow::bail!("device wipe is not supported for {}", device.device_type());
                }
                if !device.device().wipe_device().await? {
                    anyhow::bail!("device wipe was not completed");
                }
                if let Some(OutputFormat::Json) = format {
                    println!("{}", serde_json::json!({ "success": true }));
                }
            }
        }
        Commands::Device(DeviceCommands::Restore { label, word_count }) => {
            if let Some(mut device) = select_device(&dev_man).await? {
                let context = match device.device_type() {
                    #[cfg(feature = "bitbox")]
                    DeviceType::BitBox02 => bitbox_restore_context()?,
                    #[cfg(feature = "trezor")]
                    DeviceType::Trezor => trezor_restore_context()?,
                    #[cfg(feature = "keepkey")]
                    DeviceType::KeepKey => keepkey_restore_context()?,
                    device_type => {
                        anyhow::bail!("device restore is not supported for {device_type}")
                    }
                };
                if !device
                    .device()
                    .restore_device(RestoreOptions { label, word_count }, Some(context))
                    .await?
                {
                    anyhow::bail!("device restore was not completed");
                }
                if let Some(OutputFormat::Json) = format {
                    println!("{}", serde_json::json!({ "success": true }));
                }
            }
        }
        Commands::Device(DeviceCommands::TogglePassphrase) => {
            if let Some(mut device) = select_device(&dev_man).await? {
                let needs_pin_sent = device.device_type() == DeviceType::KeepKey
                    && device.info().await?.needs_pin_sent == Some(true);
                if !matches!(
                    device.device_type(),
                    DeviceType::BitBox02 | DeviceType::KeepKey | DeviceType::Trezor
                ) {
                    anyhow::bail!(
                        "device toggle-passphrase is not supported for {}",
                        device.device_type()
                    );
                }
                if !device.device().toggle_passphrase().await? {
                    anyhow::bail!("passphrase setting was not changed");
                }
                if let Some(OutputFormat::Json) = format {
                    println!("{}", serde_json::json!({ "success": true }));
                }
                if needs_pin_sent {
                    eprintln!("{SEND_PIN_INSTRUCTION}");
                    eprintln!("{PIN_MATRIX_DESCRIPTION}");
                }
            }
        }
        Commands::Device(DeviceCommands::PromptPin) => {
            if let Some(mut device) = select_device(&dev_man).await? {
                if !matches!(
                    device.device_type(),
                    DeviceType::KeepKey | DeviceType::Trezor
                ) {
                    anyhow::bail!(
                        "device prompt-pin is not supported for {}",
                        device.device_type()
                    );
                }
                eprintln!("{SEND_PIN_INSTRUCTION}");
                eprintln!("{PIN_MATRIX_DESCRIPTION}");
                if !device.device().prompt_pin().await? {
                    anyhow::bail!("device did not ask for a PIN");
                }
                if let Some(OutputFormat::Json) = format {
                    println!("{}", serde_json::json!({ "success": true }));
                }
            }
        }
        Commands::Device(DeviceCommands::SendPin { positions }) => {
            // Nothing may be sent to a device waiting for a PIN, so this lookup stays quiet.
            if let Some(mut device) = dev_man.get_device_without_contacting().await? {
                if !matches!(
                    device.device_type(),
                    DeviceType::KeepKey | DeviceType::Trezor
                ) {
                    anyhow::bail!(
                        "device send-pin is not supported for {}",
                        device.device_type()
                    );
                }
                let context = match device.device_type() {
                    #[cfg(feature = "keepkey")]
                    DeviceType::KeepKey => keepkey_pin_context(positions)?,
                    #[cfg(feature = "trezor")]
                    DeviceType::Trezor => trezor_pin_context(positions)?,
                    #[allow(unreachable_patterns)]
                    device_type => {
                        let _ = positions;
                        anyhow::bail!("{device_type} support is not compiled into this build");
                    }
                };
                if !device.device().send_pin(Some(context)).await? {
                    anyhow::bail!("device rejected the PIN");
                }
                if let Some(OutputFormat::Json) = format {
                    println!("{}", serde_json::json!({ "success": true }));
                }
            }
        }
        Commands::Device(DeviceCommands::InstallUdevRules {
            targets,
            all,
            location,
        }) => {
            if all && !targets.is_empty() {
                anyhow::bail!("--all cannot be combined with explicit device targets");
            }
            if !all && targets.is_empty() {
                anyhow::bail!("specify at least one device target or --all");
            }

            let selection = if all {
                UdevRuleSelection::Devices(vec![
                    bhwi_cli::DeviceType::Coldcard,
                    bhwi_cli::DeviceType::Trezor,
                    bhwi_cli::DeviceType::KeepKey,
                    bhwi_cli::DeviceType::Jade,
                    bhwi_cli::DeviceType::Ledger,
                ])
            } else {
                UdevRuleSelection::Devices(targets.into_iter().map(DeviceType::from).collect())
            };
            install_udev_rules(&location, selection)?;
            if let Some(OutputFormat::Json) = format {
                println!("{}", serde_json::json!({ "success": true }));
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            if let Some(mut d) = select_device(&dev_man).await? {
                println!("{}", d.device().get_extended_pubkey(path, false).await?);
            }
        }
        Commands::Descriptor(DescriptorCommands::Register { name, descriptor }) => {
            if let Some(mut d) = select_device(&dev_man).await? {
                let registration = d.device().register_wallet(&name, &descriptor).await?;
                match format {
                    Some(OutputFormat::Json) => {
                        let (status, hmac) = match registration {
                            WalletRegistration::Complete { hmac } => {
                                ("complete", hmac.map(hex::encode))
                            }
                            WalletRegistration::PendingUserConfirmation => {
                                ("pending_user_confirmation", None)
                            }
                        };
                        println!("{}", serde_json::json!({ "status": status, "hmac": hmac }));
                    }
                    _ => match registration {
                        WalletRegistration::Complete { hmac: Some(hmac) } => {
                            println!("{}", hex::encode(hmac));
                        }
                        WalletRegistration::Complete { hmac: None } => {}
                        WalletRegistration::PendingUserConfirmation => {
                            eprintln!("Wallet registration is pending confirmation on the device.");
                        }
                    },
                }
            }
        }
        Commands::Psbt(PsbtCommands::Sign {
            psbt,
            name,
            descriptor,
            hmac,
            output,
        }) => {
            let psbt_text = std::fs::read_to_string(psbt)?;
            let psbt = Psbt::from_str(psbt_text.trim())?;
            let hmac = hmac.as_deref().map(parse_hmac).transpose()?;
            if let Some(mut d) = select_device(&dev_man).await? {
                let context = signing_context(d.device_type(), name, descriptor, hmac)?;
                let signed = d.device().sign_tx(psbt, context).await?;
                let signed = signed.to_string();
                if let Some(output) = output {
                    std::fs::write(output, signed)?;
                } else {
                    println!("{signed}");
                }
            }
        }
        Commands::Message(MessageCommands::Sign {
            message,
            path,
            output,
        }) => {
            if let Some(mut d) = select_device(&dev_man).await? {
                let (header, signature) = d.device().sign_message(message.as_bytes(), path).await?;
                let signature = message_signature_base64(header, &signature);
                let rendered = match format {
                    Some(OutputFormat::Json) => {
                        serde_json::json!({ "signature": signature }).to_string()
                    }
                    Some(OutputFormat::Pretty) | None => signature,
                };

                if let Some(output) = output {
                    std::fs::write(output, rendered)?;
                } else {
                    println!("{rendered}");
                }
            }
        }
    }
    Ok(())
}

fn signing_context(
    device_type: DeviceType,
    name: Option<String>,
    descriptor: Option<WalletPolicy>,
    hmac: Option<[u8; 32]>,
) -> Result<Option<DeviceContext>> {
    match device_type {
        #[cfg(feature = "ledger")]
        DeviceType::Ledger => match (name, descriptor, hmac) {
            (Some(name), Some(policy), hmac) => Ok(Some(DeviceContext::Ledger {
                wallet_policy: LedgerWalletPolicy::new(name, Version::V2, policy),
                wallet_hmac: hmac,
            })),
            (None, None, None) => Ok(None),
            (None, None, Some(_)) => anyhow::bail!("--hmac requires --name and --descriptor"),
            _ => anyhow::bail!("--name and --descriptor must be provided together"),
        },
        #[cfg(feature = "specter")]
        DeviceType::Specter => match (name, descriptor, hmac) {
            (_, Some(policy), None) => Ok(Some(DeviceContext::Specter { policy })),
            (None, None, None) => Ok(None),
            (_, _, Some(_)) => anyhow::bail!("Specter-DIY signing does not use --hmac"),
            (Some(_), None, None) => {
                anyhow::bail!("Specter-DIY signing does not use --name without --descriptor")
            }
        },
        _ if name.is_none() && descriptor.is_none() && hmac.is_none() => Ok(None),
        _ => anyhow::bail!("wallet policy options are only supported by Ledger and Specter-DIY"),
    }
}

fn message_signature_base64(
    header: u8,
    signature: &bitcoin::secp256k1::ecdsa::Signature,
) -> String {
    let mut payload = [0u8; 65];
    payload[0] = header;
    payload[1..].copy_from_slice(&signature.serialize_compact());
    BASE64_STANDARD.encode(payload)
}

fn parse_hmac(hmac: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hmac)?;
    let hmac: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("hmac must be 32 bytes / 64 hex characters"))?;
    Ok(hmac)
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, error::ErrorKind};

    use super::*;

    #[test]
    fn register_wallet_preserves_descriptor_text() {
        let descriptor = "wpkh([f5acc2fd/84'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/<0;1>/*)";
        let args = Args::parse_from([
            "bhwi",
            "descriptor",
            "register",
            "--name",
            "clitestwallet",
            "--descriptor",
            descriptor,
        ]);

        let Commands::Descriptor(DescriptorCommands::Register {
            name,
            descriptor: parsed,
        }) = args.command
        else {
            panic!("expected descriptor register command");
        };
        assert_eq!(name, "clitestwallet");
        assert_eq!(parsed, descriptor);
    }

    #[test]
    fn address_path_and_descriptor_conflict_in_parser() {
        let error = Args::try_parse_from([
            "bhwi",
            "address",
            "get",
            "--from-path",
            "m/84'/1'/0'/0/0",
            "--from-descriptor",
            "wallet",
        ])
        .expect_err("path and descriptor are mutually exclusive");

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parses_device_install_udev_rules_targets() {
        let args = Args::try_parse_from([
            "bhwi",
            "device",
            "install-udev-rules",
            "--location",
            "/tmp/rules.d",
            "ledger",
            "jade",
        ])
        .expect("parse install udev rules");

        match args.command {
            Commands::Device(DeviceCommands::InstallUdevRules {
                targets,
                all,
                location,
            }) => {
                assert_eq!(
                    targets
                        .into_iter()
                        .map(DeviceType::from)
                        .collect::<Vec<_>>(),
                    vec![DeviceType::Ledger, DeviceType::Jade]
                );
                assert!(!all);
                assert_eq!(location, PathBuf::from("/tmp/rules.d"));
            }
            command => panic!("unexpected command: {command:?}"),
        }
    }

    #[test]
    fn parses_device_setup() {
        let args = Args::try_parse_from(["bhwi", "device", "setup", "--label", "BHWI"])
            .expect("parse device setup");
        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::Setup { label }) if label == "BHWI"
        ));
    }

    #[test]
    fn parses_device_wipe() {
        let args = Args::try_parse_from(["bhwi", "device", "wipe"]).expect("parse device wipe");
        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::Wipe)
        ));
    }

    #[test]
    fn parses_device_restore() {
        let args = Args::try_parse_from(["bhwi", "device", "restore", "--label", "Recovered"])
            .expect("parse device restore");
        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::Restore { label, word_count })
                if label == "Recovered" && word_count == 24
        ));
    }

    #[test]
    fn parses_device_restore_word_count() {
        let args = Args::try_parse_from(["bhwi", "device", "restore", "--word-count", "12"])
            .expect("parse device restore word count");
        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::Restore { word_count, .. }) if word_count == 12
        ));
    }

    #[test]
    fn parses_device_toggle_passphrase() {
        let args = Args::try_parse_from(["bhwi", "device", "toggle-passphrase"])
            .expect("parse device toggle-passphrase");
        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::TogglePassphrase)
        ));
    }

    #[test]
    fn parses_device_prompt_pin() {
        let args = Args::try_parse_from(["bhwi", "device", "prompt-pin"])
            .expect("parse device prompt-pin");
        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::PromptPin)
        ));
    }

    #[test]
    fn parses_device_send_pin_positions() {
        let args = Args::try_parse_from(["bhwi", "device", "send-pin", "7913"])
            .expect("parse device send-pin");
        let Commands::Device(DeviceCommands::SendPin { positions }) = args.command else {
            panic!("expected device send-pin");
        };
        assert_eq!(positions, "7913");
    }

    #[test]
    fn device_send_pin_requires_positions() {
        assert!(Args::try_parse_from(["bhwi", "device", "send-pin"]).is_err());
    }

    #[test]
    fn parses_device_install_udev_rules_all() {
        let args = Args::try_parse_from(["bhwi", "device", "install-udev-rules", "--all"])
            .expect("parse install all udev rules");

        match args.command {
            Commands::Device(DeviceCommands::InstallUdevRules {
                targets,
                all,
                location,
            }) => {
                assert!(targets.is_empty());
                assert!(all);
                assert_eq!(location, PathBuf::from("/etc/udev/rules.d/"));
            }
            command => panic!("unexpected command: {command:?}"),
        }
    }

    #[test]
    fn parses_representative_global_and_signing_args() {
        let shared = [
            "--network",
            "testnet",
            "--fingerprint",
            "f5acc2fd",
            "--device-type",
            "ledger",
            "--device-path",
            "tcp:localhost:9999",
            "--format",
            "json",
            "--passphrase",
            "secret",
        ];
        for argv in [
            [
                vec!["bhwi"],
                shared.to_vec(),
                vec![
                    "message",
                    "sign",
                    "--message",
                    "hello",
                    "--path",
                    "m/44'/1'/0'/0",
                ],
            ],
            [
                vec!["bhwi", "message"],
                shared.to_vec(),
                vec!["sign", "--message", "hello", "--path", "m/44'/1'/0'/0"],
            ],
            [
                vec![
                    "bhwi",
                    "message",
                    "sign",
                    "--message",
                    "hello",
                    "--path",
                    "m/44'/1'/0'/0",
                ],
                shared.to_vec(),
                vec![],
            ],
        ] {
            let args = Args::try_parse_from(argv.concat()).expect("shared options parse");
            assert_eq!(args.network, Network::Testnet);
            assert_eq!(
                args.fingerprint.as_ref().expect("fingerprint").to_string(),
                "f5acc2fd"
            );
            assert!(matches!(args.device_type, Some(DeviceTypeArg::Ledger)));
            assert_eq!(args.device_path.as_deref(), Some("tcp:localhost:9999"));
            assert!(matches!(args.format, Some(OutputFormat::Json)));
            assert_eq!(args.passphrase.as_deref(), Some("secret"));
            let selector = args.device_selector();
            assert_eq!(selector.network, Network::Testnet);
            assert_eq!(selector.fingerprint.as_ref(), args.fingerprint.as_ref());
            assert_eq!(selector.device_type, Some(DeviceType::Ledger));
            assert_eq!(selector.device_path.as_deref(), Some("tcp:localhost:9999"));
            #[cfg(any(feature = "trezor", feature = "keepkey"))]
            assert_eq!(
                selector.passphrase.as_ref().map(|p| p.as_str()),
                Some("secret")
            );
            assert!(matches!(
                args.command,
                Commands::Message(MessageCommands::Sign {
                    message,
                    path,
                    output: None,
                }) if message == "hello" && path.to_string() == "44'/1'/0'/0"
            ));
        }
    }

    #[test]
    fn parses_psbt_sign_policy_and_output() {
        let descriptor = "wpkh([f5acc2fd/84'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/<0;1>/*)";
        let hmac = "ab".repeat(32);
        let args = Args::try_parse_from([
            "bhwi",
            "psbt",
            "sign",
            "--psbt",
            "input.psbt",
            "--wallet-name",
            "wallet",
            "--descriptor",
            descriptor,
            "--hmac",
            &hmac,
            "-o",
            "signed.psbt",
        ])
        .expect("parse PSBT policy");
        assert!(matches!(
            args.command,
            Commands::Psbt(PsbtCommands::Sign { psbt, name, descriptor: Some(policy), hmac: Some(parsed_hmac), output: Some(output) })
                if psbt.as_os_str() == "input.psbt"
                    && name.as_deref() == Some("wallet")
                    && policy == WalletPolicy::from_str(descriptor).expect("valid wallet policy")
                    && parsed_hmac == hmac
                    && output.as_os_str() == "signed.psbt"
        ));
    }

    #[test]
    fn rejects_missing_leaf_inputs_and_unimplemented_commands() {
        for argv in [
            vec!["bhwi", "descriptor", "register"],
            vec!["bhwi", "descriptor", "register", "--name", "wallet"],
            vec![
                "bhwi",
                "descriptor",
                "register",
                "--descriptor",
                "wpkh(key)",
            ],
            vec!["bhwi", "psbt", "sign"],
            vec!["bhwi", "message", "sign"],
            vec!["bhwi", "message", "sign", "--message", "hello"],
            vec!["bhwi", "message", "sign", "--path", "m/44'/1'/0'/0"],
        ] {
            assert_eq!(
                Args::try_parse_from(argv).unwrap_err().kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
        for argv in [
            ["bhwi", "descriptor"],
            ["bhwi", "psbt"],
            ["bhwi", "message"],
        ] {
            assert!(Args::try_parse_from(argv).is_err());
        }
        assert!(
            Args::try_parse_from([
                "bhwi",
                "message",
                "sign",
                "--message",
                "hello",
                "--path",
                "not/a/path",
            ])
            .is_err()
        );
        for name in ["register-wallet", "sign-psbt", "sign-message"] {
            assert_eq!(
                Args::try_parse_from(["bhwi", name, "--help"])
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSubcommand
            );
        }
        for argv in [["bhwi", "message", "verify"], ["bhwi", "psbt", "decode"]] {
            assert_eq!(
                Args::try_parse_from(argv).unwrap_err().kind(),
                ErrorKind::InvalidSubcommand
            );
        }
    }

    #[test]
    fn parses_device_backup_with_explicit_output() {
        let args = Args::parse_from(["bhwi", "device", "backup", "--output", "backup.7z"]);

        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::Backup { output })
                if output.as_deref() == Some(std::path::Path::new("backup.7z"))
        ));
    }

    #[test]
    fn parses_device_backup_without_output() {
        let args = Args::parse_from(["bhwi", "device", "backup"]);

        assert!(matches!(
            args.command,
            Commands::Device(DeviceCommands::Backup { output: None })
        ));
    }

    #[test]
    fn native_cli_accepts_device_type_and_path_selectors() {
        let args = Args::try_parse_from([
            "bhwi",
            "--device-type",
            "bitbox02",
            "--device-path",
            "tcp:127.0.0.1:15423",
            "device",
            "list",
        ])
        .expect("native selectors parse");

        assert_eq!(
            args.device_type.map(DeviceType::from),
            Some(DeviceType::BitBox02)
        );
        assert_eq!(args.device_path.as_deref(), Some("tcp:127.0.0.1:15423"));
    }

    #[test]
    fn native_cli_accepts_keepkey_canonical_name_and_alias() {
        for name in ["keepkey", "keep-key"] {
            let args = Args::try_parse_from([
                "bhwi",
                "--device-type",
                name,
                "--device-path",
                "127.0.0.1:11044",
                "device",
                "list",
            ])
            .expect("KeepKey selector parses");
            assert_eq!(
                args.device_type.map(DeviceType::from),
                Some(DeviceType::KeepKey)
            );
            assert_eq!(args.device_path.as_deref(), Some("127.0.0.1:11044"));
        }
    }

    #[cfg(feature = "specter")]
    #[test]
    fn specter_signing_accepts_a_descriptor_without_a_wallet_name() {
        let policy = WalletPolicy::from_str(
            "wpkh([f5acc2fd/84'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/<0;1>/*)",
        )
        .expect("valid wallet policy");
        let context = signing_context(DeviceType::Specter, None, Some(policy), None)
            .expect("Specter context");
        assert!(matches!(context, Some(DeviceContext::Specter { .. })));
        assert!(signing_context(DeviceType::Specter, Some("unused".into()), None, None).is_err());
    }

    #[cfg(any(feature = "trezor", feature = "keepkey"))]
    #[test]
    fn native_cli_passes_password_through_to_the_selector() {
        let args = Args::try_parse_from(["bhwi", "-p", "secret", "device", "list"])
            .expect("password parses");
        assert_eq!(
            args.device_selector()
                .passphrase
                .map(|p| p.as_str().to_owned()),
            Some("secret".to_owned())
        );

        let without = Args::try_parse_from(["bhwi", "device", "list"]).expect("no password parses");
        assert!(without.device_selector().passphrase.is_none());
    }

    #[test]
    fn native_cli_remembers_any_given_password_in_every_build() {
        for (argv, given) in [
            (vec!["bhwi", "-p", "secret", "device", "list"], true),
            (vec!["bhwi", "-p", "", "device", "list"], true),
            (vec!["bhwi", "device", "list"], false),
        ] {
            let args = Args::try_parse_from(argv).expect("arguments parse");
            assert_eq!(args.manager().password_given(), given);
        }
    }

    #[test]
    fn clap_definition_is_valid() {
        Args::command().debug_assert();
    }
}
