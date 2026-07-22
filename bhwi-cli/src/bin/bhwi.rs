use anyhow::Result;
use bhwi::ledger::{LedgerWalletPolicy, Version};
use bhwi_async::{DeviceBackup, DeviceContext, WalletRegistration};
use bhwi_cli::{
    DeviceManager, OutputFormat,
    address::AddressTarget,
    config::DeviceSelector,
    get_descriptors::GetKeypoolOptions,
    udev::{UdevRuleSelection, install_udev_rules},
};

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
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    /// default will be the first connected device with the master fingerprint matching.
    #[arg(long, alias = "fg", value_parser = clap::value_parser!(bitcoin::bip32::Fingerprint))]
    fingerprint: Option<Fingerprint>,
    /// default will be the Bitcoin mainnet network.
    #[arg(long, short, value_parser = clap::value_parser!(bitcoin::Network), default_value_t = bitcoin::Network::Bitcoin)]
    network: Network,
    /// output formatting
    #[arg(long, short)]
    format: Option<OutputFormat>,
}

impl Args {
    fn device_selector(&self) -> DeviceSelector {
        DeviceSelector {
            network: self.network,
            fingerprint: self.fingerprint,
            include_emulators: true,
            ..DeviceSelector::default()
        }
    }
}

impl From<&Args> for DeviceSelector {
    fn from(args: &Args) -> Self {
        args.device_selector()
    }
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    #[command(subcommand)]
    Address(AddressCommands),
    #[command(subcommand)]
    Descriptor(DescriptorCommands),
    #[command(subcommand)]
    Device(DeviceCommands),
    #[command(subcommand)]
    Xpub(XpubCommands),
    /// Register a wallet policy on the device
    RegisterWallet {
        /// Name of the wallet
        #[arg(long)]
        name: String,
        /// Miniscript wallet policy descriptor
        #[arg(long)]
        descriptor: String,
    },
    /// Sign a PSBT with the selected device
    SignPsbt {
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
        /// Output file. Defaults to stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Sign a message with the selected device
    SignMessage {
        /// Message to sign
        #[arg(long)]
        message: String,
        /// BIP32 derivation path (e.g. m/44'/0'/0'/0/0)
        #[arg(long, value_parser = clap::value_parser!(DerivationPath))]
        path: DerivationPath,
        /// Output file. Defaults to stdout.
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
        /// Miniscript wallet policy matching the registered wallet,
        /// required for Ledger descriptor-based addresses.
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
    /// Install udev rules for hardware wallet device access
    InstallUdevRules {
        /// Device rule targets to install
        #[arg(value_enum)]
        targets: Vec<bhwi_cli::DeviceType>,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let command = args.command.to_owned();
    let format = args.format;
    let selector = DeviceSelector::from(&args);
    let dev_man = DeviceManager::new(selector);
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
            let mut devices = dev_man.enumerate().await?;
            for (i, device) in devices.iter_mut().enumerate() {
                // XXX: Coldcard always needs unlocking
                device.device().unlock(dev_man.selector.network).await?;
                let fingerprint = device.fingerprint().await?;
                let name = device.name().to_string();
                let is_emulated = device.is_emulated();
                let info = device.info().await?;
                match format {
                    Some(OutputFormat::Pretty) => {
                        if i == 0 {
                            println!(
                                "{:<18} | {:<8} | {:<15} | {:<12} | {:<8}",
                                "Name", "Emulated", "Fingerprint", "Network", "Version"
                            );
                        }
                        println!("{}", "-".repeat(80));
                        let network = info.networks_string();
                        println!(
                            "{name:<18} | {is_emulated:<8} | {fingerprint:<15} | {network:<12} | {:<8}",
                            info.version
                        );
                        println!("{}", "-".repeat(80));
                    }
                    Some(OutputFormat::Json) => {}
                    None => println!("{fingerprint}"),
                }
            }
            if let Some(OutputFormat::Json) = format {
                println!("{}", serde_json::json![devices])
            }
        }
        Commands::Device(DeviceCommands::Backup { output }) => {
            if let Some(mut d) = dev_man.get_device_with_fingerprint().await? {
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
                    bhwi_cli::DeviceType::Jade,
                    bhwi_cli::DeviceType::Ledger,
                ])
            } else {
                UdevRuleSelection::Devices(targets)
            };
            install_udev_rules(&location, selection)?;
            if let Some(OutputFormat::Json) = format {
                println!("{}", serde_json::json!({ "success": true }));
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            if let Some(mut d) = dev_man.get_device_with_fingerprint().await? {
                println!("{}", d.device().get_extended_pubkey(path, false).await?);
            }
        }
        Commands::RegisterWallet { name, descriptor } => {
            if let Some(mut d) = dev_man.get_device_with_fingerprint().await? {
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
        Commands::SignPsbt {
            psbt,
            name,
            descriptor,
            hmac,
            output,
        } => {
            let psbt_text = std::fs::read_to_string(psbt)?;
            let psbt = Psbt::from_str(psbt_text.trim())?;
            let hmac = hmac.as_deref().map(parse_hmac).transpose()?;
            let context = match (name, descriptor, hmac) {
                (Some(name), Some(policy), hmac) => Some(DeviceContext::Ledger {
                    wallet_policy: LedgerWalletPolicy::new(name, Version::V2, policy),
                    wallet_hmac: hmac,
                }),
                (None, None, None) => None,
                (None, None, Some(_)) => {
                    anyhow::bail!("--hmac requires --name and --descriptor for Ledger signing")
                }
                _ => anyhow::bail!(
                    "--name and --descriptor must be provided together for Ledger signing"
                ),
            };
            if let Some(mut d) = dev_man.get_device_with_fingerprint().await? {
                let signed = d.device().sign_tx(psbt, context).await?;
                let signed = signed.to_string();
                if let Some(output) = output {
                    std::fs::write(output, signed)?;
                } else {
                    println!("{signed}");
                }
            }
        }
        Commands::SignMessage {
            message,
            path,
            output,
        } => {
            if let Some(mut d) = dev_man.get_device_with_fingerprint().await? {
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
            "register-wallet",
            "--name",
            "clitestwallet",
            "--descriptor",
            descriptor,
        ]);

        let Commands::RegisterWallet {
            name,
            descriptor: parsed,
        } = args.command
        else {
            panic!("expected register-wallet command");
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
                    targets,
                    vec![bhwi_cli::DeviceType::Ledger, bhwi_cli::DeviceType::Jade]
                );
                assert!(!all);
                assert_eq!(location, PathBuf::from("/tmp/rules.d"));
            }
            command => panic!("unexpected command: {command:?}"),
        }
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
        let args = Args::parse_from([
            "bhwi",
            "--network",
            "testnet",
            "--fingerprint",
            "f5acc2fd",
            "--format",
            "json",
            "sign-message",
            "--message",
            "hello",
            "--path",
            "m/44'/1'/0'/0",
        ]);

        assert_eq!(args.network, Network::Testnet);
        assert_eq!(
            args.fingerprint.expect("fingerprint").to_string().as_str(),
            "f5acc2fd"
        );
        assert!(matches!(args.format, Some(OutputFormat::Json)));
        assert!(matches!(
            args.command,
            Commands::SignMessage {
                message,
                path,
                output: None,
            } if message == "hello" && path.to_string() == "44'/1'/0'/0"
        ));
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
    fn native_cli_rejects_hwi_only_selector_flags() {
        let error = Args::try_parse_from([
            "bhwi",
            "--device-path",
            "tcp:localhost:9999",
            "device",
            "list",
        ])
        .expect_err("native CLI must not accept HWI compatibility flags");

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn clap_definition_is_valid() {
        Args::command().debug_assert();
    }
}
