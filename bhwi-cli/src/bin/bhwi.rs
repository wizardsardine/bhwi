use anyhow::Result;
use bhwi_cli::{DeviceManager, OutputFormat, address::AddressTarget, config::Config};

use bitcoin::{
    Network,
    address::AddressType,
    bip32::{DerivationPath, Fingerprint},
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    #[arg(long)]
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

impl From<Args> for Config {
    fn from(args: Args) -> Self {
        let Args {
            network,
            fingerprint,
            format,
            ..
        } = args;
        Self {
            network,
            fingerprint,
            format,
        }
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
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum DeviceCommands {
    /// List all available devices
    #[command(alias = "enumerate")]
    List,
}

#[derive(Debug, Clone, Subcommand)]
enum XpubCommands {
    Get {
        #[arg(value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        path: DerivationPath,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum DescriptorCommands {
    /// Get pubkey descriptors from device
    #[command()]
    Pubkeys {
        #[arg(long, short)]
        account: Option<u32>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let command = args.command.to_owned();
    let format = args.format;
    let config: Config = args.into();
    let dev_man = DeviceManager::new(config);
    match command {
        Commands::Address(AddressCommands::Get {
            from_path,
            from_descriptor,
            index,
            change,
            display,
            address_format,
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
                };
                dev_man.get_address(target).await?
            }
            _ => anyhow::bail!("either --from-path or --from-descriptor must be specified"),
        },
        Commands::Descriptor(DescriptorCommands::Pubkeys { account }) => {
            dev_man.get_pubkey_descriptors(account).await?
        }
        Commands::Device(DeviceCommands::List) => {
            let mut devices = dev_man.enumerate().await?;
            for (i, device) in devices.iter_mut().enumerate() {
                // XXX: Coldcard always needs unlocking
                device.device().unlock(dev_man.config.network).await?;
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
        Commands::Xpub(XpubCommands::Get { path }) => {
            if let Some(mut d) = dev_man.get_device_with_fingerprint().await? {
                println!("{}", d.device().get_extended_pubkey(path, false).await?);
            }
        }
    }
    Ok(())
}
