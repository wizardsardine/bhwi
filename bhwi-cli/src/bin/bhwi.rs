use anyhow::Result;
use bhwi_cli::{DeviceManager, OutputFormat, config::Config};

use bitcoin::{
    Network,
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
    Descriptor(DescriptorCommands),
    #[command(subcommand)]
    Device(DeviceCommands),
    #[command(subcommand)]
    Xpub(XpubCommands),
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
        Commands::Descriptor(DescriptorCommands::Pubkeys { account }) => {
            dev_man.get_pubkey_descriptors(account).await?
        }
        Commands::Device(DeviceCommands::List) => {
            let mut devices = dev_man.enumerate().await?;
            for (i, device) in devices.iter_mut().enumerate() {
                let fingerprint = device.fingerprint().await?;
                let name = device.name();
                let is_emulated = device.is_emulated();
                match format {
                    Some(OutputFormat::Pretty) => {
                        if i == 0 {
                            println!("{:<18} | {:<8} | {:<15}", "Name", "Emulated", "Fingerprint");
                        }
                        println!("{}", "-".repeat(55));
                        println!("{name:<18} | {is_emulated:<8} | {fingerprint:<15}");
                        println!("{}", "-".repeat(55));
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
