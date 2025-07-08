use bhwi_cli::{get_device_with_fingerprint, list, Error};

use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    Network,
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
    #[arg(long, value_parser = clap::value_parser!(bitcoin::Network), default_value_t = bitcoin::Network::Bitcoin)]
    network: Network,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(subcommand)]
    Device(DeviceCommands),
    #[command(subcommand)]
    Xpub(XpubCommands),
}

#[derive(Debug, Subcommand)]
enum DeviceCommands {
    List,
}

#[derive(Debug, Subcommand)]
enum XpubCommands {
    Get {
        #[arg(long, value_parser = clap::value_parser!(bitcoin::bip32::DerivationPath))]
        path: DerivationPath,
    },
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    match args.command {
        Commands::Device(DeviceCommands::List) => {
            let devices = list(args.network).await?;
            if devices.is_empty() {
                eprintln!("No devices found");
            } else {
                for mut device in devices {
                    match device.get_master_fingerprint().await {
                        Ok(fingerprint) => {
                            println!("{}", fingerprint);
                        }
                        Err(e) => {
                            eprintln!("Error accessing device: {:?}", e);
                        }
                    }
                }
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            if let Some(mut device) = get_device_with_fingerprint(args.network, args.fingerprint).await? {
                match device.get_extended_pubkey(path, false).await {
                    Ok(xpub) => {
                        println!("{}", xpub);
                    }
                    Err(e) => {
                        eprintln!("Error getting xpub: {:?}", e);
                    }
                }
            } else {
                eprintln!("No device found");
            }
        }
    }
    Ok(())
}
