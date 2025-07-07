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
            for mut device in list(args.network).await? {
                eprint!("{}", device.get_master_fingerprint().await?);
            }
        }
        Commands::Xpub(XpubCommands::Get { path }) => {
            if let Some(mut d) = get_device_with_fingerprint(args.network, args.fingerprint).await?
            {
                eprintln!("{}", d.get_extended_pubkey(path, false).await?);
            }
        }
    }
    Ok(())
}
