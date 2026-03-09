use bitcoin::{Network, bip32::Fingerprint};

// TODO: eventually have this be parsable by toml/yaml, env vars
#[derive(Debug)]
pub struct Config {
    pub network: Network,
    pub fingerprint: Option<Fingerprint>,
}
