use bitcoin::Network;
use bitcoin::address::AddressType;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::ecdsa::Signature;

use crate::{coldcard, jade, ledger};

#[derive(Default)]
pub struct UnlockOptions {
    pub network: Option<Network>,
}

#[derive(Clone, Debug)]
pub enum DisplayAddress {
    ByPath {
        path: DerivationPath,
        display: bool,
        address_format: Option<AddressType>,
    },
    ByDescriptor {
        index: u32,
        change: bool,
        display: bool,
        descriptor_name: String,
    },
}

#[allow(clippy::large_enum_variant)]
pub enum Command {
    GetMasterFingerprint,
    GetVersion,
    GetXpub {
        path: DerivationPath,
        display: bool,
    },
    DisplayAddress(DisplayAddress, Option<DeviceContext>),
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    Unlock {
        options: UnlockOptions,
    },
}

/// Device-specific context data required by certain commands.
#[derive(Clone, Debug)]
pub enum DeviceContext {
    /// Required contexts for Ledger devices
    Ledger {
        wallet_policy: ledger::LedgerWalletPolicy,
        wallet_hmac: Option<[u8; 32]>,
    },
}

pub enum Response {
    TaskDone,
    TaskBusy,
    Info(Info),
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    EncryptionKey([u8; 64]),
    Signature(u8, Signature),
    Address(String),
}

/// Device Information
#[derive(Debug, Clone, Default)]
pub struct Info {
    pub version: String,
    pub networks: Vec<Network>,
    pub firmware: Option<String>,
}

pub enum Recipient {
    Device,
    PinServer { url: String },
}

pub struct Transmit {
    pub recipient: Recipient,
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encryption error: {0}")]
    Encryption(&'static str),

    #[error("no error or result returned")]
    NoErrorOrResult,

    #[error("missing command info: {0}")]
    MissingCommandInfo(&'static str),

    #[error("unexpected result for {1}: {0:x?}")]
    UnexpectedResult(Vec<u8>, String),

    #[error("rpc error {0}: {1:?}")]
    Rpc(i32, Option<String>),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("request error: {0}")]
    Request(&'static str),

    #[error("authentication refused")]
    AuthenticationRefused,

    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(String),
}

impl Error {
    pub fn unexpected_result(data: Vec<u8>, context: impl Into<String>) -> Self {
        Error::UnexpectedResult(data, context.into())
    }
}

pub type ColdcardInterpreter<'a> =
    coldcard::ColdcardInterpreter<'a, Command, Transmit, Response, Error>;
pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response, Error>;
pub type LedgerInterpreter = ledger::LedgerInterpreter<Command, Transmit, Response, Error>;

impl From<Vec<u8>> for Transmit {
    fn from(payload: Vec<u8>) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload,
            encrypted: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Interpreter;

    #[test]
    fn common_interpreter_is_satisfied() {
        let interpreters: Vec<
            Box<
                dyn Interpreter<
                        Command = super::Command,
                        Transmit = super::Transmit,
                        Response = super::Response,
                        Error = super::Error,
                    >,
            >,
        > = vec![
            Box::<LedgerInterpreter>::default(),
            Box::<JadeInterpreter>::default(),
        ];
        assert_eq!(interpreters.len(), 2);
    }
}
