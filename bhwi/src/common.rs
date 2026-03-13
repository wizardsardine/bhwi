use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::ecdsa::Signature;

use crate::{coldcard, jade, ledger};

#[derive(Default)]
pub struct UnlockOptions {
    pub network: Option<Network>,
}

pub enum Command {
    Unlock {
        options: UnlockOptions,
    },
    GetMasterFingerprint,
    GetXpub {
        path: DerivationPath,
        display: bool,
    },
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
}

pub enum Response {
    TaskDone,
    TaskBusy,
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    EncryptionKey([u8; 64]),
    Signature(u8, Signature),
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

    #[error("unexpected result: {0:x?}")]
    UnexpectedResult(Vec<u8>),

    #[error("rpc error {0}: {1:?}")]
    Rpc(i32, Option<String>),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("request error: {0}")]
    Request(&'static str),

    #[error("authentication refused")]
    AuthenticationRefused,
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
