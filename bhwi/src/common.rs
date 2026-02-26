use bitcoin::{
    Network,
    bip32::{DerivationPath, Fingerprint, Xpub},
};

use crate::{coldcard, jade, ledger};

#[derive(Default)]
pub struct UnlockOptions {
    pub network: Option<Network>,
}

pub enum Command {
    Unlock { options: UnlockOptions },
    GetMasterFingerprint,
    GetXpub { path: DerivationPath, display: bool },
}

pub enum Response {
    TaskDone,
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    EncryptionKey([u8; 64]),
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

#[derive(Debug)]
pub enum Error {
    Encryption(&'static str),
    NoErrorOrResult,
    MissingCommandInfo(&'static str),
    UnexpectedResult(Vec<u8>),
    // Generic RPC/communication errors
    Rpc(i32, Option<String>), // (code, message)
    Serialization(String),
    Request(&'static str),
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
