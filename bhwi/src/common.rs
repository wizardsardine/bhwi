use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    Network,
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

impl TryFrom<Command> for coldcard::ColdcardCommand {
    type Error = coldcard::ColdcardError;
    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Unlock { .. } => Ok(Self::StartEncryption),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, .. } => Ok(Self::GetXpub(path)),
        }
    }
}

impl From<coldcard::ColdcardResponse> for Response {
    fn from(res: coldcard::ColdcardResponse) -> Response {
        match res {
            coldcard::ColdcardResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            coldcard::ColdcardResponse::Xpub(xpub) => Response::Xpub(xpub),
            coldcard::ColdcardResponse::MyPub { encryption_key, .. } => {
                Response::EncryptionKey(encryption_key)
            }
        }
    }
}

impl From<coldcard::ColdcardTransmit> for Transmit {
    fn from(transmit: coldcard::ColdcardTransmit) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload: transmit.payload,
            encrypted: transmit.encrypted,
        }
    }
}

impl From<coldcard::ColdcardError> for Error {
    fn from(error: coldcard::ColdcardError) -> Error {
        match error {
            coldcard::ColdcardError::Encryption(e) => Error::Encryption(e),
            coldcard::ColdcardError::MissingCommandInfo(e) => Error::MissingCommandInfo(e),
            coldcard::ColdcardError::NoErrorOrResult => Error::NoErrorOrResult,
            coldcard::ColdcardError::Serialization(s) => Error::Serialization(s),
        }
    }
}

pub type ColdcardInterpreter<'a> =
    coldcard::ColdcardInterpreter<'a, Command, Transmit, Response, Error>;

impl From<Command> for jade::JadeCommand {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Unlock { .. } => Self::Auth,
            Command::GetMasterFingerprint => Self::GetMasterFingerprint,
            Command::GetXpub { path, .. } => Self::GetXpub(path),
        }
    }
}

impl From<jade::JadeResponse> for Response {
    fn from(res: jade::JadeResponse) -> Response {
        match res {
            jade::JadeResponse::TaskDone => Response::TaskDone,
            jade::JadeResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            jade::JadeResponse::Xpub(xpub) => Response::Xpub(xpub),
        }
    }
}

impl From<jade::JadeRecipient> for Recipient {
    fn from(recipient: jade::JadeRecipient) -> Recipient {
        match recipient {
            jade::JadeRecipient::Device => Recipient::Device,
            jade::JadeRecipient::PinServer { url } => Recipient::PinServer { url },
        }
    }
}

impl From<jade::JadeTransmit> for Transmit {
    fn from(transmit: jade::JadeTransmit) -> Transmit {
        Transmit {
            recipient: transmit.recipient.into(),
            payload: transmit.payload,
            encrypted: false,
        }
    }
}

impl From<jade::JadeError> for Error {
    fn from(error: jade::JadeError) -> Error {
        match error {
            jade::JadeError::Cbor => Error::Serialization("cbor".to_string()),
            jade::JadeError::NoErrorOrResult => Error::NoErrorOrResult,
            jade::JadeError::Rpc(api_error) => Error::Rpc(api_error.code, api_error.message),
            jade::JadeError::Serialization(s) => Error::Serialization(s),
            jade::JadeError::UnexpectedResult(msg) => Error::UnexpectedResult(msg.into_bytes()),
            jade::JadeError::HandshakeRefused => Error::AuthenticationRefused,
        }
    }
}

pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response, Error>;

impl TryFrom<Command> for ledger::LedgerCommand {
    type Error = ledger::LedgerError;
    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Unlock { options } => options
                .network
                .map(Self::OpenApp)
                .ok_or(ledger::LedgerError::MissingCommandInfo("network")),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, display } => Ok(Self::GetXpub { path, display }),
        }
    }
}

impl From<ledger::LedgerResponse> for Response {
    fn from(res: ledger::LedgerResponse) -> Response {
        match res {
            ledger::LedgerResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            ledger::LedgerResponse::TaskDone => Response::TaskDone,
            ledger::LedgerResponse::Xpub(xpub) => Response::Xpub(xpub),
        }
    }
}

impl From<Vec<u8>> for Transmit {
    fn from(payload: Vec<u8>) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload,
            encrypted: false,
        }
    }
}

impl From<ledger::apdu::ApduCommand> for Transmit {
    fn from(payload: ledger::apdu::ApduCommand) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload: payload.encode(),
            encrypted: false,
        }
    }
}

impl From<ledger::LedgerError> for Error {
    fn from(error: ledger::LedgerError) -> Error {
        match error {
            ledger::LedgerError::MissingCommandInfo(e) => Error::MissingCommandInfo(e),
            ledger::LedgerError::NoErrorOrResult => Error::NoErrorOrResult,
            ledger::LedgerError::Apdu(e) => Error::Serialization(format!("{:?}", e)),
            ledger::LedgerError::Store(_) => Error::Request("Store operation failed"),
            ledger::LedgerError::Interrupted => Error::Request("Operation interrupted"),
            ledger::LedgerError::UnexpectedResult(data) => Error::UnexpectedResult(data),
            ledger::LedgerError::FailedToOpenApp(_) => Error::AuthenticationRefused,
        }
    }
}

pub type LedgerInterpreter = ledger::LedgerInterpreter<Command, Transmit, Response, Error>;

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
