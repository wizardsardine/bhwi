use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    Network,
};

use crate::{jade, ledger};

pub enum Command<'a> {
    Unlock(Network),
    GetMasterFingerprint,
    GetXpub {
        path: &'a DerivationPath,
        display: bool,
    },
}

pub enum Response {
    TaskDone,
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
}

pub enum Recipient {
    Device,
    PinServer { url: String },
}

pub struct Transmit {
    pub recipient: Recipient,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    NoErrorOrResult,
    UnexpectedResult(Vec<u8>),
    // Generic RPC/communication errors
    Rpc(i32, Option<String>), // (code, message)
    Serialization,
    Request(&'static str),
    AuthenticationRefused,
}

impl<'a> From<Command<'a>> for jade::JadeCommand<'a> {
    fn from(cmd: Command<'a>) -> Self {
        match cmd {
            Command::Unlock(..) => Self::Auth,
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
        }
    }
}

impl From<jade::JadeError> for Error {
    fn from(error: jade::JadeError) -> Error {
        match error {
            jade::JadeError::Cbor => Error::Serialization,
            jade::JadeError::NoErrorOrResult => Error::NoErrorOrResult,
            jade::JadeError::Rpc(api_error) => Error::Rpc(api_error.code, api_error.message),
            jade::JadeError::Serialization(_) => Error::Serialization,
            jade::JadeError::UnexpectedResult(msg) => Error::UnexpectedResult(msg.into_bytes()),
            jade::JadeError::HandshakeRefused => Error::AuthenticationRefused,
        }
    }
}

pub type JadeInterpreter<'a> = jade::JadeInterpreter<'a, Command<'a>, Transmit, Response, Error>;

impl<'a> From<Command<'a>> for ledger::LedgerCommand<'a> {
    fn from(cmd: Command<'a>) -> Self {
        match cmd {
            Command::Unlock(network) => Self::OpenApp(network),
            Command::GetMasterFingerprint => Self::GetMasterFingerprint,
            Command::GetXpub { path, display } => Self::GetXpub { path, display },
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
        }
    }
}

impl From<ledger::apdu::ApduCommand> for Transmit {
    fn from(payload: ledger::apdu::ApduCommand) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload: payload.encode(),
        }
    }
}

impl From<ledger::LedgerError> for Error {
    fn from(error: ledger::LedgerError) -> Error {
        match error {
            ledger::LedgerError::NoErrorOrResult => Error::NoErrorOrResult,
            ledger::LedgerError::Apdu(_) => Error::Serialization,
            ledger::LedgerError::Store(_) => Error::Request("Store operation failed"),
            ledger::LedgerError::Interrupted => Error::Request("Operation interrupted"),
            ledger::LedgerError::UnexpectedResult(data) => Error::UnexpectedResult(data),
            ledger::LedgerError::FailedToOpenApp(_) => Error::AuthenticationRefused,
        }
    }
}

pub type LedgerInterpreter<'a> =
    ledger::LedgerInterpreter<'a, Command<'a>, Transmit, Response, Error>;

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
