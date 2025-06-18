use bitcoin::{bip32::Fingerprint, Network};

use crate::{jade, ledger};

pub enum Command {
    Unlock(Network),
    GetMasterFingerprint,
}

pub enum Response {
    TaskDone,
    MasterFingerprint(Fingerprint),
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

impl From<Command> for jade::JadeCommand {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Unlock(..) => Self::Auth,
            Command::GetMasterFingerprint => Self::GetMasterFingerprint,
        }
    }
}

impl From<jade::JadeResponse> for Response {
    fn from(res: jade::JadeResponse) -> Response {
        match res {
            jade::JadeResponse::TaskDone => Response::TaskDone,
            jade::JadeResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
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

pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response, Error>;

impl From<Command> for ledger::LedgerCommand {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Unlock(network) => Self::OpenApp(network),
            Command::GetMasterFingerprint => Self::GetMasterFingerprint,
        }
    }
}

impl From<ledger::LedgerResponse> for Response {
    fn from(res: ledger::LedgerResponse) -> Response {
        match res {
            ledger::LedgerResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            ledger::LedgerResponse::TaskDone => Response::TaskDone,
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
            ledger::LedgerError::UnexpectedResult(_, data) => Error::UnexpectedResult(data),
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
