use bitcoin::bip32::Fingerprint;

use crate::{jade, ledger, Interpreter};

pub enum Command {
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
}

impl From<Command> for jade::JadeCommand {
    fn from(cmd: Command) -> Self {
        match cmd {
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
            jade::JadeError::NoErrorOrResult => Error::NoErrorOrResult,
            jade::JadeError::Rpc(_) => Error::NoErrorOrResult,
            jade::JadeError::Request(_) => Error::NoErrorOrResult,
            jade::JadeError::Unexpected(_) => Error::NoErrorOrResult,
            jade::JadeError::HandshakeRefused => Error::NoErrorOrResult,
        }
    }
}

pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response, Error>;

impl From<Command> for ledger::LedgerCommand {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::GetMasterFingerprint => Self::GetMasterFingerprint,
        }
    }
}

impl From<ledger::LedgerResponse> for Response {
    fn from(res: ledger::LedgerResponse) -> Response {
        match res {
            ledger::LedgerResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
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
            _ => Error::NoErrorOrResult,
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
            Box::new(LedgerInterpreter::new()),
            Box::new(JadeInterpreter::new()),
        ];
        assert_eq!(interpreters.len(), 2);
    }
}
