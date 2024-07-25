use bitcoin::bip32::Fingerprint;

use crate::{jade, ledger};

pub enum Command {
    GetMasterFingerprint,
}

pub enum Response {
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

pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response>;

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

pub type LedgerInterpreter = ledger::LedgerInterpreter<Command, Transmit, Response>;

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
                >,
            >,
        > = vec![
            Box::new(LedgerInterpreter::new()),
            Box::new(JadeInterpreter::new()),
        ];
        assert_eq!(interpreters.len(), 2);
    }
}
