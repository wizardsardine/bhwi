pub mod api;
pub mod encrypt;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};

use crate::Interpreter;

#[derive(Debug)]
pub enum ColdcardError {
    Encryption(&'static str),
    MissingCommandInfo(&'static str),
    NoErrorOrResult,
    Serialization(String),
}

pub enum ColdcardCommand {
    StartEncryption,
    GetMasterFingerprint,
    GetXpub(DerivationPath),
}

pub enum ColdcardResponse {
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    MyPub {
        encryption_key: [u8; 64],
        xpub_fingerprint: Fingerprint,
        xpub: Option<Xpub>,
    },
}

pub struct ColdcardTransmit {
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

enum State {
    New,
    Running(ColdcardCommand),
    Finished(ColdcardResponse),
}

pub struct ColdcardInterpreter<'a, C, T, R, E> {
    state: State,
    encryption: &'a mut encrypt::Engine,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<'a, C, T, R, E> ColdcardInterpreter<'a, C, T, R, E> {
    pub fn new(encryption: &'a mut encrypt::Engine) -> Self {
        Self {
            state: State::New,
            encryption,
            _marker: std::marker::PhantomData,
        }
    }
}

fn request(
    payload: Vec<u8>,
    encryption: &mut encrypt::Engine,
) -> Result<ColdcardTransmit, ColdcardError> {
    Ok(ColdcardTransmit {
        payload: encryption.encrypt(payload)?,
        encrypted: true,
    })
}

impl<'a, C, T, R, E> Interpreter for ColdcardInterpreter<'a, C, T, R, E>
where
    C: TryInto<ColdcardCommand, Error = ColdcardError>,
    T: From<ColdcardTransmit>,
    R: From<ColdcardResponse>,
    E: From<ColdcardError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: ColdcardCommand = command.try_into()?;
        let req = match &command {
            ColdcardCommand::StartEncryption => ColdcardTransmit {
                payload: api::request::start_encryption(None, &self.encryption.pub_key()?),
                encrypted: false,
            },
            ColdcardCommand::GetMasterFingerprint => request(
                api::request::get_xpub(&DerivationPath::master()),
                self.encryption,
            )?,
            ColdcardCommand::GetXpub(path) => {
                request(api::request::get_xpub(path), self.encryption)?
            }
        };

        self.state = State::Running(command);
        Ok(req.into())
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        match &self.state {
            State::New => Ok(None),
            State::Running(ColdcardCommand::GetMasterFingerprint) => {
                let data = self.encryption.decrypt(data)?;
                let xpub = api::response::xpub(data)?;
                self.state =
                    State::Finished(ColdcardResponse::MasterFingerprint(xpub.fingerprint()));
                Ok(None)
            }
            State::Running(ColdcardCommand::GetXpub(..)) => {
                let data = self.encryption.decrypt(data)?;
                let xpub = api::response::xpub(data)?;
                self.state = State::Finished(ColdcardResponse::Xpub(xpub));
                Ok(None)
            }
            State::Running(ColdcardCommand::StartEncryption) => {
                let mypub = api::response::mypub(data)?;
                self.state = State::Finished(mypub);
                Ok(None)
            }
            State::Finished(..) => Ok(None),
        }
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        if let State::Finished(res) = self.state {
            Ok(Self::Response::from(res))
        } else {
            Err(ColdcardError::NoErrorOrResult.into())
        }
    }
}
