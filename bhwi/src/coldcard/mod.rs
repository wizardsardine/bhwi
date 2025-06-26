pub mod api;
pub mod encrypt;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};

use crate::Interpreter;

#[derive(Debug)]
pub enum ColdcardError {
    NoErrorOrResult,
    Serialization(String),
}

pub enum ColdcardCommand<'a> {
    GetMasterFingerprint,
    GetXpub(&'a DerivationPath),
}

pub enum ColdcardResponse {
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
}

pub struct ColdcardTransmit {
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

enum State<'a> {
    New,
    Running(ColdcardCommand<'a>),
    Finished(ColdcardResponse),
}

pub struct ColdcardInterpreter<'a, C, T, R, E> {
    state: State<'a>,
    encryption: Option<&'a mut encrypt::Engine>,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<'a, C, T, R, E> ColdcardInterpreter<'a, C, T, R, E> {
    pub fn new(encryption: Option<&'a mut encrypt::Engine>) -> Self {
        Self {
            state: State::New,
            encryption,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, C, T, R, E> Default for ColdcardInterpreter<'a, C, T, R, E> {
    fn default() -> Self {
        Self {
            state: State::New,
            encryption: None,
            _marker: std::marker::PhantomData,
        }
    }
}

fn request(payload: Vec<u8>, encryption: Option<&mut encrypt::Engine>) -> ColdcardTransmit {
    if let Some(e) = encryption {
        ColdcardTransmit {
            payload: e.encrypt(payload),
            encrypted: true,
        }
    } else {
        ColdcardTransmit {
            payload,
            encrypted: false,
        }
    }
}

impl<'a, C, T, R, E> Interpreter for ColdcardInterpreter<'a, C, T, R, E>
where
    C: Into<ColdcardCommand<'a>>,
    T: From<ColdcardTransmit>,
    R: From<ColdcardResponse>,
    E: From<ColdcardError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: ColdcardCommand = command.into();
        let req = match &command {
            ColdcardCommand::GetMasterFingerprint => request(
                api::request::get_xpub(&DerivationPath::master()),
                self.encryption.as_deref_mut(),
            ),
            ColdcardCommand::GetXpub(path) => {
                request(api::request::get_xpub(path), self.encryption.as_deref_mut())
            }
        };

        self.state = State::Running(command);
        Ok(req.into())
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        match &self.state {
            State::New => Ok(None),
            State::Running(ColdcardCommand::GetMasterFingerprint) => {
                let data = match &mut self.encryption {
                    Some(e) => e.decrypt(data),
                    None => data,
                };
                let xpub = api::response::xpub(data)?;
                self.state =
                    State::Finished(ColdcardResponse::MasterFingerprint(xpub.fingerprint()));
                Ok(None)
            }
            State::Running(ColdcardCommand::GetXpub(..)) => {
                let data = match &mut self.encryption {
                    Some(e) => e.decrypt(data),
                    None => data,
                };
                let xpub = api::response::xpub(data)?;
                self.state = State::Finished(ColdcardResponse::Xpub(xpub));
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
