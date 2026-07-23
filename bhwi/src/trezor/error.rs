use crate::common;

#[derive(Debug, thiserror::Error)]
pub enum TrezorError {
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("malformed trezor message frame")]
    MalformedFrame,
    #[error("unexpected trezor message type {0} while {1}")]
    UnexpectedMessage(u16, &'static str),
    #[error("device failure: {1}")]
    Failure(i32, String),
    #[error("device is locked: {0}")]
    Locked(&'static str),
    #[error("device returned a key for the wrong network")]
    NetworkMismatch,
    #[error("device refused the operation")]
    ActionCancelled,
    #[error("unsupported command: {0}")]
    Unsupported(&'static str),
    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<TrezorError> for common::Error {
    fn from(e: TrezorError) -> Self {
        match e {
            TrezorError::Decode(err) => common::Error::Serialization(err.to_string()),
            TrezorError::MalformedFrame => {
                common::Error::Serialization("malformed trezor message frame".into())
            }
            TrezorError::UnexpectedMessage(t, ctx) => {
                common::Error::unexpected_result(t.to_be_bytes().to_vec(), format!("trezor: {ctx}"))
            }
            TrezorError::Failure(_, msg) => common::Error::Device(msg),
            TrezorError::Locked(ctx) => common::Error::Device(format!("device is locked: {ctx}")),
            TrezorError::NetworkMismatch => {
                common::Error::InvalidInput("device returned a key for the wrong network".into())
            }
            TrezorError::ActionCancelled => common::Error::AuthenticationRefused,
            TrezorError::Unsupported(s) => common::Error::InvalidInput(s.into()),
            TrezorError::UnsupportedDisplayAddress(s) => {
                common::Error::UnsupportedDisplayAddress(s.into())
            }
            TrezorError::InvalidInput(s) => common::Error::InvalidInput(s),
        }
    }
}
