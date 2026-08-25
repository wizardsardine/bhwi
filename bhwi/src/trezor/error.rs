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
    #[error("{0}")]
    Locked(&'static str),
    #[error("device returned a key for the wrong network")]
    NetworkMismatch,
    #[error("device refused the operation")]
    ActionCancelled,
    #[error("device is already initialized")]
    AlreadyInitialized,
    #[error("unsupported command: {0}")]
    Unsupported(&'static str),
    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(&'static str),
    #[error("Passphrase too long")]
    PassphraseTooLong,
    #[error("Non-numeric PIN provided")]
    NonNumericPin,
    #[error("{0}")]
    AlreadyUnlocked(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl TrezorError {
    pub const NO_PIN_NEEDED: &'static str = "This device does not need a PIN";
    pub const PIN_ALREADY_SENT: &'static str = "The PIN has already been sent to this device";
    pub const LOCKED: &'static str =
        "Trezor is locked. Unlock by using 'promptpin' and then 'sendpin'.";
}
