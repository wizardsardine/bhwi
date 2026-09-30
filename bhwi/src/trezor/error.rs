//! Errors shared by Trezor and KeepKey protocol interpretation.

/// A Trezor or KeepKey device, input, or protocol error.
#[derive(Debug, thiserror::Error)]
pub enum TrezorError {
    /// Protobuf decoding failure.
    #[error("protobuf decode error: {0}")]
    Decode(
        /// Protobuf decoder error.
        #[from]
        prost::DecodeError,
    ),
    /// Invalid or incomplete message framing.
    #[error("malformed device message frame")]
    MalformedFrame,
    /// Unexpected wire message identifier and the operation expecting it.
    #[error("unexpected device message type {0} while {1}")]
    UnexpectedMessage(
        /// Received wire message identifier.
        u16,
        /// Operation that expected another message.
        &'static str,
    ),
    /// Device failure code and message.
    #[error("device failure: {1}")]
    Failure(
        /// Device failure code.
        Option<i32>,
        /// Device failure message.
        String,
    ),
    /// A locked device requiring host PIN entry.
    #[error("{0}")]
    Locked(
        /// Host PIN-entry instructions.
        &'static str,
    ),
    /// An extended key encoded for a different network family.
    #[error("device returned a key for the wrong network")]
    NetworkMismatch,
    /// An operation refused or cancelled by the device.
    #[error("device refused the operation")]
    ActionCancelled(i32),
    /// Setup or restore attempted on an initialized device.
    #[error("device is already initialized")]
    AlreadyInitialized,
    /// An unsupported command or missing management context.
    #[error("unsupported command: {0}")]
    Unsupported(
        /// Unsupported operation or missing context.
        &'static str,
    ),
    /// A management command missing caller-supplied data.
    #[error("unsupported command: {0}")]
    MissingContext(&'static str),
    /// An unsupported address-display request.
    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(
        /// Unsupported-display description.
        &'static str,
    ),
    /// A host passphrase exceeding 50 normalized UTF-8 bytes.
    #[error("Passphrase too long")]
    PassphraseTooLong,
    /// Empty or non-ASCII-digit PIN positions.
    #[error("Non-numeric PIN provided")]
    NonNumericPin,
    /// A PIN operation unnecessary for an already unlocked device.
    #[error("{0}")]
    AlreadyUnlocked(
        /// Reason no PIN operation is required.
        &'static str,
    ),
    /// Invalid or unsupported command data.
    #[error("invalid input: {0}")]
    InvalidInput(
        /// Invalid-input description.
        String,
    ),
}

impl TrezorError {
    /// Error message when a device has no PIN protection.
    pub const NO_PIN_NEEDED: &'static str = "This device does not need a PIN";
    /// Error message when a PIN is already cached.
    pub const PIN_ALREADY_SENT: &'static str = "The PIN has already been sent to this device";
    /// Error message for a locked Trezor requiring host PIN entry.
    pub const LOCKED: &'static str =
        "Trezor is locked. Unlock by using 'promptpin' and then 'sendpin'.";
}
