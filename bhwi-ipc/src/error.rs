use std::error::Error as StdError;
use std::fmt::{self, Display};

use bhwi_async::ErrorKind;
use bhwi_async::device::classify_error;

pub use crate::bhwi_capnp::ErrorCode;
use crate::bhwi_capnp::{error as wire_error, result};

/// Every wire error code.
pub const ALL_CODES: [ErrorCode; 27] = [
    ErrorCode::UserCancelled,
    ErrorCode::AuthenticationRefused,
    ErrorCode::HostUnavailable,
    ErrorCode::Locked,
    ErrorCode::NotReady,
    ErrorCode::Busy,
    ErrorCode::AlreadyUnlocked,
    ErrorCode::NotInitialized,
    ErrorCode::AlreadyInitialized,
    ErrorCode::WrongPin,
    ErrorCode::WrongNetwork,
    ErrorCode::Duplicate,
    ErrorCode::Unsupported,
    ErrorCode::UnsupportedDisplayAddress,
    ErrorCode::MissingContext,
    ErrorCode::InvalidInput,
    ErrorCode::Rejected,
    ErrorCode::DeviceFailure,
    ErrorCode::Protocol,
    ErrorCode::UnexpectedResponse,
    ErrorCode::Serialization,
    ErrorCode::Encryption,
    ErrorCode::Transport,
    ErrorCode::Disconnected,
    ErrorCode::Other,
    ErrorCode::NoDevice,
    ErrorCode::BadArgument,
];

/// Returns a code's name as written in the schema.
pub fn code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::UserCancelled => "userCancelled",
        ErrorCode::AuthenticationRefused => "authenticationRefused",
        ErrorCode::HostUnavailable => "hostUnavailable",
        ErrorCode::Locked => "locked",
        ErrorCode::NotReady => "notReady",
        ErrorCode::Busy => "busy",
        ErrorCode::AlreadyUnlocked => "alreadyUnlocked",
        ErrorCode::NotInitialized => "notInitialized",
        ErrorCode::AlreadyInitialized => "alreadyInitialized",
        ErrorCode::WrongPin => "wrongPin",
        ErrorCode::WrongNetwork => "wrongNetwork",
        ErrorCode::Duplicate => "duplicate",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::UnsupportedDisplayAddress => "unsupportedDisplayAddress",
        ErrorCode::MissingContext => "missingContext",
        ErrorCode::InvalidInput => "invalidInput",
        ErrorCode::Rejected => "rejected",
        ErrorCode::DeviceFailure => "deviceFailure",
        ErrorCode::Protocol => "protocol",
        ErrorCode::UnexpectedResponse => "unexpectedResponse",
        ErrorCode::Serialization => "serialization",
        ErrorCode::Encryption => "encryption",
        ErrorCode::Transport => "transport",
        ErrorCode::Disconnected => "disconnected",
        ErrorCode::Other => "other",
        ErrorCode::NoDevice => "noDevice",
        ErrorCode::BadArgument => "badArgument",
    }
}

/// A failure returned to the client as an `error` result.
#[derive(Debug)]
pub struct Failure {
    /// The wire error code.
    pub code: ErrorCode,
    /// The message shown to the client.
    pub message: String,
}

impl Failure {
    /// Creates a failure with `code` and `message`.
    pub fn new(code: ErrorCode, message: impl Display) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }

    fn fill(&self, mut builder: wire_error::Builder<'_>) {
        builder.set_code(self.code);
        builder.set_message(&self.message);
    }
}

impl Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", code_name(self.code), self.message)
    }
}

impl StdError for Failure {}

/// A request field the server cannot read is a bad argument: invalid UTF-8, or
/// an enum value from a newer schema.
impl From<capnp::Error> for Failure {
    fn from(err: capnp::Error) -> Self {
        bad_argument(err)
    }
}

impl From<capnp::NotInSchema> for Failure {
    fn from(err: capnp::NotInSchema) -> Self {
        bad_argument(err)
    }
}

impl From<std::str::Utf8Error> for Failure {
    fn from(err: std::str::Utf8Error) -> Self {
        bad_argument(err)
    }
}

/// Creates a `badArgument` failure.
pub fn bad_argument(message: impl Display) -> Failure {
    Failure::new(ErrorCode::BadArgument, message)
}

/// Returns the wire code for an error kind.
pub fn kind_code(kind: ErrorKind) -> ErrorCode {
    match kind {
        ErrorKind::UserCancelled => ErrorCode::UserCancelled,
        ErrorKind::AuthenticationRefused => ErrorCode::AuthenticationRefused,
        ErrorKind::HostUnavailable => ErrorCode::HostUnavailable,
        ErrorKind::Locked => ErrorCode::Locked,
        ErrorKind::NotReady => ErrorCode::NotReady,
        ErrorKind::Busy => ErrorCode::Busy,
        ErrorKind::AlreadyUnlocked => ErrorCode::AlreadyUnlocked,
        ErrorKind::NotInitialized => ErrorCode::NotInitialized,
        ErrorKind::AlreadyInitialized => ErrorCode::AlreadyInitialized,
        ErrorKind::WrongPin => ErrorCode::WrongPin,
        ErrorKind::WrongNetwork => ErrorCode::WrongNetwork,
        ErrorKind::Duplicate => ErrorCode::Duplicate,
        ErrorKind::Unsupported => ErrorCode::Unsupported,
        ErrorKind::UnsupportedDisplayAddress => ErrorCode::UnsupportedDisplayAddress,
        ErrorKind::MissingContext => ErrorCode::MissingContext,
        ErrorKind::InvalidInput => ErrorCode::InvalidInput,
        ErrorKind::Rejected => ErrorCode::Rejected,
        ErrorKind::DeviceFailure => ErrorCode::DeviceFailure,
        ErrorKind::Protocol => ErrorCode::Protocol,
        ErrorKind::UnexpectedResponse => ErrorCode::UnexpectedResponse,
        ErrorKind::Serialization => ErrorCode::Serialization,
        ErrorKind::Encryption => ErrorCode::Encryption,
        ErrorKind::Transport => ErrorCode::Transport,
        ErrorKind::Disconnected => ErrorCode::Disconnected,
        _ => ErrorCode::Other,
    }
}

/// Converts a device error, keeping a client's refusal code if one is in its chain.
pub fn device(err: &(dyn StdError + 'static)) -> Failure {
    let mut source = Some(err);
    while let Some(current) = source {
        if let Some(failure) = current.downcast_ref::<Failure>() {
            return Failure::new(failure.code, &failure.message);
        }
        source = current.source();
    }
    let error = classify_error(err);
    Failure::new(kind_code(error.kind()), error.message())
}

/// A client refuses a prompt by raising `"<code>: <message>"`, so its code
/// survives the exception.
pub fn prompter(err: capnp::Error) -> Failure {
    match raised(&err) {
        Some((code, message)) => Failure::new(code, message),
        None => Failure::new(ErrorCode::Other, err),
    }
}

fn raised(err: &capnp::Error) -> Option<(ErrorCode, &str)> {
    // capnp-rpc prefixes every exception received from the peer.
    let extra = err
        .extra
        .strip_prefix("remote exception: ")
        .unwrap_or(&err.extra);
    let (name, message) = extra.split_once(": ")?;
    let code = ALL_CODES
        .into_iter()
        .find(|code| code_name(*code) == name)?;
    Some((code, message))
}

/// Writes an outcome into a `Result`: the `ok` arm through `fill_ok`, or the `error` arm.
pub fn reply<Ok: capnp::traits::Owned, T>(
    builder: result::Builder<'_, Ok>,
    outcome: Result<T, Failure>,
    fill_ok: impl FnOnce(result::Builder<'_, Ok>, T) -> Result<(), capnp::Error>,
) -> Result<(), capnp::Error> {
    match outcome {
        Ok(value) => fill_ok(builder, value),
        Err(failure) => {
            failure.fill(builder.init_error());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_prompt_keeps_its_code_through_the_device_layer() {
        let refused = Failure::new(ErrorCode::UserCancelled, "closed the dialog");
        let failure = device(&bhwi_async::HWIDeviceError::new(refused));
        assert_eq!(failure.code, ErrorCode::UserCancelled);
        assert_eq!(failure.message, "closed the dialog");
    }

    #[test]
    fn a_refusal_keeps_its_code() {
        for code in ALL_CODES {
            for prefix in ["", "remote exception: "] {
                let raised =
                    capnp::Error::failed(format!("{prefix}{}: why it happened", code_name(code)));
                let failure = prompter(raised);
                assert_eq!(failure.code, code, "{prefix}{}", code_name(code));
                assert_eq!(failure.message, "why it happened");
            }
        }
    }

    #[test]
    fn an_uncoded_refusal_is_other() {
        let failure = prompter(capnp::Error::failed("no prefix".into()));
        assert_eq!(failure.code, ErrorCode::Other);
    }

    // Add each new `ErrorKind` here, with a schema code of the same name.
    #[test]
    fn every_error_kind_has_its_own_code() {
        let kinds = [
            ErrorKind::UserCancelled,
            ErrorKind::AuthenticationRefused,
            ErrorKind::HostUnavailable,
            ErrorKind::Locked,
            ErrorKind::NotReady,
            ErrorKind::Busy,
            ErrorKind::AlreadyUnlocked,
            ErrorKind::NotInitialized,
            ErrorKind::AlreadyInitialized,
            ErrorKind::WrongPin,
            ErrorKind::WrongNetwork,
            ErrorKind::Duplicate,
            ErrorKind::Unsupported,
            ErrorKind::UnsupportedDisplayAddress,
            ErrorKind::MissingContext,
            ErrorKind::InvalidInput,
            ErrorKind::Rejected,
            ErrorKind::DeviceFailure,
            ErrorKind::Protocol,
            ErrorKind::UnexpectedResponse,
            ErrorKind::Serialization,
            ErrorKind::Encryption,
            ErrorKind::Transport,
            ErrorKind::Disconnected,
            ErrorKind::Other,
        ];
        for kind in kinds {
            let mut expected = format!("{kind:?}");
            expected[..1].make_ascii_lowercase();
            assert_eq!(code_name(kind_code(kind)), expected);
        }
    }
}
