//! Sans-I/O hardware-wallet protocols and shared commands.
//!
//! Interpreters produce messages for the caller to route and consume responses without
//! performing transport I/O. The [`common`] module provides device-independent commands,
//! responses, and routing information; device modules expose their native protocols.

pub use bitcoin;
pub use miniscript;

#[cfg(feature = "bitbox")]
pub mod bitbox;
#[cfg(feature = "coldcard")]
pub mod coldcard;
pub mod common;
pub mod device;
#[cfg(feature = "jade")]
pub mod jade;
#[cfg(feature = "keepkey")]
pub mod keepkey;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(any(feature = "trezor", feature = "keepkey"))]
pub mod passphrase;
pub mod policy;
#[cfg(feature = "specter")]
pub mod specter;
#[cfg(feature = "trezor")]
pub mod trezor;

/// A sans-I/O state machine for one hardware-wallet operation.
///
/// Call [`start`](Self::start), route its transmission, and pass received bytes to
/// [`exchange`](Self::exchange), repeating whenever another transmission is returned.
/// Consume the interpreter with [`end`](Self::end) to obtain the final result.
/// An `exchange` result of `None` means no next transmission, not necessarily completion:
/// Specter-DIY also returns `None` while waiting for the rest of a framed response.
pub trait Interpreter {
    /// The operation and its caller-supplied inputs.
    type Command;
    /// An outgoing message, including any routing information.
    type Transmit;
    /// The completed operation's result.
    type Response;
    /// An error in command conversion or protocol processing.
    type Error;
    /// Starts an operation and returns its initial transmission.
    ///
    /// Supported commands and required context depend on the interpreter.
    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error>;
    /// Consumes received bytes and returns the next transmission, if any.
    ///
    /// `None` does not universally indicate completion; an interpreter may still need
    /// more response bytes. Follow the device protocol's framing contract before
    /// calling [`end`](Self::end).
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error>;
    /// Consumes the interpreter and returns the completed operation's result.
    ///
    /// Returns an error if no final result is available.
    fn end(self) -> Result<Self::Response, Self::Error>;
}
