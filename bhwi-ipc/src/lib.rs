//! A Cap'n Proto server that gives other programs access to hardware wallets.
//!
//! Clients connect over a Unix socket and use the interface in `schema/bhwi.capnp`.
//! Expected failures return an `error` result with an `ErrorCode`.

/// Generated Cap'n Proto types for `schema/bhwi.capnp`.
pub mod bhwi_capnp {
    #![allow(clippy::all, missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/bhwi_capnp.rs"));
}

/// Conversions between wire types and bhwi types.
pub mod convert;
/// The `Device` capability served for one held device.
pub mod device;
/// Wire error codes and the failures that carry them.
pub mod error;
/// Unix socket binding and the accept loop.
#[cfg(unix)]
pub mod listener;
/// The client's `Prompter` capability, called while a command runs.
pub mod prompt;
/// Which devices are held, so each has one client at a time.
pub mod registry;
/// The top-level `Bhwi` capability that lists and opens devices.
pub mod server;
/// The state shared by one held device's capabilities.
pub mod session;
/// The `Signing` capability for one PSBT signing run.
pub mod signing;
