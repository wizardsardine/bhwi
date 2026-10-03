//! Generic errors for Ledger Bitcoin clients.

use core::fmt::Debug;

use super::{apdu::StatusWord, store::StoreError};

/// A client, transport, delegated-store, or application error.
#[derive(Debug)]
pub enum BitcoinClientError<T: Debug> {
    /// Client-side protocol failure.
    ClientError(
        /// Protocol failure description.
        String,
    ),
    /// Invalid PSBT data.
    InvalidPsbt,
    /// Transport-specific failure.
    Transport(
        /// Transport-specific error.
        T,
    ),
    /// Failure answering a delegated data request.
    Store(
        /// Delegated-store error.
        StoreError,
    ),
    /// Application failure for an instruction.
    Device {
        /// Instruction byte.
        command: u8,
        /// Application response status.
        status: StatusWord,
    },
    /// Unexpected response bytes for an instruction.
    UnexpectedResult {
        /// Instruction byte.
        command: u8,
        /// Unexpected response bytes.
        data: Vec<u8>,
    },
    /// Malformed application response.
    InvalidResponse(
        /// Invalid-response description.
        String,
    ),
    /// An application version unsupported by the client.
    UnsupportedAppVersion,
}

impl<T: Debug> From<StoreError> for BitcoinClientError<T> {
    fn from(e: StoreError) -> BitcoinClientError<T> {
        BitcoinClientError::Store(e)
    }
}
