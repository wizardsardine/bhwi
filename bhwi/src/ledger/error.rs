use core::fmt::Debug;

use super::{apdu::StatusWord, store::StoreError};

#[derive(Debug)]
pub enum BitcoinClientError<T: Debug> {
    ClientError(String),
    InvalidPsbt,
    Transport(T),
    Store(StoreError),
    Device { command: u8, status: StatusWord },
    UnexpectedResult { command: u8, data: Vec<u8> },
    InvalidResponse(String),
    UnsupportedAppVersion,
}

impl<T: Debug> From<StoreError> for BitcoinClientError<T> {
    fn from(e: StoreError) -> BitcoinClientError<T> {
        BitcoinClientError::Store(e)
    }
}
