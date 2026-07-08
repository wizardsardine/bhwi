// Error variants (`BitBoxDeviceError`) and their integer code mapping are ported
// from bitbox-api-rs (`src/error.rs`),
// Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
// Version 2.0 — see BITBOX_LICENSE at the repository root.

use thiserror::Error;

/// Errors returned by the BitBox02 device itself (protobuf `error.code`).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BitBoxDeviceError {
    #[error("error code not recognized")]
    Unknown,
    #[error("invalid input")]
    InvalidInput,
    #[error("memory")]
    Memory,
    #[error("generic error")]
    Generic,
    #[error("aborted by the user")]
    UserAbort,
    #[error("can't call this endpoint: wrong state")]
    InvalidState,
    #[error("function disabled")]
    Disabled,
    #[error("duplicate entry")]
    Duplicate,
    #[error("noise encryption failed")]
    NoiseEncrypt,
    #[error("noise decryption failed")]
    NoiseDecrypt,
}

impl BitBoxDeviceError {
    pub fn from_code(code: i32) -> Self {
        match code {
            101 => Self::InvalidInput,
            102 => Self::Memory,
            103 => Self::Generic,
            104 => Self::UserAbort,
            105 => Self::InvalidState,
            106 => Self::Disabled,
            107 => Self::Duplicate,
            108 => Self::NoiseEncrypt,
            109 => Self::NoiseDecrypt,
            _ => Self::Unknown,
        }
    }
}

/// Top-level BitBox integration error.
#[derive(Error, Debug)]
pub enum BitBoxError {
    #[error("firmware version {0} required")]
    Version(&'static str),
    #[error("bitbox device error: {0}")]
    Device(#[from] BitBoxDeviceError),
    #[error("noise channel error: {0}")]
    Noise(&'static str),
    #[error("noise config error: {0}")]
    NoiseConfig(String),
    #[error("pairing code rejected by user")]
    NoisePairingRejected,
    #[error("BitBox returned an unexpected response")]
    UnexpectedResponse,
    #[error("protobuf message could not be decoded: {0}")]
    ProtobufDecode(String),
    #[error("protobuf message could not be encoded: {0}")]
    ProtobufEncode(String),
    #[error("failed parsing keypath: {0}")]
    KeypathParse(String),
    #[error("PSBT error: {0}")]
    Psbt(String),
    #[error("unexpected signature format returned by BitBox")]
    InvalidSignature,
    #[error("Antiklepto verification failed: {0}")]
    AntiKlepto(String),
    #[error("Bitcoin transaction signing error: {0}")]
    BtcSign(String),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("communication framing error: {0}")]
    Framing(&'static str),
    #[error("transport error: {0}")]
    Transport(String),
}

impl From<prost::DecodeError> for BitBoxError {
    fn from(e: prost::DecodeError) -> Self {
        BitBoxError::ProtobufDecode(e.to_string())
    }
}

impl From<prost::EncodeError> for BitBoxError {
    fn from(e: prost::EncodeError) -> Self {
        BitBoxError::ProtobufEncode(e.to_string())
    }
}
