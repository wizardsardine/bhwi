//! Errors reported by BitBox02 devices and protocol helpers.
//!
// Error variants (`BitBoxDeviceError`) and their integer code mapping are ported
// from bitbox-api-rs (`src/error.rs`),
// Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
// Version 2.0 — see BITBOX_LICENSE at the repository root.

use thiserror::Error;

/// Errors returned by the BitBox02 device itself (protobuf `error.code`).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BitBoxDeviceError {
    /// An unrecognized device error code.
    #[error("error code not recognized")]
    Unknown(i32),
    /// Input rejected by the device.
    #[error("invalid input")]
    InvalidInput,
    /// A device memory error.
    #[error("memory")]
    Memory,
    /// An unspecified device failure.
    #[error("generic error")]
    Generic,
    /// An operation cancelled on the device.
    #[error("aborted by the user")]
    UserAbort,
    /// An endpoint invoked in the wrong device state.
    #[error("can't call this endpoint: wrong state")]
    InvalidState,
    /// A disabled device function.
    #[error("function disabled")]
    Disabled,
    /// An entry that already exists.
    #[error("duplicate entry")]
    Duplicate,
    /// Device-side Noise encryption failure.
    #[error("noise encryption failed")]
    NoiseEncrypt,
    /// Device-side Noise decryption failure.
    #[error("noise decryption failed")]
    NoiseDecrypt,
}

impl BitBoxDeviceError {
    /// Maps a firmware error code, returning [`Self::Unknown`] for unrecognized codes.
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
            _ => Self::Unknown(code),
        }
    }

    /// Returns the device's numeric error code.
    pub fn code(&self) -> i32 {
        match self {
            Self::InvalidInput => 101,
            Self::Memory => 102,
            Self::Generic => 103,
            Self::UserAbort => 104,
            Self::InvalidState => 105,
            Self::Disabled => 106,
            Self::Duplicate => 107,
            Self::NoiseEncrypt => 108,
            Self::NoiseDecrypt => 109,
            Self::Unknown(code) => *code,
        }
    }
}

/// Top-level BitBox integration error.
#[derive(Error, Debug)]
pub enum BitBoxError {
    /// A minimum firmware version requirement.
    #[error("firmware version {0} required")]
    Version(
        /// Required minimum firmware version.
        &'static str,
    ),
    /// An error reported by the device.
    #[error("bitbox device error: {0}")]
    Device(
        /// Device-reported failure.
        #[from]
        BitBoxDeviceError,
    ),
    /// A Noise session or handshake failure.
    #[error("noise channel error: {0}")]
    Noise(
        /// Failure context.
        &'static str,
    ),
    /// Invalid Noise configuration.
    #[error("noise config error: {0}")]
    NoiseConfig(
        /// Configuration failure description.
        String,
    ),
    /// Pairing rejected by the user.
    #[error("pairing code rejected by user")]
    NoisePairingRejected,
    /// A response incompatible with the current operation.
    #[error("BitBox returned an unexpected response")]
    UnexpectedResponse,
    /// Protobuf decoding failure.
    #[error("protobuf message could not be decoded: {0}")]
    ProtobufDecode(
        /// Decoder error description.
        String,
    ),
    /// Protobuf encoding failure.
    #[error("protobuf message could not be encoded: {0}")]
    ProtobufEncode(
        /// Encoder error description.
        String,
    ),
    /// Invalid or unsupported PSBT data.
    #[error("PSBT error: {0}")]
    Psbt(
        /// PSBT failure description.
        String,
    ),
    /// A malformed device signature.
    #[error("unexpected signature format returned by BitBox")]
    InvalidSignature,
    /// An anti-klepto nonce or verification failure.
    #[error("Antiklepto verification failed: {0}")]
    AntiKlepto(
        /// Nonce or verification failure description.
        String,
    ),
    /// A transaction signing preparation or protocol failure.
    #[error("Bitcoin transaction signing error: {0}")]
    BtcSign(
        /// Signing failure description.
        String,
    ),
    /// Invalid command input or missing context.
    #[error("invalid input: {0}")]
    InvalidInput(
        /// Invalid-input description.
        &'static str,
    ),
    /// A command missing caller-supplied data.
    #[error("missing command info: {0}")]
    MissingContext(&'static str),
    /// An operation the device cannot perform.
    #[error("missing command info: {0}")]
    Unsupported(&'static str),
    /// Setup attempted on an initialized device.
    #[error("The BitBox02 must be wiped before setup.")]
    AlreadyInitialized,
    /// An operation that needs an initialized device.
    #[error("The BitBox02 must be initialized first.")]
    NotInitialized,
    /// An address format unsupported by this adapter.
    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(
        /// Unsupported-format description.
        &'static str,
    ),
    /// Invalid communication framing.
    #[error("communication framing error: {0}")]
    Framing(
        /// Framing failure description.
        &'static str,
    ),
    /// A transport failure.
    #[error("transport error: {0}")]
    Transport(
        /// Transport failure description.
        String,
    ),
    /// The device disconnected.
    #[error("transport error: {0}")]
    Disconnected(String),
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
