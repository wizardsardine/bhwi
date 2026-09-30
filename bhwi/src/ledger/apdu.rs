//! Ledger APDU envelopes, command codes, and response status words.

use core::convert::TryFrom;
use core::fmt::Debug;

/// Protocol version encoded in the APDU `p2` parameter.
pub const CURRENT_PROTOCOL_VERSION: u8 = 1;

/// Ledger APDU command classes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cla {
    /// Application-independent commands.
    Default = 0xB0,
    /// Bitcoin application commands.
    Bitcoin = 0xE1,
    /// Framework commands for interrupted execution.
    Framework = 0xF8,
}

/// Bitcoin application instruction identifiers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BitcoinCommandCode {
    /// Extended-public-key retrieval.
    GetExtendedPubkey = 0x00,
    /// Application information retrieval.
    GetVersion = 0x01,
    /// Wallet policy registration.
    RegisterWallet = 0x02,
    /// Wallet address retrieval.
    GetWalletAddress = 0x03,
    /// PSBT signing.
    SignPSBT = 0x04,
    /// Master fingerprint retrieval.
    GetMasterFingerprint = 0x05,
    /// Message signing.
    SignMessage = 0x10,
}

/// Framework instruction identifiers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameworkCommandCode {
    /// Resumes execution with a response to a delegated request.
    ContinueInterrupted = 0x01,
}

/// Host commands requested during interrupted application execution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientCommandCode {
    /// Records a value yielded by the device.
    Yield = 0x10,
    /// Requests a known hash preimage.
    GetPreimage = 0x40,
    /// Requests a Merkle leaf and proof.
    GetMerkleLeafProof = 0x41,
    /// Requests a leaf's index in a known Merkle tree.
    GetMerkleLeafIndex = 0x42,
    /// Requests queued proof or preimage fragments.
    GetMoreElements = 0xA0,
}

impl TryFrom<u8> for ClientCommandCode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x10 => Ok(ClientCommandCode::Yield),
            0x40 => Ok(ClientCommandCode::GetPreimage),
            0x41 => Ok(ClientCommandCode::GetMerkleLeafProof),
            0x42 => Ok(ClientCommandCode::GetMerkleLeafIndex),
            0xA0 => Ok(ClientCommandCode::GetMoreElements),
            _ => Err(()),
        }
    }
}

/// Recognized Ledger response status words.
///
/// The interpreter maps [`Self::Deny`], [`Self::SecurityStatusNotSatisfied`],
/// and [`Self::UserRefusedOnDevice`] to user cancellation only on operations
/// that check for it, such as signing, wallet registration, address display,
/// and opening an app. Xpub and application-info requests instead report
/// unexpected-result errors for these statuses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusWord {
    /// Rejected by the user.
    Deny = 0x6985,
    /// Security status not satisfied.
    SecurityStatusNotSatisfied = 0x6982,
    /// User refusal on Stax or Flex.
    UserRefusedOnDevice = 0x5501,
    /// Incorrect command data.
    IncorrectData = 0x6A80,
    /// Unsupported operation.
    NotSupported = 0x6A82,
    /// Invalid `p1` or `p2` parameter.
    WrongP1P2 = 0x6A86,
    /// Invalid data length.
    WrongDataLength = 0x6A87,
    /// Unsupported instruction.
    InsNotSupported = 0x6D00,
    /// Unsupported command class.
    ClaNotSupported = 0x6E00,
    /// Invalid application state.
    BadState = 0xB007,
    /// Signature failure.
    SignatureFail = 0xB008,
    /// Command not allowed.
    CommandNotAllowed = 0x6901,
    /// Successful completion.
    OK = 0x9000,
    /// Execution interrupted to request a host response.
    InterruptedExecution = 0xE000,
}

impl TryFrom<u16> for StatusWord {
    type Error = ApduError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x6985 => Ok(StatusWord::Deny),
            0x6982 => Ok(StatusWord::SecurityStatusNotSatisfied),
            0x5501 => Ok(StatusWord::UserRefusedOnDevice),
            0x6901 => Ok(StatusWord::CommandNotAllowed),
            0x6A80 => Ok(StatusWord::IncorrectData),
            0x6A82 => Ok(StatusWord::NotSupported),
            0x6A86 => Ok(StatusWord::WrongP1P2),
            0x6A87 => Ok(StatusWord::WrongDataLength),
            0x6D00 => Ok(StatusWord::InsNotSupported),
            0x6E00 => Ok(StatusWord::ClaNotSupported),
            0xB007 => Ok(StatusWord::BadState),
            0xB008 => Ok(StatusWord::SignatureFail),
            0x9000 => Ok(StatusWord::OK),
            0xE000 => Ok(StatusWord::InterruptedExecution),
            _ => Err(ApduError::StatusWordUnknown(value)),
        }
    }
}

/// A Ledger APDU command with a short data-length header.
#[derive(Clone)]
pub struct ApduCommand {
    /// Command class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// First instruction parameter.
    pub p1: u8,
    /// Second instruction parameter, usually the protocol version.
    pub p2: u8,
    /// Command data bytes.
    pub data: Vec<u8>,
}

impl ApduCommand {
    /// Encodes the header and command data.
    ///
    /// The data length is cast to `u8` without validation; callers must ensure
    /// it fits the short APDU format.
    pub fn encode(&self) -> Vec<u8> {
        let mut vec = vec![self.cla, self.ins, self.p1, self.p2, self.data.len() as u8];
        vec.extend(self.data.iter());
        vec
    }
}

impl core::default::Default for ApduCommand {
    fn default() -> Self {
        Self {
            cla: Cla::Default as u8,
            ins: 0x00,
            p1: 0x00,
            p2: CURRENT_PROTOCOL_VERSION,
            data: Vec::new(),
        }
    }
}

/// A Ledger APDU response decoded from data followed by a two-byte status word.
#[derive(Debug)]
pub struct ApduResponse {
    /// Response bytes without the trailing status word.
    pub data: Vec<u8>,
    /// Recognized response status.
    pub status_word: StatusWord,
}

impl From<ApduResponse> for Vec<u8> {
    fn from(res: ApduResponse) -> Vec<u8> {
        let mut vec = res.data;
        vec.extend((res.status_word as u16).to_be_bytes().to_vec().iter());
        vec
    }
}

impl TryFrom<Vec<u8>> for ApduResponse {
    type Error = ApduError;
    fn try_from(res: Vec<u8>) -> Result<Self, Self::Error> {
        if res.len() < 2 {
            return Err(ApduError::ResponseTooShort);
        }
        let s = u16::from_be_bytes([res[res.len() - 2], res[res.len() - 1]]);
        let status_word = StatusWord::try_from(s)?;

        Ok(ApduResponse {
            data: res[0..res.len() - 2].to_vec(),
            status_word,
        })
    }
}

/// APDU response decoding errors.
#[derive(Debug, thiserror::Error)]
pub enum ApduError {
    /// A status word not recognized by [`StatusWord`].
    #[error("unknown status word 0x{0:04x}")]
    StatusWordUnknown(u16),

    /// A response missing its two-byte status word.
    #[error("response too short")]
    ResponseTooShort,
}
