use core::convert::TryFrom;
use core::fmt::Debug;

// p2 encodes the protocol version implemented
pub const CURRENT_PROTOCOL_VERSION: u8 = 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cla {
    Default = 0xB0,
    Bitcoin = 0xE1,
    Framework = 0xF8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BitcoinCommandCode {
    GetExtendedPubkey = 0x00,
    GetVersion = 0x01,
    RegisterWallet = 0x02,
    GetWalletAddress = 0x03,
    SignPSBT = 0x04,
    GetMasterFingerprint = 0x05,
    SignMessage = 0x10,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameworkCommandCode {
    ContinueInterrupted = 0x01,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientCommandCode {
    Yield = 0x10,
    GetPreimage = 0x40,
    GetMerkleLeafProof = 0x41,
    GetMerkleLeafIndex = 0x42,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusWord {
    /// Rejected by user
    Deny = 0x6985,
    /// Incorrect Data
    IncorrectData = 0x6A80,
    /// Not Supported
    NotSupported = 0x6A82,
    /// Wrong P1P2
    WrongP1P2 = 0x6A86,
    /// Wrong DataLength
    WrongDataLength = 0x6A87,
    /// Ins not supported
    InsNotSupported = 0x6D00,
    /// Cla not supported
    ClaNotSupported = 0x6E00,
    /// Bad state
    BadState = 0xB007,
    /// Signature fail
    SignatureFail = 0xB008,
    /// Success
    OK = 0x9000,
    /// The command is interrupted, and requires the client's response
    InterruptedExecution = 0xE000,
}

impl TryFrom<u16> for StatusWord {
    type Error = ApduError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x6985 => Ok(StatusWord::Deny),
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
            _ => Err(ApduError::StatusWordUnknown),
        }
    }
}

#[derive(Clone)]
pub struct ApduCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl ApduCommand {
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

#[derive(Debug)]
pub struct ApduResponse {
    pub data: Vec<u8>,
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

#[derive(Debug)]
pub enum ApduError {
    StatusWordUnknown,
    ResponseTooShort,
}
