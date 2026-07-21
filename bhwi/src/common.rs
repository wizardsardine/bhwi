#[cfg(feature = "bitbox")]
use crate::bitbox;
use crate::miniscript::descriptor::{DescriptorPublicKey, WalletPolicy};
use crate::{coldcard, jade, ledger};
use bitcoin::Network;
use bitcoin::address::AddressType;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;

#[derive(Default)]
pub struct UnlockOptions {
    pub network: Option<Network>,
}

#[derive(Clone, Debug)]
pub enum DisplayAddress {
    ByPath {
        path: DerivationPath,
        display: bool,
        address_format: Option<AddressType>,
    },
    ByDescriptor {
        index: u32,
        change: bool,
        display: bool,
        descriptor_name: String,
    },
    /// Display a multisig address from the same inputs as Python HWI's
    /// `display_multisig_address(addr_type, multisig)` API.
    ByMultisig(MultisigDisplayAddress),
}

/// Sans-I/O representation of Python HWI's `AddressType` and
/// `MultisigDescriptor` arguments to `display_multisig_address`.
///
/// `threshold`, `sorted`, and `keys` correspond to HWI's
/// `MultisigDescriptor.thresh`, `is_sorted`, and `pubkeys`, respectively.
#[derive(Clone, Debug)]
pub struct MultisigDisplayAddress {
    /// Number of keys required to authorize a spend.
    pub threshold: u8,
    /// Script wrapper used to derive the address.
    pub address_type: MultisigAddressType,
    /// Whether keys use BIP67 sorting (`sortedmulti` rather than `multi`).
    pub sorted: bool,
    /// Descriptor keys, including origins and concrete address derivations.
    pub keys: Vec<DescriptorPublicKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum MultisigAddressType {
    /// Legacy P2SH multisig.
    Legacy,
    /// P2SH-wrapped P2WSH multisig.
    ShWit,
    /// Native P2WSH multisig.
    Wit,
}

#[allow(clippy::large_enum_variant)]
pub enum Command {
    Backup,
    GetMasterFingerprint,
    GetVersion,
    GetXpub {
        path: DerivationPath,
        display: bool,
    },
    DisplayAddress(DisplayAddress, Option<DeviceContext>),
    RegisterWallet {
        name: String,
        policy: WalletPolicy,
    },
    SignTx(Psbt, Option<DeviceContext>),
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    Unlock {
        options: UnlockOptions,
    },
}

/// Device-specific context data required by certain commands.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum DeviceContext {
    /// Required contexts for Ledger devices
    Ledger {
        wallet_policy: ledger::LedgerWalletPolicy,
        wallet_hmac: Option<[u8; 32]>,
    },
    /// Required context for BitBox02 descriptor-based address display: the wallet policy
    /// (with key origins) of the registered descriptor.
    #[cfg(feature = "bitbox")]
    BitBox { policy: WalletPolicy },
}

pub enum Response {
    Backup(DeviceBackup),
    TaskDone,
    TaskBusy,
    Info(Info),
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    EncryptionKey([u8; 64]),
    Signature(u8, Signature),
    SignedPsbt(Psbt),
    Address(String),
    WalletRegistration(WalletRegistration),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletRegistration {
    Complete { hmac: Option<[u8; 32]> },
    PendingUserConfirmation,
}

impl WalletRegistration {
    pub fn hmac(self) -> Option<[u8; 32]> {
        match self {
            Self::Complete { hmac } => hmac,
            Self::PendingUserConfirmation => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceBackup {
    Complete,
    File(Vec<u8>),
}

/// Device Information
#[derive(Debug, Clone, Default)]
pub struct Info {
    pub version: String,
    pub networks: Vec<Network>,
    pub firmware: Option<String>,
}

pub enum Recipient {
    Device,
    PinServer { url: String },
}

pub struct Transmit {
    pub recipient: Recipient,
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encryption error: {0}")]
    Encryption(&'static str),

    #[error("no error or result returned")]
    NoErrorOrResult,

    #[error("missing command info: {0}")]
    MissingCommandInfo(&'static str),

    #[error("{0}")]
    Device(String),

    #[error("unexpected result for {1}: {0:x?}")]
    UnexpectedResult(Vec<u8>, String),

    #[error("rpc error {0}: {1:?}")]
    Rpc(i32, Option<String>),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("request error: {0}")]
    Request(&'static str),

    #[error("authentication refused")]
    AuthenticationRefused,

    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(String),
}

impl Error {
    pub fn unexpected_result(data: Vec<u8>, context: impl Into<String>) -> Self {
        Error::UnexpectedResult(data, context.into())
    }
}

#[cfg(feature = "bitbox")]
pub type BitBoxInterpreter<'a> = bitbox::BitBoxInterpreter<'a, Command, Transmit, Response, Error>;
pub type ColdcardInterpreter<'a> =
    coldcard::ColdcardInterpreter<'a, Command, Transmit, Response, Error>;
pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response, Error>;
pub type LedgerInterpreter = ledger::LedgerInterpreter<Command, Transmit, Response, Error>;

impl From<Vec<u8>> for Transmit {
    fn from(payload: Vec<u8>) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload,
            encrypted: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Interpreter;

    #[test]
    fn common_interpreter_is_satisfied() {
        let interpreters: Vec<
            Box<
                dyn Interpreter<
                        Command = super::Command,
                        Transmit = super::Transmit,
                        Response = super::Response,
                        Error = super::Error,
                    >,
            >,
        > = vec![
            Box::<LedgerInterpreter>::default(),
            Box::<JadeInterpreter>::default(),
        ];
        assert_eq!(interpreters.len(), 2);
    }
}
