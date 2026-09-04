#[cfg(feature = "bitbox")]
use crate::bitbox;
#[cfg(feature = "coldcard")]
use crate::coldcard;
#[cfg(feature = "jade")]
use crate::jade;
#[cfg(feature = "keepkey")]
use crate::keepkey;
#[cfg(feature = "ledger")]
use crate::ledger;
use crate::miniscript::descriptor::{DescriptorPublicKey, WalletPolicy};
#[cfg(feature = "trezor")]
use crate::trezor;
use bitcoin::Network;
use bitcoin::address::AddressType;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;

mod adapters;

#[derive(Default)]
pub struct UnlockOptions {
    pub network: Option<Network>,
}

#[derive(Clone, Debug, Default)]
pub struct SetupOptions {
    pub label: String,
    pub backup_passphrase: String,
}

#[derive(Clone, Debug)]
pub struct RestoreOptions {
    pub label: String,
    pub word_count: i32,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            label: String::new(),
            word_count: 24,
        }
    }
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
    Setup(SetupOptions, Option<DeviceContext>),
    Wipe,
    Restore(RestoreOptions, Option<DeviceContext>),
    TogglePassphrase,
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
    PromptPin,
    SendPin(Option<DeviceContext>),
}

/// Device-specific context data required by certain commands.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum DeviceContext {
    /// Required contexts for Ledger devices
    #[cfg(feature = "ledger")]
    Ledger {
        wallet_policy: ledger::LedgerWalletPolicy,
        wallet_hmac: Option<[u8; 32]>,
    },
    /// Required context for BitBox02 descriptor-based address display: the wallet policy
    /// (with key origins) of the registered descriptor.
    #[cfg(feature = "bitbox")]
    BitBox { policy: WalletPolicy },
    /// Required context for BitBox02 setup and restore operations.
    #[cfg(feature = "bitbox")]
    BitBoxManagement(bitbox::ManagementContext),
    /// Required context for Trezor setup.
    #[cfg(feature = "trezor")]
    TrezorManagement(trezor::ManagementContext),
    /// Required context for KeepKey management commands.
    #[cfg(feature = "keepkey")]
    KeepKeyManagement(keepkey::ManagementContext),
}

pub enum Response {
    Backup(DeviceBackup),
    DeviceAction(bool),
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
    /// Whether the device has initialized wallet material, when reported by the firmware.
    pub initialized: Option<bool>,
    /// User-set device name, when the device protocol reports one.
    pub label: Option<String>,
    /// Whether the device can take a passphrase on its own screen, when it reports the capability.
    pub on_device_passphrase_entry: Option<bool>,
    /// Whether the device is waiting for a PIN from the host, when it reports a lock state.
    pub needs_pin_sent: Option<bool>,
    /// Whether the device expects the BIP39 passphrase from the host rather than its own screen.
    pub needs_passphrase_sent: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostRequest {
    PinMatrix {
        kind: PinMatrixRequestKind,
    },
    RecoveryCharacter {
        word_position: u32,
        character_position: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinMatrixRequestKind {
    Current,
    NewFirst,
    NewSecond,
    Unknown(i32),
}

#[derive(Eq, PartialEq)]
pub enum HostResponse {
    PinPositions(String),
    RecoveryCharacter(char),
    RecoveryDelete,
    RecoveryNextWord,
    RecoveryDone,
}

impl core::fmt::Debug for HostResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PinPositions(_) => f.write_str("PinPositions(<redacted>)"),
            Self::RecoveryCharacter(_) => f.write_str("RecoveryCharacter(<redacted>)"),
            Self::RecoveryDelete => f.write_str("RecoveryDelete"),
            Self::RecoveryNextWord => f.write_str("RecoveryNextWord"),
            Self::RecoveryDone => f.write_str("RecoveryDone"),
        }
    }
}

fn zeroize_string(value: &mut String) {
    zeroize::Zeroize::zeroize(value);
}

impl HostResponse {
    pub fn into_bytes_for(self, request: &HostRequest) -> Result<Vec<u8>, Error> {
        match (request, self) {
            (HostRequest::PinMatrix { .. }, Self::PinPositions(mut positions)) => {
                if positions.is_empty() || !positions.bytes().all(|byte| byte.is_ascii_digit()) {
                    zeroize_string(&mut positions);
                    return Err(Error::InvalidInput(
                        "PIN positions must contain ASCII digits".into(),
                    ));
                }
                Ok(positions.into_bytes())
            }
            (HostRequest::RecoveryCharacter { .. }, Self::RecoveryCharacter(character)) => {
                if !character.is_ascii_lowercase() {
                    return Err(Error::InvalidInput(
                        "recovery cipher response must be one lowercase ASCII character".into(),
                    ));
                }
                Ok(vec![character as u8])
            }
            (
                HostRequest::RecoveryCharacter {
                    word_position,
                    character_position,
                },
                action,
            ) => {
                let byte = match action {
                    Self::RecoveryDelete if *word_position != 0 || *character_position != 0 => 0x08,
                    Self::RecoveryNextWord if *character_position >= 3 => b' ',
                    Self::RecoveryDone
                        if matches!(*word_position, 11 | 17 | 23) && *character_position >= 3 =>
                    {
                        b'\n'
                    }
                    Self::RecoveryDelete | Self::RecoveryNextWord | Self::RecoveryDone => {
                        return Err(Error::InvalidInput(
                            "recovery action is not valid at this position".into(),
                        ));
                    }
                    Self::PinPositions(mut positions) => {
                        zeroize_string(&mut positions);
                        return Err(Error::InvalidInput(
                            "host response does not match request".into(),
                        ));
                    }
                    Self::RecoveryCharacter(_) => {
                        return Err(Error::InvalidInput(
                            "host response does not match request".into(),
                        ));
                    }
                };
                Ok(vec![byte])
            }
            _ => Err(Error::InvalidInput(
                "host response does not match request".into(),
            )),
        }
    }
}

pub enum Recipient {
    Device,
    PinServer { url: String },
    Host(HostRequest),
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

    #[error("action canceled by the user")]
    UserCancelled,

    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(String),

    #[error("{0}")]
    DeviceAlreadyUnlocked(&'static str),
}

impl Error {
    pub fn unexpected_result(data: Vec<u8>, context: impl Into<String>) -> Self {
        Error::UnexpectedResult(data, context.into())
    }
}

#[cfg(feature = "bitbox")]
pub type BitBoxInterpreter<'a> = bitbox::BitBoxInterpreter<'a, Command, Transmit, Response, Error>;
#[cfg(feature = "coldcard")]
pub type ColdcardInterpreter<'a> =
    coldcard::ColdcardInterpreter<'a, Command, Transmit, Response, Error>;
#[cfg(feature = "jade")]
pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response, Error>;
#[cfg(feature = "ledger")]
pub type LedgerInterpreter = ledger::LedgerInterpreter<Command, Transmit, Response, Error>;
#[cfg(feature = "trezor")]
pub type TrezorInterpreter = trezor::TrezorInterpreter<Command, Transmit, Response, Error>;
#[cfg(feature = "keepkey")]
pub type KeepKeyInterpreter = keepkey::KeepKeyInterpreter<Command, Transmit, Response, Error>;

impl From<Vec<u8>> for Transmit {
    fn from(payload: Vec<u8>) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload,
            encrypted: false,
        }
    }
}

impl From<HostRequest> for Transmit {
    fn from(request: HostRequest) -> Self {
        Self {
            recipient: Recipient::Host(request),
            payload: Vec::new(),
            encrypted: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Interpreter;

    fn assert_interpreter<I>()
    where
        I: Interpreter<
                Command = super::Command,
                Transmit = super::Transmit,
                Response = super::Response,
                Error = super::Error,
            >,
    {
    }

    #[test]
    fn common_interpreters_are_satisfied() {
        #[cfg(feature = "bitbox")]
        assert_interpreter::<BitBoxInterpreter<'static>>();
        #[cfg(feature = "coldcard")]
        assert_interpreter::<ColdcardInterpreter<'static>>();
        #[cfg(feature = "jade")]
        assert_interpreter::<JadeInterpreter>();
        #[cfg(feature = "keepkey")]
        assert_interpreter::<KeepKeyInterpreter>();
        #[cfg(feature = "ledger")]
        assert_interpreter::<LedgerInterpreter>();
        #[cfg(feature = "trezor")]
        assert_interpreter::<TrezorInterpreter>();
    }

    #[test]
    fn host_response_validation_and_encoding() {
        let pin = HostRequest::PinMatrix {
            kind: PinMatrixRequestKind::Current,
        };
        assert_eq!(
            HostResponse::PinPositions("123".into())
                .into_bytes_for(&pin)
                .unwrap(),
            b"123"
        );
        assert!(matches!(
            HostResponse::PinPositions("".into()).into_bytes_for(&pin),
            Err(Error::InvalidInput(message))
                if message == "PIN positions must contain ASCII digits"
        ));
        assert!(matches!(
            HostResponse::PinPositions("１２３".into()).into_bytes_for(&pin),
            Err(Error::InvalidInput(message))
                if message == "PIN positions must contain ASCII digits"
        ));

        let first = HostRequest::RecoveryCharacter {
            word_position: 0,
            character_position: 0,
        };
        assert_eq!(
            HostResponse::RecoveryCharacter('a')
                .into_bytes_for(&first)
                .unwrap(),
            b"a"
        );
        assert!(matches!(
            HostResponse::RecoveryCharacter('A').into_bytes_for(&first),
            Err(Error::InvalidInput(message))
                if message
                    == "recovery cipher response must be one lowercase ASCII character"
        ));
        assert!(matches!(
            HostResponse::RecoveryDelete.into_bytes_for(&first),
            Err(Error::InvalidInput(message))
                if message == "recovery action is not valid at this position"
        ));
        for request in [
            HostRequest::RecoveryCharacter {
                word_position: 0,
                character_position: 1,
            },
            HostRequest::RecoveryCharacter {
                word_position: 1,
                character_position: 0,
            },
        ] {
            assert_eq!(
                HostResponse::RecoveryDelete
                    .into_bytes_for(&request)
                    .unwrap(),
                [0x08]
            );
        }

        let middle = HostRequest::RecoveryCharacter {
            word_position: 1,
            character_position: 3,
        };
        assert_eq!(
            HostResponse::RecoveryDelete
                .into_bytes_for(&middle)
                .unwrap(),
            [0x08]
        );
        assert_eq!(
            HostResponse::RecoveryNextWord
                .into_bytes_for(&middle)
                .unwrap(),
            b" "
        );
        assert!(HostResponse::RecoveryDone.into_bytes_for(&middle).is_err());
        let too_early = HostRequest::RecoveryCharacter {
            word_position: 1,
            character_position: 2,
        };
        assert!(matches!(
            HostResponse::RecoveryNextWord.into_bytes_for(&too_early),
            Err(Error::InvalidInput(message))
                if message == "recovery action is not valid at this position"
        ));

        let last = HostRequest::RecoveryCharacter {
            word_position: 11,
            character_position: 3,
        };
        assert_eq!(
            HostResponse::RecoveryDone.into_bytes_for(&last).unwrap(),
            b"\n"
        );
        assert!(matches!(
            HostResponse::PinPositions("1".into()).into_bytes_for(&last),
            Err(Error::InvalidInput(message))
                if message == "host response does not match request"
        ));
    }

    #[test]
    fn host_response_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", HostResponse::PinPositions("8675309".into())),
            "PinPositions(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", HostResponse::RecoveryCharacter('q')),
            "RecoveryCharacter(<redacted>)"
        );
    }
}
