//! Device-independent commands, responses, and message routing.
//!
//! Command support and required context vary by device. Interpreters perform no I/O:
//! callers route [`Transmit`] messages to the device, PIN server, or host and return
//! the resulting bytes to [`crate::Interpreter::exchange`].

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
#[cfg(feature = "specter")]
use crate::specter;
#[cfg(feature = "trezor")]
use crate::trezor;
use bitcoin::Network;
use bitcoin::address::AddressType;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;

mod adapters;

/// Options for starting a device session or unlocking a wallet.
#[derive(Default)]
pub struct UnlockOptions {
    /// Requested network, where supported by the backend.
    ///
    /// Ledger requires a network to select its Bitcoin application. Trezor and
    /// KeepKey use it to select the session network; other common adapters ignore it.
    pub network: Option<Network>,
}

/// Options for initializing a new device wallet.
#[derive(Clone, Debug, Default)]
pub struct SetupOptions {
    /// Requested device label; empty labels are omitted by Trezor and KeepKey.
    pub label: String,
    /// Backup passphrase supplied by the caller.
    ///
    /// BitBox rejects nonempty values; the Trezor and KeepKey adapters do not use it.
    pub backup_passphrase: String,
}

/// Options for restoring a device wallet.
#[derive(Clone, Debug)]
pub struct RestoreOptions {
    /// Requested device label; empty labels are omitted by Trezor and KeepKey.
    pub label: String,
    /// Number of recovery words.
    ///
    /// Defaults to 24. Trezor and KeepKey accept 12, 18, or 24; BitBox ignores this field.
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

/// Inputs for deriving or displaying an address.
///
/// Display flags request device confirmation where supported. Some backends ignore
/// the flag or always display; Specter-DIY rejects requests for undisplayed addresses.
#[derive(Clone, Debug)]
pub enum DisplayAddress {
    /// Derives an address from a device key path.
    ByPath {
        /// Key derivation path for the address.
        path: DerivationPath,
        /// Whether to request address confirmation on the device.
        display: bool,
        /// Requested script format, or the backend's default or path-inferred format.
        address_format: Option<AddressType>,
    },
    /// Derives an address from a registered descriptor or wallet policy.
    ///
    /// Ledger, BitBox, and Specter-DIY require their corresponding [`DeviceContext`].
    /// Trezor and KeepKey do not support this form.
    ByDescriptor {
        /// Address index within the selected descriptor branch.
        index: u32,
        /// Whether to select the change branch rather than the receiving branch.
        change: bool,
        /// Whether to request address confirmation on the device.
        display: bool,
        /// Registered descriptor name used by Jade and Coldcard.
        ///
        /// Policy-based backends use the supplied context instead.
        descriptor_name: String,
    },
    /// Displays a multisig address using Python HWI-compatible inputs.
    ByMultisig(
        /// Multisig script wrapper, threshold, and concrete keys.
        MultisigDisplayAddress,
    ),
}

/// Sans-I/O inputs for Python HWI's `display_multisig_address` operation.
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

/// A script wrapper for a multisig address.
#[derive(Clone, Copy, Debug)]
pub enum MultisigAddressType {
    /// Legacy P2SH multisig.
    Legacy,
    /// P2SH-wrapped P2WSH multisig.
    ShWit,
    /// Native P2WSH multisig.
    Wit,
}

/// A device-independent hardware-wallet operation.
///
/// Commands are not supported uniformly. Conversion to a device command can fail
/// for unsupported operations or missing or mismatched [`DeviceContext`].
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Creates a backup on the device or retrieves a backup file.
    Backup,
    /// Initializes a device wallet using caller-supplied management data.
    Setup(
        /// Requested label and backup options.
        SetupOptions,
        /// Device-specific setup inputs, such as host entropy.
        Option<DeviceContext>,
    ),
    /// Erases the device's wallet material.
    Wipe,
    /// Starts wallet recovery using caller-supplied management data.
    Restore(
        /// Requested label and recovery word count.
        RestoreOptions,
        /// Device-specific recovery inputs, such as a U2F counter.
        Option<DeviceContext>,
    ),
    /// Toggles the device's BIP-39 passphrase-protection setting.
    TogglePassphrase,
    /// Retrieves the wallet's master key fingerprint.
    GetMasterFingerprint,
    /// Retrieves backend-specific firmware or application information.
    GetVersion,
    /// Retrieves an extended public key.
    GetXpub {
        /// Key derivation path.
        path: DerivationPath,
        /// Whether to request confirmation on the device, where supported.
        display: bool,
    },
    /// Derives or displays an address.
    DisplayAddress(
        /// Address derivation inputs and requested display behavior.
        DisplayAddress,
        /// Device-specific policy context required by some address forms.
        Option<DeviceContext>,
    ),
    /// Registers a named wallet policy on a supporting device.
    ///
    /// Trezor and KeepKey do not support wallet registration.
    RegisterWallet {
        /// Wallet name shown or stored by the device.
        name: String,
        /// Wallet policy, including its descriptor keys and origins.
        policy: WalletPolicy,
    },
    /// Signs the inputs of a partially signed Bitcoin transaction.
    ///
    /// Ledger requires policy context even when no wallet HMAC is needed. BitBox
    /// accepts optional policy context; Coldcard, Trezor, and KeepKey require `None`.
    SignTx(
        /// Transaction and metadata to sign.
        Psbt,
        /// Optional device-specific policy inputs.
        Option<DeviceContext>,
    ),
    /// Signs a message with the key at a derivation path.
    SignMessage {
        /// Message bytes in the form accepted by the device protocol.
        message: Vec<u8>,
        /// Signing key derivation path.
        path: DerivationPath,
    },
    /// Starts a session, authenticates, pairs, or opens an app, depending on the backend.
    ///
    /// This does not uniformly mean that a device's PIN lock is cleared.
    Unlock {
        /// Requested session network and unlock options.
        options: UnlockOptions,
    },
    /// Requests a scrambled PIN-entry matrix from a supporting device.
    PromptPin,
    /// Submits scrambled keypad positions, not literal PIN digits.
    SendPin(
        /// Management context containing the caller-supplied PIN positions.
        Option<DeviceContext>,
    ),
}

/// Device-specific inputs required by certain shared commands.
///
/// Management context carries caller-provided entropy, PIN positions, timestamps,
/// or counters. Interpreters neither collect these inputs nor perform transport I/O.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum DeviceContext {
    /// Wallet policy for Ledger signing and descriptor-based address display.
    #[cfg(feature = "ledger")]
    Ledger {
        /// Policy used to derive addresses or identify signing inputs.
        wallet_policy: ledger::LedgerWalletPolicy,
        /// Registration HMAC, or `None` for a policy used without a token.
        ///
        /// The Ledger context itself is still required when this is `None`.
        wallet_hmac: Option<[u8; 32]>,
    },
    /// Wallet policy for BitBox descriptor display or policy-based signing.
    #[cfg(feature = "bitbox")]
    BitBox {
        /// Descriptor policy with the key origins required by the device.
        policy: WalletPolicy,
    },
    /// Required context for BitBox02 setup and restore operations.
    #[cfg(feature = "bitbox")]
    BitBoxManagement(
        /// Caller-supplied setup mode and time information.
        bitbox::ManagementContext,
    ),
    /// Caller-supplied inputs for Trezor setup, restore, or PIN submission.
    #[cfg(feature = "trezor")]
    TrezorManagement(
        /// Host entropy, U2F counter, or scrambled keypad positions.
        trezor::ManagementContext,
    ),
    /// Caller-supplied inputs for KeepKey setup, restore, or PIN submission.
    #[cfg(feature = "keepkey")]
    KeepKeyManagement(
        /// Host entropy, U2F counter, or scrambled keypad positions.
        keepkey::ManagementContext,
    ),
    /// Wallet policy required for Specter-DIY descriptor address display.
    #[cfg(feature = "specter")]
    Specter {
        /// Descriptor policy used to prepare the address display request.
        policy: WalletPolicy,
    },
}

/// The result of a shared hardware-wallet command.
pub enum Response {
    /// The outcome of a backup operation.
    Backup(
        /// Backup completion or downloaded file contents.
        DeviceBackup,
    ),
    /// Backend-specific outcome of a management or PIN request.
    ///
    /// Trezor PIN prompting and KeepKey passphrase toggling can return `true`
    /// while PIN entry is still pending.
    DeviceAction(
        /// Whether the backend accepted or completed the request.
        bool,
    ),
    /// A terminal outcome without another result.
    ///
    /// Ledger also uses this for failed or unsupported signing; it does not
    /// guarantee success.
    TaskDone,
    /// The device reports that an operation is still busy.
    TaskBusy,
    /// Backend-specific device or application information.
    Info(
        /// Information reported or derived by the backend.
        Info,
    ),
    /// The wallet's master key fingerprint.
    MasterFingerprint(
        /// Four-byte BIP-32 fingerprint.
        Fingerprint,
    ),
    /// An extended public key.
    Xpub(
        /// Derived BIP-32 extended public key.
        Xpub,
    ),
    /// Coldcard peer public-key material for establishing encryption.
    EncryptionKey(
        /// Uncompressed secp256k1 public key without the `0x04` prefix.
        [u8; 64],
    ),
    /// An ECDSA message signature and its backend-specific header.
    Signature(
        /// Compact-message signature header, not normalized across backends.
        u8,
        /// ECDSA signature, excluding the header byte.
        Signature,
    ),
    /// A PSBT containing signatures returned by the device.
    SignedPsbt(
        /// Partially signed transaction; not necessarily finalized or fully signed.
        Psbt,
    ),
    /// An address returned by the device.
    Address(
        /// Address in the device protocol's string encoding.
        String,
    ),
    /// The outcome of registering a wallet policy.
    WalletRegistration(
        /// Registration state and any authentication token.
        WalletRegistration,
    ),
}

/// Completion state of a wallet-registration request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletRegistration {
    /// Registration completed, with or without an authentication token.
    Complete {
        /// Device-issued wallet HMAC, when the backend provides one.
        hmac: Option<[u8; 32]>,
    },
    /// The request was submitted but still requires confirmation on the device.
    PendingUserConfirmation,
}

impl WalletRegistration {
    /// Returns the registration HMAC, if available.
    ///
    /// Returns `None` both for completion without a token and for pending user
    /// confirmation. Inspect the variant to distinguish those states.
    pub fn hmac(self) -> Option<[u8; 32]> {
        match self {
            Self::Complete { hmac } => hmac,
            Self::PendingUserConfirmation => None,
        }
    }
}

/// Completion or file contents returned by a backup operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceBackup {
    /// The device completed its backup without returning a downloaded file.
    Complete,
    /// A backup file downloaded from the device.
    File(
        /// File bytes in the device's backup format.
        Vec<u8>,
    ),
}

/// Backend-specific device, firmware, and session information.
///
/// Optional fields may be unreported, not `false`. The meaning and availability of
/// names and network lists depend on the backend.
#[derive(Debug, Clone, Default)]
pub struct Info {
    /// Firmware or application version string reported by the backend.
    pub version: String,
    /// Networks reported by the backend, or an empty list when unreported.
    ///
    /// This may describe the active application or selected session network rather
    /// than every network supported by the hardware.
    pub networks: Vec<Network>,
    /// Backend-specific device, model, or application name, when reported.
    pub firmware: Option<String>,
    /// Whether the device has initialized wallet material, when reported by the firmware.
    pub initialized: Option<bool>,
    /// User-set device name, when the device protocol reports one.
    pub label: Option<String>,
    /// Whether the device can take a passphrase on its own screen, when it reports the capability.
    pub on_device_passphrase_entry: Option<bool>,
    /// Whether the device is waiting for a PIN from the host, when it reports a lock state.
    pub needs_pin_sent: Option<bool>,
    /// Whether the BIP-39 passphrase is expected from the host, when reported or derived.
    pub needs_passphrase_sent: Option<bool>,
}

/// A device request for input that the caller must collect from the user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostRequest {
    /// Requests positions on the scrambled keypad displayed by the device.
    PinMatrix {
        /// Whether the device asks for the current PIN or a new PIN confirmation.
        kind: PinMatrixRequestKind,
    },
    /// Requests a character or control action during cipher-based recovery.
    RecoveryCharacter {
        /// Zero-based recovery word position reported by the device.
        word_position: u32,
        /// Zero-based character position within the current recovery word.
        character_position: u32,
    },
}

/// The purpose of a scrambled PIN-matrix request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinMatrixRequestKind {
    /// Entry of the current PIN.
    Current,
    /// First entry of a new PIN.
    NewFirst,
    /// Confirmation of the new PIN.
    NewSecond,
    /// A request kind not recognized by this library.
    Unknown(
        /// Raw protocol value.
        i32,
    ),
}

/// A typed answer to a [`HostRequest`].
///
/// Encode the answer with [`into_bytes_for`](Self::into_bytes_for) before returning
/// it to the interpreter. `Debug` output redacts PIN positions and recovery characters.
#[derive(Eq, PartialEq)]
pub enum HostResponse {
    /// Scrambled keypad positions, never the literal PIN digits.
    PinPositions(
        /// Nonempty ASCII digits representing the selected positions.
        String,
    ),
    /// A recovery-cipher character selected using the device's displayed mapping.
    RecoveryCharacter(
        /// One lowercase ASCII character.
        char,
    ),
    /// Deletes the previous recovery character.
    RecoveryDelete,
    /// Advances to the next recovery word.
    RecoveryNextWord,
    /// Completes recovery after the last word.
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
    /// Validates and encodes this answer for the given host request.
    ///
    /// PIN positions encode as ASCII bytes. Validation requires nonempty ASCII
    /// digits but does not restrict them to the range 1–9. Recovery characters
    /// must be lowercase ASCII. Delete encodes as `0x08` and is allowed unless both
    /// positions are zero; next-word encodes as a space and requires a character
    /// position of at least 3. Done encodes as a newline and requires a word position
    /// of 11, 17, or 23 and a character position of at least 3.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::InvalidInput`] error if the answer does not match the request,
    /// its contents are invalid, or a recovery action is invalid at that position.
    ///
    /// # Examples
    ///
    /// Encode synthetic keypad positions, not literal PIN digits:
    ///
    /// ```
    /// use bhwi::common::{ErrorKind, HostRequest, HostResponse, PinMatrixRequestKind};
    ///
    /// let request = HostRequest::PinMatrix {
    ///     kind: PinMatrixRequestKind::Current,
    /// };
    /// let bytes = HostResponse::PinPositions("123".into())
    ///     .into_bytes_for(&request)
    ///     .unwrap();
    /// assert_eq!(bytes, b"123");
    /// let error = HostResponse::PinPositions(String::new())
    ///     .into_bytes_for(&request)
    ///     .unwrap_err();
    /// assert_eq!(error.kind(), ErrorKind::InvalidInput);
    /// ```
    pub fn into_bytes_for(self, request: &HostRequest) -> Result<Vec<u8>, Error> {
        match (request, self) {
            (HostRequest::PinMatrix { .. }, Self::PinPositions(mut positions)) => {
                if positions.is_empty() || !positions.bytes().all(|byte| byte.is_ascii_digit()) {
                    zeroize_string(&mut positions);
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "PIN positions must contain ASCII digits",
                    ));
                }
                Ok(positions.into_bytes())
            }
            (HostRequest::RecoveryCharacter { .. }, Self::RecoveryCharacter(character)) => {
                if !character.is_ascii_lowercase() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "recovery cipher response must be one lowercase ASCII character",
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
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "recovery action is not valid at this position",
                        ));
                    }
                    Self::PinPositions(mut positions) => {
                        zeroize_string(&mut positions);
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "host response does not match request",
                        ));
                    }
                    Self::RecoveryCharacter(_) => {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "host response does not match request",
                        ));
                    }
                };
                Ok(vec![byte])
            }
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "host response does not match request",
            )),
        }
    }
}

/// The destination of a shared interpreter's next request.
pub enum Recipient {
    /// The hardware wallet or its emulator.
    Device,
    /// An external PIN-server HTTP endpoint.
    PinServer {
        /// URL to which the caller sends the transmission payload.
        url: String,
    },
    /// User interaction handled by the caller rather than a transport.
    Host(
        /// Request to answer with [`HostResponse::into_bytes_for`].
        HostRequest,
    ),
}

/// A routed request produced by a shared interpreter.
///
/// Send device or PIN-server payloads to their recipient and return the response
/// bytes to [`crate::Interpreter::exchange`]. For host requests, collect a typed
/// [`HostResponse`] and encode it with [`HostResponse::into_bytes_for`].
///
/// Converting a byte vector targets the device with `encrypted` set to `false`.
/// Converting a [`HostRequest`] targets the host with an empty payload.
pub struct Transmit {
    /// Destination of the payload or host-interaction request.
    pub recipient: Recipient,
    /// Encoded protocol payload, ready to route; empty for a converted host request.
    pub payload: Vec<u8>,
    /// Whether the payload is already encrypted.
    ///
    /// Transports may use this flag for framing; callers must not encrypt the
    /// payload again.
    pub encrypted: bool,
}

/// The kind of failure an error reports, shared by every device.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The user declined on the device or dismissed a prompt.
    UserCancelled,
    /// The device's login step failed without saying why.
    AuthenticationRefused,
    /// The host could not get an answer from the user.
    HostUnavailable,
    /// The device needs its PIN before it will answer.
    Locked,
    /// The device is reachable but not ready to run commands.
    NotReady,
    /// A PIN step was requested but the device is already unlocked.
    AlreadyUnlocked,
    /// The device has no wallet.
    NotInitialized,
    /// The device already has a wallet.
    AlreadyInitialized,
    /// The PIN was wrong.
    WrongPin,
    /// A key or address belongs to another network.
    WrongNetwork,
    /// The item being created already exists on the device.
    Duplicate,
    /// The device or firmware cannot run this command.
    Unsupported,
    /// The device cannot display this address type.
    UnsupportedDisplayAddress,
    /// The command needs data the caller did not supply.
    MissingContext,
    /// The caller's data is malformed or was rejected as invalid.
    InvalidInput,
    /// The device refused for a reason no other kind covers.
    Rejected,
    /// The device reported an internal failure.
    DeviceFailure,
    /// Host and device disagreed on the protocol.
    Protocol,
    /// A valid reply that is not the one expected.
    UnexpectedResponse,
    /// Bytes could not be encoded or decoded.
    Serialization,
    /// Channel encryption or decryption failed.
    Encryption,
    /// I/O with the device or a helper service failed.
    Transport,
    /// The device went away.
    Disconnected,
    /// No other kind applies.
    Other,
}

/// A device's own error code, in that vendor's numbering.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceCode {
    /// A Ledger status word.
    Ledger(u16),
    /// A Trezor failure code.
    Trezor(i32),
    /// A KeepKey failure code.
    KeepKey(i32),
    /// A Jade RPC error code.
    Jade(i32),
    /// A BitBox02 error code.
    BitBox(i32),
}

/// A failure with its kind, the device's code and message, and any data the device sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    device_code: Option<DeviceCode>,
    message: String,
    data: Option<Vec<u8>>,
}

impl Error {
    /// Creates an error of `kind` with `message`.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            device_code: None,
            message: message.into(),
            data: None,
        }
    }

    /// Sets the device's own error code.
    pub fn with_device_code(mut self, code: DeviceCode) -> Self {
        self.device_code = Some(code);
        self
    }

    /// Sets data the device sent with the error; it is never printed.
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Returns the failure kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the device's own error code, if it sent one.
    pub fn device_code(&self) -> Option<DeviceCode> {
        self.device_code
    }

    /// Returns the message without the kind.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns data the device sent with the error.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.message.is_empty() {
            write!(f, "[{:?}]", self.kind)
        } else {
            write!(f, "[{:?}] {}", self.kind, self.message)
        }
    }
}

impl std::error::Error for Error {}

/// The BitBox interpreter using this module's shared command and result types.
#[cfg(feature = "bitbox")]
pub type BitBoxInterpreter<'a> = bitbox::BitBoxInterpreter<'a, Command, Transmit, Response, Error>;
/// The Coldcard interpreter using this module's shared command and result types.
#[cfg(feature = "coldcard")]
pub type ColdcardInterpreter<'a> =
    coldcard::ColdcardInterpreter<'a, Command, Transmit, Response, Error>;
/// The Jade interpreter using this module's shared command and result types.
#[cfg(feature = "jade")]
pub type JadeInterpreter = jade::JadeInterpreter<Command, Transmit, Response, Error>;
/// The Ledger interpreter using this module's shared command and result types.
#[cfg(feature = "ledger")]
pub type LedgerInterpreter = ledger::LedgerInterpreter<Command, Transmit, Response, Error>;
/// The Trezor interpreter using this module's shared command and result types.
#[cfg(feature = "trezor")]
pub type TrezorInterpreter = trezor::TrezorInterpreter<Command, Transmit, Response, Error>;
/// The KeepKey interpreter using this module's shared command and result types.
#[cfg(feature = "keepkey")]
pub type KeepKeyInterpreter = keepkey::KeepKeyInterpreter<Command, Transmit, Response, Error>;
/// The Specter-DIY interpreter using this module's shared command and result types.
#[cfg(feature = "specter")]
pub type SpecterInterpreter = specter::SpecterInterpreter<Command, Transmit, Response, Error>;

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
        #[cfg(feature = "specter")]
        assert_interpreter::<SpecterInterpreter>();
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
            Err(e) if e.kind() == ErrorKind::InvalidInput
                && e.message() == "PIN positions must contain ASCII digits"
        ));
        assert!(matches!(
            HostResponse::PinPositions("１２３".into()).into_bytes_for(&pin),
            Err(e) if e.kind() == ErrorKind::InvalidInput
                && e.message() == "PIN positions must contain ASCII digits"
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
            Err(e) if e.kind() == ErrorKind::InvalidInput
                && e.message()
                    == "recovery cipher response must be one lowercase ASCII character"
        ));
        assert!(matches!(
            HostResponse::RecoveryDelete.into_bytes_for(&first),
            Err(e) if e.kind() == ErrorKind::InvalidInput
                && e.message() == "recovery action is not valid at this position"
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
            Err(e) if e.kind() == ErrorKind::InvalidInput
                && e.message() == "recovery action is not valid at this position"
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
            Err(e) if e.kind() == ErrorKind::InvalidInput
                && e.message() == "host response does not match request"
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
