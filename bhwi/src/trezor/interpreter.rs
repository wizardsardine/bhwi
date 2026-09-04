use core::marker::PhantomData;
use core::str::FromStr;

use bitcoin::address::AddressType;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{Network, NetworkKind, Transaction};

use crate::Interpreter;
use crate::common::{HostRequest, PinMatrixRequestKind};
use crate::miniscript::descriptor::{DescriptorPublicKey, SinglePubKey, Wildcard};
use crate::trezor::api::{self, MessageType};
use crate::trezor::error::TrezorError;
use crate::trezor::proto::{bitcoin as btc, common as pb, management as mgmt};
use zeroize::Zeroize;

pub enum TrezorCommand {
    Initialize(Option<Network>),
    GetFeatures,
    GetMasterFingerprint,
    GetXpub {
        address_n: Vec<u32>,
        display: bool,
    },
    GetAddress {
        address_n: Vec<u32>,
        display: bool,
        script_type: btc::InputScriptType,
    },
    GetMultisigAddress(TrezorMultisigAddress),
    SignMessage {
        address_n: Vec<u32>,
        message: Vec<u8>,
    },
    SignTx(Box<Psbt>),
    Wipe,
    TogglePassphrase,
    Setup {
        label: Option<String>,
        host_entropy: [u8; 32],
    },
    Restore {
        label: Option<String>,
        word_count: u32,
        u2f_counter: u32,
    },
    PromptPin,
    SendPin(crate::trezor::HostPin),
}

pub(crate) enum EngineCommand {
    Initialize(Option<Network>),
    GetFeatures,
    GetMasterFingerprint,
    GetXpub {
        address_n: Vec<u32>,
        display: bool,
    },
    GetAddress {
        address_n: Vec<u32>,
        display: bool,
        script_type: btc::InputScriptType,
    },
    GetMultisigAddress(TrezorMultisigAddress),
    SignMessage {
        address_n: Vec<u32>,
        message: Vec<u8>,
    },
    SignTx(Box<Psbt>),
    Wipe,
    TogglePassphrase,
    Setup {
        label: Option<String>,
        host_entropy: [u8; 32],
    },
    Restore {
        label: Option<String>,
        word_count: u32,
        u2f_counter: u32,
    },
    PromptPin,
    SendPin(crate::trezor::HostPin),
}

impl From<TrezorCommand> for EngineCommand {
    fn from(command: TrezorCommand) -> Self {
        match command {
            TrezorCommand::Initialize(network) => Self::Initialize(network),
            TrezorCommand::GetFeatures => Self::GetFeatures,
            TrezorCommand::GetMasterFingerprint => Self::GetMasterFingerprint,
            TrezorCommand::GetXpub { address_n, display } => Self::GetXpub { address_n, display },
            TrezorCommand::GetAddress {
                address_n,
                display,
                script_type,
            } => Self::GetAddress {
                address_n,
                display,
                script_type,
            },
            TrezorCommand::GetMultisigAddress(address) => Self::GetMultisigAddress(address),
            TrezorCommand::SignMessage { address_n, message } => {
                Self::SignMessage { address_n, message }
            }
            TrezorCommand::SignTx(psbt) => Self::SignTx(psbt),
            TrezorCommand::Wipe => Self::Wipe,
            TrezorCommand::TogglePassphrase => Self::TogglePassphrase,
            TrezorCommand::Setup {
                label,
                host_entropy,
            } => Self::Setup {
                label,
                host_entropy,
            },
            TrezorCommand::Restore {
                label,
                word_count,
                u2f_counter,
            } => Self::Restore {
                label,
                word_count,
                u2f_counter,
            },
            TrezorCommand::PromptPin => Self::PromptPin,
            TrezorCommand::SendPin(pin) => Self::SendPin(pin),
        }
    }
}

/// m/44'/1'/0', the key asked for to raise the keypad. The reply is never read.
const PIN_PROMPT_PATH: [u32; 3] = [0x8000_002c, 0x8000_0001, 0x8000_0000];

pub struct TrezorMultisigAddress {
    pub threshold: u8,
    pub address_type: TrezorMultisigAddressType,
    pub sorted: bool,
    pub keys: Vec<DescriptorPublicKey>,
}

#[derive(Clone, Copy, Debug)]
pub enum TrezorMultisigAddressType {
    Legacy,
    ShWit,
    Wit,
}

pub enum TrezorResponse {
    DeviceAction(bool),
    SignedPsbt(Box<Psbt>),
    Info(TrezorDeviceInfo),
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    Address(String),
    Signature(u8, bitcoin::secp256k1::ecdsa::Signature),
}

pub struct TrezorDeviceInfo {
    pub version: String,
    /// The network the session was opened for; Features does not report one.
    pub network: Network,
    pub model: Option<String>,
    pub initialized: Option<bool>,
    pub label: Option<String>,
    pub on_device_passphrase_entry: bool,
    pub needs_pin_sent: bool,
    pub passphrase_protection: bool,
}

enum PublicKeyKind {
    Fingerprint,
    Xpub,
}

enum State {
    New,
    AwaitFeatures,
    AwaitPublicKey(PublicKeyKind),
    AwaitAddress,
    AwaitMultisigAddress(Box<MultisigCtx>),
    AwaitMessageSignature,
    AwaitSuccess,
    AwaitToggleSuccess,
    AwaitRecovery,
    AwaitHostPin(Box<State>),
    AwaitRecoveryCharacter(Box<State>),
    AwaitPassphraseCancel,
    AwaitLockedCancel,
    AwaitPassphraseSetting,
    AwaitPinPromptFeatures,
    AwaitPinMatrix,
    AwaitPinResult,
    AwaitPinFailureFeatures,
    AwaitSetupFeatures(Box<SetupCtx>),
    AwaitRestoreFeatures(Box<RestoreCtx>),
    AwaitEntropyRequest([u8; 32]),
    AwaitSignKey(Box<Psbt>),
    AwaitTxRequest(Box<SignCtx>),
    Finished(TrezorResponse),
}

pub(crate) struct SetupCtx {
    pub(crate) label: Option<String>,
    pub(crate) passphrase_protection: bool,
    pub(crate) host_entropy: [u8; 32],
}

pub(crate) struct RestoreCtx {
    pub(crate) label: Option<String>,
    pub(crate) passphrase_protection: bool,
    pub(crate) word_count: u32,
    pub(crate) u2f_counter: u32,
}

struct MultisigCtx {
    multisig: btc::MultisigRedeemScriptType,
    script_type: btc::InputScriptType,
    paths: Vec<Vec<u32>>,
    next: usize,
}

struct SignCtx {
    psbt: Box<Psbt>,
    tx: Transaction,
    coin: String,
    master_fp: Fingerprint,
    signatures: Vec<(u32, Vec<u8>)>,
    passes: usize,
    ignored: std::collections::BTreeSet<usize>,
    external_inputs: bool,
}

const MAX_SIGN_PASSES: usize = 15;

pub(crate) enum EngineTransmit {
    Device(Vec<u8>),
    Host(HostRequest),
}

pub(crate) struct DeviceFeatures {
    pub(crate) major_version: u32,
    pub(crate) minor_version: u32,
    pub(crate) patch_version: u32,
    pub(crate) pin_protection: bool,
    pub(crate) passphrase_protection: bool,
    pub(crate) label: Option<String>,
    pub(crate) initialized: Option<bool>,
    pub(crate) unlocked: bool,
    pub(crate) model: Option<String>,
    pub(crate) on_device_passphrase_entry: bool,
}

pub(crate) trait Profile {
    const HOST_MANAGEMENT: bool;
    const CHARACTER_CIPHER: bool;
    const TOGGLE_PENDING_PIN: bool;
    const EXTERNAL_INPUTS: bool;
    const DEFAULT_ON_DEVICE_PASSPHRASE: bool;

    fn coin_name(network: Network) -> String;
    fn decode_features(payload: &[u8]) -> Result<DeviceFeatures, TrezorError>;
    fn get_public_key(
        address_n: Vec<u32>,
        show_display: bool,
        script_type: btc::InputScriptType,
        coin_name: String,
    ) -> Vec<u8>;
    fn sign_message(address_n: Vec<u32>, message: Vec<u8>, coin_name: String) -> Vec<u8>;
    fn passphrase_ack(on_device: bool, passphrase: &str) -> Vec<u8>;
    fn passphrase_too_long(passphrase: &crate::trezor::HostPassphrase) -> bool;
    fn reset_device(features: &DeviceFeatures, context: SetupCtx) -> Result<Vec<u8>, TrezorError>;
    fn recovery_device(
        features: &DeviceFeatures,
        context: RestoreCtx,
    ) -> Result<Vec<u8>, TrezorError>;
    fn locked_message() -> &'static str;
    fn pin_failure_needs_features(_failure: &pb::Failure) -> bool {
        true
    }

    fn validate_command(_command: &EngineCommand) -> Result<(), TrezorError> {
        Ok(())
    }

    fn validate_psbt(_psbt: &Psbt, _master_fp: Fingerprint) -> Result<(), TrezorError> {
        Ok(())
    }

    fn decode_character_request(_payload: &[u8]) -> Result<HostRequest, TrezorError> {
        Err(TrezorError::Unsupported(
            "character-cipher recovery is not supported",
        ))
    }

    fn character_ack(_value: u8) -> Result<Vec<u8>, TrezorError> {
        Err(TrezorError::Unsupported(
            "character-cipher recovery is not supported",
        ))
    }
}

struct TrezorProfile;

impl Profile for TrezorProfile {
    const HOST_MANAGEMENT: bool = false;
    const CHARACTER_CIPHER: bool = false;
    const TOGGLE_PENDING_PIN: bool = false;
    const EXTERNAL_INPUTS: bool = false;
    const DEFAULT_ON_DEVICE_PASSPHRASE: bool = true;

    fn coin_name(network: Network) -> String {
        coin_name(network)
    }

    fn decode_features(payload: &[u8]) -> Result<DeviceFeatures, TrezorError> {
        let features: mgmt::Features = api::decode(payload)?;
        Ok(trezor_device_features(features))
    }

    fn get_public_key(
        address_n: Vec<u32>,
        show_display: bool,
        script_type: btc::InputScriptType,
        coin_name: String,
    ) -> Vec<u8> {
        api::get_public_key(address_n, show_display, script_type, coin_name)
    }

    fn sign_message(address_n: Vec<u32>, message: Vec<u8>, coin_name: String) -> Vec<u8> {
        api::sign_message(address_n, message, coin_name)
    }

    fn passphrase_ack(on_device: bool, passphrase: &str) -> Vec<u8> {
        if on_device {
            api::passphrase_ack_on_device()
        } else {
            api::passphrase_ack_from_host(passphrase)
        }
    }

    fn passphrase_too_long(passphrase: &crate::trezor::HostPassphrase) -> bool {
        passphrase.is_too_long()
    }

    fn reset_device(features: &DeviceFeatures, context: SetupCtx) -> Result<Vec<u8>, TrezorError> {
        if features.model.as_deref().unwrap_or("1") == "1" {
            return Err(TrezorError::Unsupported(
                "Trezor One setup needs host PIN entry, which is not supported in this build",
            ));
        }
        let strength = if features.model.as_deref() == Some("1") {
            256
        } else {
            128
        };
        Ok(api::reset_device(
            strength,
            context.passphrase_protection,
            context.label,
        ))
    }

    fn recovery_device(
        features: &DeviceFeatures,
        context: RestoreCtx,
    ) -> Result<Vec<u8>, TrezorError> {
        if features.model.as_deref().unwrap_or("1") == "1" {
            return Err(TrezorError::Unsupported(
                "Trezor One restore needs host word entry, which is not supported in this build",
            ));
        }
        Ok(api::recovery_device(
            context.word_count,
            context.passphrase_protection,
            context.label,
            context.u2f_counter,
        ))
    }

    fn locked_message() -> &'static str {
        TrezorError::LOCKED
    }
}

pub(crate) struct Engine<P> {
    state: State,
    network: Network,
    passphrase: Option<crate::trezor::HostPassphrase>,
    on_device_passphrase: bool,
    _profile: PhantomData<P>,
}

impl<P: Profile> Default for Engine<P> {
    fn default() -> Self {
        Self {
            state: State::New,
            network: Network::Bitcoin,
            passphrase: None,
            on_device_passphrase: P::DEFAULT_ON_DEVICE_PASSPHRASE,
            _profile: PhantomData,
        }
    }
}

impl<P: Profile> Engine<P> {
    pub(crate) fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub(crate) fn with_passphrase(
        mut self,
        passphrase: Option<crate::trezor::HostPassphrase>,
    ) -> Self {
        self.passphrase = passphrase;
        self
    }

    pub(crate) fn with_on_device_passphrase(mut self, on_device: bool) -> Self {
        self.on_device_passphrase = on_device;
        self
    }

    fn wants_passphrase_protection(&self) -> bool {
        self.passphrase
            .as_ref()
            .is_some_and(|passphrase| !passphrase.as_str().is_empty())
    }

    pub(crate) fn start(&mut self, command: EngineCommand) -> Result<EngineTransmit, TrezorError> {
        P::validate_command(&command)?;
        let coin = P::coin_name(self.network);
        let bytes = match command {
            EngineCommand::Initialize(network) => {
                if let Some(network) = network {
                    self.network = network;
                }
                self.state = State::AwaitFeatures;
                api::initialize()
            }
            EngineCommand::GetFeatures => {
                self.state = State::AwaitFeatures;
                api::get_features()
            }
            EngineCommand::GetMasterFingerprint => {
                self.state = State::AwaitPublicKey(PublicKeyKind::Fingerprint);
                P::get_public_key(Vec::new(), false, btc::InputScriptType::Spendaddress, coin)
            }
            EngineCommand::GetXpub { address_n, display } => {
                self.state = State::AwaitPublicKey(PublicKeyKind::Xpub);
                P::get_public_key(address_n, display, btc::InputScriptType::Spendwitness, coin)
            }
            EngineCommand::GetAddress {
                address_n,
                display,
                script_type,
            } => {
                self.state = State::AwaitAddress;
                api::get_address(address_n, display, script_type, coin, None)
            }
            EngineCommand::GetMultisigAddress(address) => {
                let script_type = multisig_script_type(address.address_type);
                let (multisig, paths) = multisig_script(&address)?;
                let bytes = api::get_address(
                    paths[0].clone(),
                    true,
                    script_type,
                    coin,
                    Some(multisig.clone()),
                );
                self.state = State::AwaitMultisigAddress(Box::new(MultisigCtx {
                    multisig,
                    script_type,
                    paths,
                    next: 1,
                }));
                bytes
            }
            EngineCommand::SignMessage { address_n, message } => {
                self.state = State::AwaitMessageSignature;
                P::sign_message(address_n, message, coin)
            }
            EngineCommand::Wipe => {
                self.state = State::AwaitSuccess;
                api::wipe_device()
            }
            EngineCommand::TogglePassphrase => {
                self.state = State::AwaitPassphraseSetting;
                api::get_features()
            }
            EngineCommand::PromptPin => {
                self.state = State::AwaitPinPromptFeatures;
                api::initialize()
            }
            EngineCommand::SendPin(pin) => {
                self.on_device_passphrase = false;
                self.state = State::AwaitPinResult;
                api::pin_matrix_ack(pin.as_str())
            }
            EngineCommand::Setup {
                label,
                host_entropy,
            } => {
                self.state = State::AwaitSetupFeatures(Box::new(SetupCtx {
                    label,
                    passphrase_protection: self.wants_passphrase_protection(),
                    host_entropy,
                }));
                api::get_features()
            }
            EngineCommand::Restore {
                label,
                word_count,
                u2f_counter,
            } => {
                self.state = State::AwaitRestoreFeatures(Box::new(RestoreCtx {
                    label,
                    passphrase_protection: self.wants_passphrase_protection(),
                    word_count,
                    u2f_counter,
                }));
                api::get_features()
            }
            EngineCommand::SignTx(psbt) => {
                self.state = State::AwaitSignKey(psbt);
                P::get_public_key(Vec::new(), false, btc::InputScriptType::Spendaddress, coin)
            }
        };
        Ok(EngineTransmit::Device(bytes))
    }

    pub(crate) fn exchange(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Option<EngineTransmit>, TrezorError> {
        if matches!(
            self.state,
            State::AwaitHostPin(_) | State::AwaitRecoveryCharacter(_)
        ) {
            return self.consume_host_response(data);
        }

        let (msg_type, payload) = api::parse_frame(&data)?;

        if matches!(self.state, State::New | State::Finished(_)) {
            return Err(TrezorError::UnexpectedMessage(
                msg_type,
                "no command in progress",
            ));
        }
        if matches!(self.state, State::AwaitPassphraseCancel) {
            return Err(TrezorError::PassphraseTooLong);
        }
        if matches!(self.state, State::AwaitLockedCancel) {
            return Err(TrezorError::Locked(P::locked_message()));
        }
        if msg_type == MessageType::ButtonRequest as u16 {
            return Ok(Some(EngineTransmit::Device(api::button_ack())));
        }
        if msg_type == MessageType::PassphraseRequest as u16 {
            let on_device = self.on_device_passphrase && P::DEFAULT_ON_DEVICE_PASSPHRASE;
            if !on_device && self.passphrase.as_ref().is_some_and(P::passphrase_too_long) {
                self.state = State::AwaitPassphraseCancel;
                return Ok(Some(EngineTransmit::Device(api::cancel())));
            }
            let passphrase = self
                .passphrase
                .as_ref()
                .map_or("", crate::trezor::HostPassphrase::as_str);
            return Ok(Some(EngineTransmit::Device(P::passphrase_ack(
                on_device, passphrase,
            ))));
        }
        if msg_type == MessageType::Failure as u16 && !matches!(self.state, State::AwaitPinResult) {
            let failure: pb::Failure = api::decode(&payload)?;
            let error = failure_error(failure);
            if matches!(error, TrezorError::ActionCancelled) {
                return Err(error);
            }
            if let State::AwaitMultisigAddress(ctx) = &mut self.state
                && ctx.next < ctx.paths.len()
            {
                let bytes = api::get_address(
                    ctx.paths[ctx.next].clone(),
                    true,
                    ctx.script_type,
                    P::coin_name(self.network),
                    Some(ctx.multisig.clone()),
                );
                ctx.next += 1;
                return Ok(Some(EngineTransmit::Device(bytes)));
            }
            if matches!(self.state, State::AwaitMultisigAddress(_)) {
                return Err(TrezorError::InvalidInput(
                    "No path supplied matched device keys".into(),
                ));
            }
            return Err(error);
        }
        if msg_type == MessageType::PinMatrixRequest as u16 {
            let request: pb::PinMatrixRequest = api::decode(&payload)?;
            let kind = pin_request_kind(request.r#type);
            if matches!(self.state, State::AwaitPinMatrix) {
                // promptpin deliberately leaves the device waiting for sendpin.
            } else if P::TOGGLE_PENDING_PIN
                && matches!(self.state, State::AwaitToggleSuccess)
                && kind == PinMatrixRequestKind::Current
            {
                self.state = State::Finished(TrezorResponse::DeviceAction(true));
                return Ok(None);
            } else if P::HOST_MANAGEMENT
                && matches!(
                    self.state,
                    State::AwaitEntropyRequest(_) | State::AwaitRecovery
                )
            {
                let resume = core::mem::replace(&mut self.state, State::New);
                self.state = State::AwaitHostPin(Box::new(resume));
                return Ok(Some(EngineTransmit::Host(HostRequest::PinMatrix { kind })));
            } else {
                self.state = State::AwaitLockedCancel;
                return Ok(Some(EngineTransmit::Device(api::cancel())));
            }
        }
        if P::CHARACTER_CIPHER && msg_type == 80 && matches!(self.state, State::AwaitRecovery) {
            let request = P::decode_character_request(&payload)?;
            let resume = core::mem::replace(&mut self.state, State::New);
            self.state = State::AwaitRecoveryCharacter(Box::new(resume));
            return Ok(Some(EngineTransmit::Host(request)));
        }

        let response = match &self.state {
            State::AwaitFeatures => {
                let features = expect_features::<P>(msg_type, &payload, "reading features")?;
                TrezorResponse::Info(device_info(features, self.network))
            }
            State::AwaitPublicKey(kind) => {
                let pubkey: btc::PublicKey = expect(
                    msg_type,
                    MessageType::PublicKey,
                    &payload,
                    "reading public key",
                )?;
                match kind {
                    PublicKeyKind::Fingerprint => {
                        let fingerprint = match pubkey.root_fingerprint {
                            Some(fingerprint) => Fingerprint::from(fingerprint.to_be_bytes()),
                            None => parse_xpub(&pubkey.xpub)?.fingerprint(),
                        };
                        TrezorResponse::MasterFingerprint(fingerprint)
                    }
                    PublicKeyKind::Xpub => {
                        let xpub = parse_xpub(&pubkey.xpub)?;
                        if xpub.network != NetworkKind::from(self.network) {
                            return Err(TrezorError::NetworkMismatch);
                        }
                        TrezorResponse::Xpub(xpub)
                    }
                }
            }
            State::AwaitAddress => {
                let address: btc::Address =
                    expect(msg_type, MessageType::Address, &payload, "reading address")?;
                TrezorResponse::Address(address.address)
            }
            State::AwaitMultisigAddress(_) => {
                let address: btc::Address =
                    expect(msg_type, MessageType::Address, &payload, "reading address")?;
                TrezorResponse::Address(address.address)
            }
            State::AwaitMessageSignature => {
                let signed: btc::MessageSignature = expect(
                    msg_type,
                    MessageType::MessageSignature,
                    &payload,
                    "reading message signature",
                )?;
                let (header, compact) = signed
                    .signature
                    .split_first()
                    .ok_or(TrezorError::InvalidInput("empty message signature".into()))?;
                let signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(compact)
                    .map_err(|e| TrezorError::InvalidInput(e.to_string()))?;
                TrezorResponse::Signature(*header, signature)
            }
            State::AwaitSetupFeatures(_) => {
                let State::AwaitSetupFeatures(context) =
                    core::mem::replace(&mut self.state, State::New)
                else {
                    unreachable!("state checked above")
                };
                let features =
                    expect_features::<P>(msg_type, &payload, "reading features before setup")?;
                if features.initialized.unwrap_or(false) {
                    return Err(TrezorError::AlreadyInitialized);
                }
                let entropy = context.host_entropy;
                let bytes = P::reset_device(&features, *context)?;
                self.state = State::AwaitEntropyRequest(entropy);
                return Ok(Some(EngineTransmit::Device(bytes)));
            }
            State::AwaitRestoreFeatures(_) => {
                let State::AwaitRestoreFeatures(context) =
                    core::mem::replace(&mut self.state, State::New)
                else {
                    unreachable!("state checked above")
                };
                let features =
                    expect_features::<P>(msg_type, &payload, "reading features before restore")?;
                if features.initialized.unwrap_or(false) {
                    return Err(TrezorError::AlreadyInitialized);
                }
                let bytes = P::recovery_device(&features, *context)?;
                self.state = if P::CHARACTER_CIPHER {
                    State::AwaitRecovery
                } else {
                    State::AwaitSuccess
                };
                return Ok(Some(EngineTransmit::Device(bytes)));
            }
            State::AwaitEntropyRequest(host_entropy) => {
                let entropy = *host_entropy;
                let _: mgmt::EntropyRequest = expect(
                    msg_type,
                    MessageType::EntropyRequest,
                    &payload,
                    "reading entropy request",
                )?;
                self.state = State::AwaitSuccess;
                return Ok(Some(EngineTransmit::Device(api::entropy_ack(&entropy))));
            }
            State::AwaitPassphraseSetting => {
                let features =
                    expect_features::<P>(msg_type, &payload, "reading passphrase setting")?;
                self.state = State::AwaitToggleSuccess;
                return Ok(Some(EngineTransmit::Device(api::apply_settings(
                    !features.passphrase_protection,
                ))));
            }
            State::AwaitPinPromptFeatures => {
                let features =
                    expect_features::<P>(msg_type, &payload, "reading features before PIN entry")?;
                check_device_pin_needed(&features)?;
                self.state = State::AwaitPinMatrix;
                return Ok(Some(EngineTransmit::Device(P::get_public_key(
                    PIN_PROMPT_PATH.to_vec(),
                    false,
                    btc::InputScriptType::Spendaddress,
                    P::coin_name(self.network),
                ))));
            }
            State::AwaitPinMatrix => TrezorResponse::DeviceAction(true),
            State::AwaitPinResult => {
                if msg_type == MessageType::Failure as u16 {
                    let failure: pb::Failure = api::decode(&payload)?;
                    let needs_features = P::pin_failure_needs_features(&failure);
                    let error = failure_error(failure);
                    if matches!(error, TrezorError::ActionCancelled) {
                        return Err(error);
                    }
                    if needs_features {
                        self.state = State::AwaitPinFailureFeatures;
                        return Ok(Some(EngineTransmit::Device(api::get_features())));
                    }
                    TrezorResponse::DeviceAction(false)
                } else {
                    TrezorResponse::DeviceAction(true)
                }
            }
            State::AwaitPinFailureFeatures => {
                let features = expect_features::<P>(
                    msg_type,
                    &payload,
                    "reading features after a rejected PIN",
                )?;
                check_device_pin_needed(&features)?;
                TrezorResponse::DeviceAction(false)
            }
            State::AwaitSuccess | State::AwaitToggleSuccess | State::AwaitRecovery => {
                let _: pb::Success = expect(
                    msg_type,
                    MessageType::Success,
                    &payload,
                    "reading device action result",
                )?;
                TrezorResponse::DeviceAction(true)
            }
            State::AwaitSignKey(_) => {
                let State::AwaitSignKey(psbt) = core::mem::replace(&mut self.state, State::New)
                else {
                    unreachable!("state checked above")
                };
                let pubkey: btc::PublicKey = expect(
                    msg_type,
                    MessageType::PublicKey,
                    &payload,
                    "reading master public key",
                )?;
                let master_fp = match pubkey.root_fingerprint {
                    Some(fingerprint) => Fingerprint::from(fingerprint.to_be_bytes()),
                    None => parse_xpub(&pubkey.xpub)?.fingerprint(),
                };
                P::validate_psbt(&psbt, master_fp)?;
                let tx = psbt.unsigned_tx.clone();
                let coin = P::coin_name(self.network);
                let bytes = api::sign_tx(
                    tx.input.len() as u32,
                    tx.output.len() as u32,
                    tx.version.0 as u32,
                    tx.lock_time.to_consensus_u32(),
                    &coin,
                );
                self.state = State::AwaitTxRequest(Box::new(SignCtx {
                    psbt,
                    tx,
                    coin,
                    master_fp,
                    signatures: Vec::new(),
                    passes: 1,
                    ignored: std::collections::BTreeSet::new(),
                    external_inputs: P::EXTERNAL_INPUTS,
                }));
                return Ok(Some(EngineTransmit::Device(bytes)));
            }
            State::AwaitTxRequest(_) => {
                let State::AwaitTxRequest(mut context) =
                    core::mem::replace(&mut self.state, State::New)
                else {
                    unreachable!("state checked above")
                };
                let request: btc::TxRequest = expect(
                    msg_type,
                    MessageType::TxRequest,
                    &payload,
                    "signing transaction",
                )?;
                match drive_sign(&mut context, request)? {
                    SignStep::Continue(bytes) => {
                        self.state = State::AwaitTxRequest(context);
                        return Ok(Some(EngineTransmit::Device(bytes)));
                    }
                    SignStep::Done(psbt) => TrezorResponse::SignedPsbt(psbt),
                }
            }
            State::AwaitPassphraseCancel => return Err(TrezorError::PassphraseTooLong),
            State::AwaitLockedCancel => return Err(TrezorError::Locked(P::locked_message())),
            State::AwaitHostPin(_) | State::AwaitRecoveryCharacter(_) => {
                unreachable!("host response states are handled before framing")
            }
            State::New | State::Finished(_) => {
                return Err(TrezorError::UnexpectedMessage(
                    msg_type,
                    "no command in progress",
                ));
            }
        };
        self.state = State::Finished(response);
        Ok(None)
    }

    fn consume_host_response(
        &mut self,
        mut data: Vec<u8>,
    ) -> Result<Option<EngineTransmit>, TrezorError> {
        let state = core::mem::replace(&mut self.state, State::New);
        let result = match state {
            State::AwaitHostPin(resume) => {
                self.state = *resume;
                match core::str::from_utf8(&data) {
                    Ok(positions)
                        if !positions.is_empty()
                            && positions.bytes().all(|byte| byte.is_ascii_digit()) =>
                    {
                        Ok(Some(EngineTransmit::Device(api::pin_matrix_ack(positions))))
                    }
                    _ => Err(TrezorError::InvalidInput(
                        "PIN positions must contain ASCII digits".into(),
                    )),
                }
            }
            State::AwaitRecoveryCharacter(resume) => {
                self.state = *resume;
                if data.len() != 1 || !matches!(data[0], b'a'..=b'z' | 0x08 | b' ' | b'\n') {
                    Err(TrezorError::InvalidInput(
                        "invalid recovery cipher response".into(),
                    ))
                } else {
                    P::character_ack(data[0]).map(|bytes| Some(EngineTransmit::Device(bytes)))
                }
            }
            _ => unreachable!("host response state checked before calling"),
        };
        data.zeroize();
        result
    }

    pub(crate) fn end(self) -> Result<TrezorResponse, TrezorError> {
        match self.state {
            State::Finished(response) => Ok(response),
            _ => Err(TrezorError::InvalidInput(
                "interpreter did not reach a response".into(),
            )),
        }
    }
}

pub struct TrezorInterpreter<C, T, R, E> {
    engine: Engine<TrezorProfile>,
    _marker: PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for TrezorInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            engine: Engine::default(),
            _marker: PhantomData,
        }
    }
}

impl<C, T, R, E> TrezorInterpreter<C, T, R, E> {
    pub fn with_network(mut self, network: Network) -> Self {
        self.engine = self.engine.with_network(network);
        self
    }

    pub fn with_passphrase(mut self, passphrase: Option<crate::trezor::HostPassphrase>) -> Self {
        self.engine = self.engine.with_passphrase(passphrase);
        self
    }

    pub fn with_on_device_passphrase(mut self, on_device: bool) -> Self {
        self.engine = self.engine.with_on_device_passphrase(on_device);
        self
    }

    #[cfg(test)]
    fn wants_passphrase_protection(&self) -> bool {
        self.engine.wants_passphrase_protection()
    }
}

impl<C, T, R, E> Interpreter for TrezorInterpreter<C, T, R, E>
where
    C: TryInto<TrezorCommand, Error = TrezorError>,
    T: From<Vec<u8>>,
    R: From<TrezorResponse>,
    E: From<TrezorError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: C) -> Result<T, E> {
        let command = command.try_into().map_err(E::from)?;
        match self.engine.start(command.into()).map_err(E::from)? {
            EngineTransmit::Device(bytes) => Ok(T::from(bytes)),
            EngineTransmit::Host(_) => Err(E::from(TrezorError::InvalidInput(
                "Trezor profile requested host interaction".into(),
            ))),
        }
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<T>, E> {
        match self.engine.exchange(data).map_err(E::from)? {
            Some(EngineTransmit::Device(bytes)) => Ok(Some(T::from(bytes))),
            Some(EngineTransmit::Host(_)) => Err(E::from(TrezorError::InvalidInput(
                "Trezor profile requested host interaction".into(),
            ))),
            None => Ok(None),
        }
    }

    fn end(self) -> Result<R, E> {
        self.engine.end().map(R::from).map_err(E::from)
    }
}

fn check_device_pin_needed(features: &DeviceFeatures) -> Result<(), TrezorError> {
    if !features.pin_protection {
        return Err(TrezorError::AlreadyUnlocked(TrezorError::NO_PIN_NEEDED));
    }
    if features.unlocked {
        return Err(TrezorError::AlreadyUnlocked(TrezorError::PIN_ALREADY_SENT));
    }
    Ok(())
}

fn expect<M: prost::Message + Default>(
    msg_type: u16,
    want: MessageType,
    payload: &[u8],
    context: &'static str,
) -> Result<M, TrezorError> {
    if msg_type != want as u16 {
        return Err(TrezorError::UnexpectedMessage(msg_type, context));
    }
    api::decode(payload)
}

fn expect_features<P: Profile>(
    msg_type: u16,
    payload: &[u8],
    context: &'static str,
) -> Result<DeviceFeatures, TrezorError> {
    if msg_type != MessageType::Features as u16 {
        return Err(TrezorError::UnexpectedMessage(msg_type, context));
    }
    P::decode_features(payload)
}

fn pin_request_kind(value: Option<i32>) -> PinMatrixRequestKind {
    use pb::pin_matrix_request::PinMatrixRequestType;
    match value {
        Some(value) if value == PinMatrixRequestType::Current as i32 => {
            PinMatrixRequestKind::Current
        }
        Some(value) if value == PinMatrixRequestType::NewFirst as i32 => {
            PinMatrixRequestKind::NewFirst
        }
        Some(value) if value == PinMatrixRequestType::NewSecond as i32 => {
            PinMatrixRequestKind::NewSecond
        }
        Some(value) => PinMatrixRequestKind::Unknown(value),
        None => PinMatrixRequestKind::Current,
    }
}

fn failure_error(failure: pb::Failure) -> TrezorError {
    let cancelled = pb::failure::FailureType::FailureActionCancelled as i32;
    let pin_cancelled = pb::failure::FailureType::FailurePinCancelled as i32;
    match failure.code {
        Some(code) if code == cancelled || code == pin_cancelled => TrezorError::ActionCancelled,
        code => {
            let message = failure.message.unwrap_or_default();
            TrezorError::Failure(
                code.unwrap_or(0),
                if message.is_empty() {
                    "device reported a failure".into()
                } else {
                    message
                },
            )
        }
    }
}

fn trezor_device_features(features: mgmt::Features) -> DeviceFeatures {
    let on_device_passphrase_entry = on_device_passphrase_entry(&features);
    DeviceFeatures {
        major_version: features.major_version,
        minor_version: features.minor_version,
        patch_version: features.patch_version,
        pin_protection: features.pin_protection.unwrap_or(false),
        passphrase_protection: features.passphrase_protection.unwrap_or(false),
        label: features.label,
        initialized: features.initialized,
        unlocked: features.unlocked.unwrap_or(false),
        model: features.model,
        on_device_passphrase_entry,
    }
}

fn device_info(features: DeviceFeatures, network: Network) -> TrezorDeviceInfo {
    TrezorDeviceInfo {
        version: format!(
            "{}.{}.{}",
            features.major_version, features.minor_version, features.patch_version
        ),
        network,
        model: features.model,
        initialized: features.initialized,
        label: features.label,
        on_device_passphrase_entry: features.on_device_passphrase_entry,
        needs_pin_sent: features.pin_protection && !features.unlocked,
        passphrase_protection: features.passphrase_protection,
    }
}

#[cfg(test)]
fn features_info(features: mgmt::Features, network: Network) -> TrezorDeviceInfo {
    device_info(trezor_device_features(features), network)
}

fn on_device_passphrase_entry(features: &mgmt::Features) -> bool {
    features
        .capabilities
        .contains(&(mgmt::features::Capability::PassphraseEntry as i32))
}

type TxType = btc::tx_ack::TransactionType;
type AckInput = btc::tx_ack::transaction_type::TxInputType;
type AckOutput = btc::tx_ack::transaction_type::TxOutputType;
type AckBinOutput = btc::tx_ack::transaction_type::TxOutputBinType;

fn prev_hash_bytes(txid: bitcoin::Txid) -> Vec<u8> {
    let mut bytes = txid.to_byte_array();
    bytes.reverse();
    bytes.to_vec()
}

fn tx_meta(tx: &Transaction) -> TxType {
    TxType {
        version: Some(tx.version.0 as u32),
        lock_time: Some(tx.lock_time.to_consensus_u32()),
        inputs_cnt: Some(tx.input.len() as u32),
        outputs_cnt: Some(tx.output.len() as u32),
        ..Default::default()
    }
}

fn prev_meta(tx: &Transaction) -> TxType {
    tx_meta(tx)
}

fn prev_tx(ctx: &SignCtx, hash: &[u8]) -> Result<Transaction, TrezorError> {
    ctx.psbt
        .inputs
        .iter()
        .filter_map(|input| input.non_witness_utxo.as_ref())
        .find(|tx| prev_hash_bytes(tx.compute_txid()) == hash)
        .cloned()
        .ok_or(TrezorError::InvalidInput(
            "psbt is missing the previous transaction the device asked for".into(),
        ))
}

fn prev_input(tx: &Transaction, index: usize) -> Result<TxType, TrezorError> {
    let input = tx.input.get(index).ok_or(TrezorError::InvalidInput(
        "previous input out of range".into(),
    ))?;
    Ok(TxType {
        inputs: vec![AckInput {
            prev_hash: prev_hash_bytes(input.previous_output.txid),
            prev_index: input.previous_output.vout,
            script_sig: Some(input.script_sig.to_bytes()),
            sequence: Some(input.sequence.to_consensus_u32()),
            ..Default::default()
        }],
        ..Default::default()
    })
}

fn prev_output(tx: &Transaction, index: usize) -> Result<TxType, TrezorError> {
    let output = tx.output.get(index).ok_or(TrezorError::InvalidInput(
        "previous output out of range".into(),
    ))?;
    Ok(TxType {
        bin_outputs: vec![AckBinOutput {
            amount: output.value.to_sat(),
            script_pubkey: output.script_pubkey.to_bytes(),
            ..Default::default()
        }],
        ..Default::default()
    })
}

fn placeholder_hd_node(public_key: Vec<u8>) -> pb::HdNodeType {
    pb::HdNodeType {
        depth: 0,
        fingerprint: 0,
        child_num: 0,
        chain_code: vec![0; 32],
        private_key: None,
        public_key,
    }
}

type Bip32Derivations =
    std::collections::BTreeMap<bitcoin::secp256k1::PublicKey, (Fingerprint, DerivationPath)>;

fn parse_multisig(
    script: &bitcoin::Script,
    derivations: &Bip32Derivations,
    xpubs: &std::collections::BTreeMap<Xpub, (Fingerprint, DerivationPath)>,
) -> Option<btc::MultisigRedeemScriptType> {
    let mut instructions = script.instructions();
    let threshold = match instructions.next()?.ok()? {
        bitcoin::script::Instruction::Op(op) => op.to_u8().checked_sub(0x50)?,
        _ => return None,
    };
    if !(1..=15).contains(&threshold) {
        return None;
    }

    let mut keys = Vec::new();
    let mut trailer = None;
    for instruction in instructions.by_ref() {
        match instruction.ok()? {
            bitcoin::script::Instruction::PushBytes(bytes) if bytes.len() == 33 => {
                keys.push(bytes.as_bytes().to_vec());
            }
            bitcoin::script::Instruction::Op(op) => {
                trailer = Some(op);
                break;
            }
            _ => return None,
        }
    }
    let count = trailer?.to_u8().checked_sub(0x50)?;
    if usize::from(count) != keys.len() || keys.is_empty() || usize::from(threshold) > keys.len() {
        return None;
    }
    if instructions.next()?.ok()?
        != bitcoin::script::Instruction::Op(bitcoin::opcodes::all::OP_CHECKMULTISIG)
    {
        return None;
    }
    if instructions.next().is_some() {
        return None;
    }

    let pubkeys = keys
        .into_iter()
        .map(|key| {
            let node = multisig_node_from_xpubs(&key, derivations, xpubs)
                .unwrap_or_else(|| (placeholder_hd_node(key.clone()), Vec::new()));
            btc::multisig_redeem_script_type::HdNodePathType {
                node: node.0,
                address_n: node.1,
            }
        })
        .collect::<Vec<_>>();

    Some(btc::MultisigRedeemScriptType {
        signatures: vec![Vec::new(); pubkeys.len()],
        m: u32::from(threshold),
        pubkeys,
        ..Default::default()
    })
}

fn multisig_node_from_xpubs(
    key: &[u8],
    derivations: &Bip32Derivations,
    xpubs: &std::collections::BTreeMap<Xpub, (Fingerprint, DerivationPath)>,
) -> Option<(pb::HdNodeType, Vec<u32>)> {
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(key).ok()?;
    let (fingerprint, path) = derivations.get(&pubkey)?;
    let path = path.to_u32_vec();
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    xpubs.iter().find_map(|(xpub, (origin_fp, origin_path))| {
        let origin = origin_path.to_u32_vec();
        if origin_fp != fingerprint || !path.starts_with(&origin) {
            return None;
        }
        let remainder = DerivationPath::from(
            path[origin.len()..]
                .iter()
                .copied()
                .map(ChildNumber::from)
                .collect::<Vec<_>>(),
        );
        if xpub.derive_pub(&secp, &remainder).ok()?.public_key != pubkey {
            return None;
        }
        Some((
            pb::HdNodeType {
                depth: u32::from(xpub.depth),
                fingerprint: u32::from_be_bytes(xpub.parent_fingerprint.to_bytes()),
                child_num: u32::from(xpub.child_number),
                chain_code: xpub.chain_code.to_bytes().to_vec(),
                private_key: None,
                public_key: xpub.public_key.serialize().to_vec(),
            },
            path[origin.len()..].to_vec(),
        ))
    })
}

fn multisig_script_type(address_type: TrezorMultisigAddressType) -> btc::InputScriptType {
    match address_type {
        TrezorMultisigAddressType::Legacy => btc::InputScriptType::Spendmultisig,
        TrezorMultisigAddressType::ShWit => btc::InputScriptType::Spendp2shwitness,
        TrezorMultisigAddressType::Wit => btc::InputScriptType::Spendwitness,
    }
}

struct MultisigKey {
    pubkey: Vec<u8>,
    path: Vec<u32>,
    node: btc::multisig_redeem_script_type::HdNodePathType,
}

fn origin_path(origin: Option<&(Fingerprint, DerivationPath)>) -> Vec<u32> {
    origin.map_or_else(Vec::new, |(_, path)| path.to_u32_vec())
}

fn multisig_script(
    address: &TrezorMultisigAddress,
) -> Result<(btc::MultisigRedeemScriptType, Vec<Vec<u32>>), TrezorError> {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let mut keys = address
        .keys
        .iter()
        .map(|key| multisig_key(&secp, key))
        .collect::<Result<Vec<_>, _>>()?;
    let threshold = usize::from(address.threshold);
    if keys.is_empty() || threshold == 0 || threshold > keys.len() {
        return Err(TrezorError::InvalidInput(format!(
            "multisig address display needs a threshold of 1 to {}, got {}",
            keys.len(),
            address.threshold
        )));
    }
    let paths = keys.iter().map(|key| key.path.clone()).collect();
    if address.sorted {
        keys.sort_by(|left, right| left.pubkey.cmp(&right.pubkey));
    }
    Ok((
        btc::MultisigRedeemScriptType {
            signatures: vec![Vec::new(); keys.len()],
            m: u32::from(address.threshold),
            pubkeys: keys.into_iter().map(|key| key.node).collect(),
            ..Default::default()
        },
        paths,
    ))
}

fn multisig_key(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    key: &DescriptorPublicKey,
) -> Result<MultisigKey, TrezorError> {
    match key {
        DescriptorPublicKey::XPub(key) => {
            if key.wildcard != Wildcard::None {
                return Err(TrezorError::InvalidInput(
                    "multisig address display requires concrete key derivation paths".into(),
                ));
            }
            let derived = key
                .xkey
                .derive_pub(secp, &key.derivation_path)
                .map_err(|e| TrezorError::InvalidInput(e.to_string()))?;
            let mut path = origin_path(key.origin.as_ref());
            path.extend(key.derivation_path.to_u32_vec());
            Ok(MultisigKey {
                pubkey: derived.public_key.serialize().to_vec(),
                path,
                node: btc::multisig_redeem_script_type::HdNodePathType {
                    node: pb::HdNodeType {
                        depth: u32::from(key.xkey.depth),
                        fingerprint: u32::from_be_bytes(key.xkey.parent_fingerprint.to_bytes()),
                        child_num: u32::from(key.xkey.child_number),
                        chain_code: key.xkey.chain_code.to_bytes().to_vec(),
                        private_key: None,
                        public_key: key.xkey.public_key.serialize().to_vec(),
                    },
                    address_n: key.derivation_path.to_u32_vec(),
                },
            })
        }
        DescriptorPublicKey::Single(key) => {
            let SinglePubKey::FullKey(pubkey) = key.key else {
                return Err(TrezorError::InvalidInput(
                    "multisig address display does not support x-only public keys".into(),
                ));
            };
            let pubkey = pubkey.to_bytes();
            Ok(MultisigKey {
                pubkey: pubkey.clone(),
                path: origin_path(key.origin.as_ref()),
                node: btc::multisig_redeem_script_type::HdNodePathType {
                    node: placeholder_hd_node(pubkey),
                    address_n: Vec::new(),
                },
            })
        }
        DescriptorPublicKey::MultiXPub(_) => Err(TrezorError::InvalidInput(
            "multisig address display does not support multipath keys".into(),
        )),
    }
}

fn our_derivation(
    derivations: &std::collections::BTreeMap<
        bitcoin::secp256k1::PublicKey,
        (Fingerprint, DerivationPath),
    >,
    master_fp: Fingerprint,
) -> Option<(bitcoin::secp256k1::PublicKey, DerivationPath)> {
    derivations
        .iter()
        .find(|(_, (fingerprint, _))| *fingerprint == master_fp)
        .map(|(key, (_, path))| (*key, path.clone()))
}

fn unsigned_derivation(
    input: &bitcoin::psbt::Input,
    master_fp: Fingerprint,
) -> Option<(bitcoin::secp256k1::PublicKey, DerivationPath)> {
    input
        .bip32_derivation
        .iter()
        .filter(|(_, (fingerprint, _))| *fingerprint == master_fp)
        .find(|(key, _)| {
            !input
                .partial_sigs
                .contains_key(&bitcoin::PublicKey::new(**key))
        })
        .map(|(key, (_, path))| (*key, path.clone()))
}

fn taproot_derivation(
    input: &bitcoin::psbt::Input,
    master_fp: Fingerprint,
) -> Option<DerivationPath> {
    let internal_key = input.tap_internal_key?;
    input
        .tap_key_origins
        .iter()
        .find(|(key, (_, (fingerprint, _)))| **key == internal_key && *fingerprint == master_fp)
        .map(|(_, (_, (_, path)))| path.clone())
}

fn spend_script_type(
    input: &bitcoin::psbt::Input,
    script_pubkey: &bitcoin::Script,
    xpubs: &std::collections::BTreeMap<Xpub, (Fingerprint, DerivationPath)>,
) -> Result<btc::InputScriptType, TrezorError> {
    let p2sh = script_pubkey.is_p2sh();
    let script = if p2sh {
        let redeem_script = input
            .redeem_script
            .clone()
            .ok_or(TrezorError::InvalidInput(
                "p2sh input has no redeem script".into(),
            ))?;
        if redeem_script.to_p2sh().as_script() != script_pubkey {
            return Err(TrezorError::InvalidInput(
                "p2sh input redeem script does not hash to the prevout script pubkey".into(),
            ));
        }
        redeem_script
    } else {
        script_pubkey.to_owned()
    };
    if script.is_p2wsh() {
        let witness_script = input
            .witness_script
            .clone()
            .ok_or(TrezorError::InvalidInput(
                "p2wsh input has no witness script".into(),
            ))?;
        if witness_script.to_p2wsh() != script {
            return Err(TrezorError::InvalidInput(
                "p2wsh input witness script does not hash to the prevout witness program".into(),
            ));
        }
        if parse_multisig(&witness_script, &input.bip32_derivation, xpubs).is_none() {
            return Err(TrezorError::Unsupported(
                "only multisig witness scripts are supported",
            ));
        }
        return Ok(if p2sh {
            btc::InputScriptType::Spendp2shwitness
        } else {
            btc::InputScriptType::Spendwitness
        });
    }
    if parse_multisig(&script, &input.bip32_derivation, xpubs).is_some() {
        if !p2sh {
            return Err(TrezorError::Unsupported(
                "bare multisig inputs cannot be signed",
            ));
        }
        return Ok(btc::InputScriptType::Spendmultisig);
    }
    if input.witness_script.is_some() {
        return Err(TrezorError::Unsupported(
            "script path signing is not yet supported",
        ));
    }
    match script.witness_version() {
        Some(bitcoin::WitnessVersion::V0) if script.is_p2wpkh() => Ok(if p2sh {
            btc::InputScriptType::Spendp2shwitness
        } else {
            btc::InputScriptType::Spendwitness
        }),
        Some(bitcoin::WitnessVersion::V1) if script.is_p2tr() => {
            Ok(btc::InputScriptType::Spendtaproot)
        }
        Some(_) => Err(TrezorError::Unsupported(
            "only p2wpkh and p2tr witness inputs are supported",
        )),
        None if script.is_p2pkh() => Ok(btc::InputScriptType::Spendaddress),
        None => Err(TrezorError::Unsupported(
            "only p2pkh, p2wpkh and p2tr inputs are supported",
        )),
    }
}

fn our_input(ctx: &SignCtx, index: usize) -> Result<(TxType, bool), TrezorError> {
    let txin = ctx
        .tx
        .input
        .get(index)
        .ok_or(TrezorError::InvalidInput("input out of range".into()))?;
    let psbt_input = ctx
        .psbt
        .inputs
        .get(index)
        .ok_or(TrezorError::InvalidInput("psbt input out of range".into()))?;
    let utxo = psbt_input
        .witness_utxo
        .clone()
        .or_else(|| {
            psbt_input
                .non_witness_utxo
                .as_ref()
                .and_then(|tx| tx.output.get(txin.previous_output.vout as usize))
                .cloned()
        })
        .ok_or(TrezorError::InvalidInput(
            "psbt input has no utxo to sign".into(),
        ))?;
    let belongs_to_device = taproot_derivation(psbt_input, ctx.master_fp).is_some()
        || our_derivation(&psbt_input.bip32_derivation, ctx.master_fp).is_some();
    if ctx.external_inputs && !belongs_to_device {
        let coin_type = if ctx.coin == "Bitcoin" { 0 } else { 1 };
        return Ok((
            TxType {
                inputs: vec![AckInput {
                    address_n: vec![0x8000_0054, 0x8000_0000 | coin_type, 0x8000_0000, 0, 0],
                    prev_hash: prev_hash_bytes(txin.previous_output.txid),
                    prev_index: txin.previous_output.vout,
                    sequence: Some(txin.sequence.to_consensus_u32()),
                    script_type: Some(btc::InputScriptType::Spendwitness as i32),
                    amount: Some(utxo.value.to_sat()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            true,
        ));
    }
    let script_type = spend_script_type(psbt_input, &utxo.script_pubkey, &ctx.psbt.xpub)?;
    let multisig = match script_type {
        btc::InputScriptType::Spendmultisig => {
            psbt_input.redeem_script.as_ref().and_then(|script| {
                parse_multisig(script, &psbt_input.bip32_derivation, &ctx.psbt.xpub)
            })
        }
        btc::InputScriptType::Spendwitness | btc::InputScriptType::Spendp2shwitness => {
            psbt_input.witness_script.as_ref().and_then(|script| {
                parse_multisig(script, &psbt_input.bip32_derivation, &ctx.psbt.xpub)
            })
        }
        _ => None,
    };
    let mut ignore = false;
    let path = match script_type {
        btc::InputScriptType::Spendtaproot => {
            ignore = psbt_input.tap_key_sig.is_some();
            taproot_derivation(psbt_input, ctx.master_fp)
        }
        _ => match unsigned_derivation(psbt_input, ctx.master_fp) {
            Some((_, path)) => Some(path),
            None => {
                ignore = true;
                our_derivation(&psbt_input.bip32_derivation, ctx.master_fp).map(|(_, path)| path)
            }
        },
    }
    .ok_or(TrezorError::InvalidInput(
        "psbt input has no unsigned key derivation for this device".into(),
    ))?;
    let acked = TxType {
        inputs: vec![AckInput {
            address_n: address_n(&path),
            prev_hash: prev_hash_bytes(txin.previous_output.txid),
            prev_index: txin.previous_output.vout,
            sequence: Some(txin.sequence.to_consensus_u32()),
            script_type: Some(script_type as i32),
            amount: Some(utxo.value.to_sat()),
            multisig,
            ..Default::default()
        }],
        ..Default::default()
    };
    Ok((acked, ignore))
}

fn our_output(ctx: &SignCtx, index: usize) -> Result<TxType, TrezorError> {
    let txout = ctx
        .tx
        .output
        .get(index)
        .ok_or(TrezorError::InvalidInput("output out of range".into()))?;
    let psbt_output = ctx
        .psbt
        .outputs
        .get(index)
        .ok_or(TrezorError::InvalidInput("psbt output out of range".into()))?;
    let network = network_of(&ctx.coin);
    let mut ack = AckOutput {
        amount: txout.value.to_sat(),
        ..Default::default()
    };
    if txout.script_pubkey.is_op_return() {
        ack.script_type = Some(btc::OutputScriptType::Paytoopreturn as i32);
        ack.op_return_data = Some(op_return_data(&txout.script_pubkey)?);
        return Ok(TxType {
            outputs: vec![ack],
            ..Default::default()
        });
    }
    let address = bitcoin::Address::from_script(&txout.script_pubkey, network)
        .map_err(|e| TrezorError::InvalidInput(e.to_string()))?;
    ack.script_type = Some(btc::OutputScriptType::Paytoaddress as i32);
    ack.address = Some(address.to_string());
    if let Some(path) = change_derivation(psbt_output, &txout.script_pubkey, ctx.master_fp) {
        ack.script_type = Some(change_script_type(&txout.script_pubkey) as i32);
        ack.address_n = address_n(&path);
        ack.address = None;

        let p2sh = txout.script_pubkey.is_p2sh();
        let redeem = psbt_output.redeem_script.as_ref();
        if let Some(redeem) = redeem {
            if !p2sh {
                return Err(TrezorError::InvalidInput(
                    "change output has a redeem script but is not p2sh".into(),
                ));
            }
            if redeem.to_p2sh() != txout.script_pubkey {
                return Err(TrezorError::InvalidInput(
                    "change output redeem script does not hash to its script pubkey".into(),
                ));
            }
        }

        let nested = redeem.is_some_and(|redeem| redeem.is_p2wsh());
        let witness = txout.script_pubkey.is_p2wsh() || nested;
        if let Some(witness_script) = psbt_output.witness_script.as_ref() {
            if !witness {
                return Err(TrezorError::InvalidInput(
                    "change output has a witness script but is not p2wsh".into(),
                ));
            }
            let program = if nested {
                redeem.expect("nested implies a redeem script")
            } else {
                &txout.script_pubkey
            };
            if witness_script.to_p2wsh() != *program {
                return Err(TrezorError::InvalidInput(
                    "change output witness script does not hash to its witness program".into(),
                ));
            }
        }

        let script = if witness {
            psbt_output.witness_script.as_ref()
        } else {
            redeem
        };
        match script.and_then(|script| {
            parse_multisig(script, &psbt_output.bip32_derivation, &ctx.psbt.xpub)
        }) {
            Some(multisig) => {
                ack.multisig = Some(multisig);
                if !witness {
                    ack.script_type = Some(btc::OutputScriptType::Paytomultisig as i32);
                }
            }
            None if witness => {
                return Err(TrezorError::InvalidInput(
                    "p2wsh change output has no multisig witness script".into(),
                ));
            }
            None if p2sh && !redeem.is_some_and(|redeem| redeem.is_p2wpkh()) => {
                return Err(TrezorError::InvalidInput(
                    "p2sh change output is neither multisig nor p2sh-wrapped segwit".into(),
                ));
            }
            None => {}
        }
    }
    Ok(TxType {
        outputs: vec![ack],
        ..Default::default()
    })
}

fn op_return_data(script_pubkey: &bitcoin::Script) -> Result<Vec<u8>, TrezorError> {
    script_pubkey
        .instructions()
        .flatten()
        .find_map(|instruction| {
            instruction
                .push_bytes()
                .map(|bytes| bytes.as_bytes().to_vec())
        })
        .ok_or(TrezorError::InvalidInput(
            "op_return output has no data to sign".into(),
        ))
}

fn change_derivation(
    output: &bitcoin::psbt::Output,
    script_pubkey: &bitcoin::Script,
    master_fp: Fingerprint,
) -> Option<DerivationPath> {
    if script_pubkey.is_p2tr() {
        let internal_key = output.tap_internal_key?;
        return output
            .tap_key_origins
            .iter()
            .find(|(key, (_, (fingerprint, _)))| **key == internal_key && *fingerprint == master_fp)
            .map(|(_, (_, (_, path)))| path.clone());
    }
    our_derivation(&output.bip32_derivation, master_fp).map(|(_, path)| path)
}

fn change_script_type(script_pubkey: &bitcoin::Script) -> btc::OutputScriptType {
    if script_pubkey.is_p2tr() {
        btc::OutputScriptType::Paytotaproot
    } else if script_pubkey.is_p2wpkh() || script_pubkey.is_p2wsh() {
        btc::OutputScriptType::Paytowitness
    } else if script_pubkey.is_p2sh() {
        btc::OutputScriptType::Paytop2shwitness
    } else {
        btc::OutputScriptType::Paytoaddress
    }
}

fn network_of(coin: &str) -> Network {
    match coin {
        "Bitcoin" => Network::Bitcoin,
        "Regtest" => Network::Regtest,
        _ => Network::Testnet,
    }
}

fn finish_sign(ctx: &mut SignCtx) -> Result<Box<Psbt>, TrezorError> {
    let master_fp = ctx.master_fp;
    let ignored = core::mem::take(&mut ctx.ignored);
    for (index, signature) in core::mem::take(&mut ctx.signatures) {
        if ignored.contains(&(index as usize)) {
            continue;
        }
        let input = ctx
            .psbt
            .inputs
            .get_mut(index as usize)
            .ok_or(TrezorError::InvalidInput(
                "signature for unknown input".into(),
            ))?;
        if input.tap_internal_key.is_some() && input.tap_key_sig.is_none() {
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
                .map_err(|e| TrezorError::InvalidInput(e.to_string()))?;
            input.tap_key_sig = Some(bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: bitcoin::sighash::TapSighashType::Default,
            });
            continue;
        }
        let (public_key, _) = unsigned_derivation(input, master_fp).ok_or(
            TrezorError::InvalidInput("signed input has no key derivation for this device".into()),
        )?;
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&signature)
            .map_err(|e| TrezorError::InvalidInput(e.to_string()))?;
        input.partial_sigs.insert(
            bitcoin::PublicKey::new(public_key),
            bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: bitcoin::sighash::EcdsaSighashType::All,
            },
        );
    }
    Ok(ctx.psbt.clone())
}

enum SignStep {
    Continue(Vec<u8>),
    Done(Box<Psbt>),
}

fn has_unsigned_key(ctx: &SignCtx) -> bool {
    ctx.psbt.inputs.iter().any(|input| {
        input.tap_internal_key.is_none() && unsigned_derivation(input, ctx.master_fp).is_some()
    })
}

fn drive_sign(ctx: &mut SignCtx, request: btc::TxRequest) -> Result<SignStep, TrezorError> {
    if let Some(serialized) = request.serialized.as_ref()
        && let (Some(index), Some(signature)) =
            (serialized.signature_index, serialized.signature.as_ref())
    {
        ctx.signatures.push((index, signature.clone()));
    }

    let details = request.details.unwrap_or_default();
    let request_type = request
        .request_type
        .and_then(|ty| btc::tx_request::RequestType::try_from(ty).ok())
        .ok_or(TrezorError::Unsupported("unknown transaction request"))?;

    let tx = match &details.tx_hash {
        Some(hash) => Some(prev_tx(ctx, hash)?),
        None => None,
    };
    let index = details.request_index.unwrap_or(0) as usize;

    let ack = match (request_type, tx) {
        (btc::tx_request::RequestType::Txfinished, _) => {
            let psbt = finish_sign(ctx)?;
            if has_unsigned_key(ctx) {
                ctx.passes += 1;
                if ctx.passes > MAX_SIGN_PASSES {
                    return Err(TrezorError::InvalidInput(
                        "multisig signing did not converge".into(),
                    ));
                }
                return Ok(SignStep::Continue(api::sign_tx(
                    ctx.tx.input.len() as u32,
                    ctx.tx.output.len() as u32,
                    ctx.tx.version.0 as u32,
                    ctx.tx.lock_time.to_consensus_u32(),
                    &ctx.coin,
                )));
            }
            return Ok(SignStep::Done(psbt));
        }
        (btc::tx_request::RequestType::Txmeta, Some(prev)) => prev_meta(&prev),
        (btc::tx_request::RequestType::Txmeta, None) => tx_meta(&ctx.tx),
        (btc::tx_request::RequestType::Txinput, Some(prev)) => prev_input(&prev, index)?,
        (btc::tx_request::RequestType::Txinput, None) => {
            let (acked, ignore) = our_input(ctx, index)?;
            if ignore {
                ctx.ignored.insert(index);
            }
            acked
        }
        (btc::tx_request::RequestType::Txoutput, Some(prev)) => prev_output(&prev, index)?,
        (btc::tx_request::RequestType::Txoutput, None) => our_output(ctx, index)?,
        (ty, _) => {
            return Err(TrezorError::Unsupported(match ty {
                btc::tx_request::RequestType::Txextradata => "extra data is not supported",
                btc::tx_request::RequestType::Txpaymentreq => "payment requests are not supported",
                _ => "origin transactions are not supported",
            }));
        }
    };
    Ok(SignStep::Continue(api::tx_ack(ack)))
}

pub(crate) fn address_n(path: &DerivationPath) -> Vec<u32> {
    path.into_iter().map(|child| u32::from(*child)).collect()
}

fn parse_xpub(xpub: &str) -> Result<Xpub, TrezorError> {
    Xpub::from_str(xpub).map_err(|e| TrezorError::InvalidInput(e.to_string()))
}

pub(crate) fn script_type(
    format: Option<AddressType>,
    path: &DerivationPath,
) -> btc::InputScriptType {
    match format {
        Some(AddressType::P2pkh) => btc::InputScriptType::Spendaddress,
        Some(AddressType::P2sh) => btc::InputScriptType::Spendp2shwitness,
        Some(AddressType::P2wpkh) => btc::InputScriptType::Spendwitness,
        Some(AddressType::P2tr) => btc::InputScriptType::Spendtaproot,
        _ => script_type_from_purpose(path),
    }
}

fn script_type_from_purpose(path: &DerivationPath) -> btc::InputScriptType {
    match path
        .into_iter()
        .next()
        .map(|child| u32::from(*child) & 0x7fff_ffff)
    {
        Some(44) => btc::InputScriptType::Spendaddress,
        Some(49) => btc::InputScriptType::Spendp2shwitness,
        Some(86) => btc::InputScriptType::Spendtaproot,
        _ => btc::InputScriptType::Spendwitness,
    }
}

fn coin_name(network: Network) -> String {
    match network {
        Network::Bitcoin => "Bitcoin",
        Network::Regtest => "Regtest",
        _ => "Testnet",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common;
    use crate::common::{Command, DisplayAddress, Error, Response, Transmit};
    use prost::Message;

    const XPUB: &str = "xpub6CLSXAha9gjRDyBn9wvyegsMdWKwengbdwY838GnzdyUxXfL9w7YKhczFkTuW4VaApKBw7UYVzbddataVrzYNjK8LWcyBy7MSHfwi15HnZS";

    type Interp = TrezorInterpreter<Command, Transmit, Response, Error>;

    fn decode_transmit<M: Message + Default>(transmit: Transmit) -> (u16, M) {
        let (msg_type, payload) = api::parse_frame(&transmit.payload).unwrap();
        (msg_type, M::decode(payload.as_slice()).unwrap())
    }

    fn framed<M: Message>(msg_type: MessageType, msg: &M) -> Vec<u8> {
        api::frame(msg_type as u16, &msg.encode_to_vec())
    }

    fn public_key(xpub: &str, root_fingerprint: Option<u32>) -> btc::PublicKey {
        btc::PublicKey {
            node: pb::HdNodeType {
                depth: 0,
                fingerprint: 0,
                child_num: 0,
                chain_code: vec![0u8; 32],
                private_key: None,
                public_key: vec![0u8; 33],
            },
            xpub: xpub.to_string(),
            root_fingerprint,
            descriptor: None,
        }
    }

    fn test_key(index: u32) -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        Xpub::from_str(XPUB)
            .unwrap()
            .derive_pub(
                &secp,
                &[bitcoin::bip32::ChildNumber::from_normal_idx(index).unwrap()],
            )
            .unwrap()
            .public_key
    }

    fn ours() -> Fingerprint {
        Fingerprint::from([1u8, 2, 3, 4])
    }

    fn theirs() -> Fingerprint {
        Fingerprint::from([9u8, 9, 9, 9])
    }

    fn p2pkh_script(key: bitcoin::secp256k1::PublicKey) -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PublicKey::new(key).pubkey_hash())
    }

    #[test]
    fn spend_script_type_follows_script_pubkey_not_purpose() {
        let key = test_key(0);
        let input = bitcoin::psbt::Input {
            bip32_derivation: [(key, (ours(), "m/84'/1'/0'/0/0".parse().unwrap()))].into(),
            ..Default::default()
        };
        assert_eq!(
            spend_script_type(&input, &p2pkh_script(key), &Default::default()).unwrap(),
            btc::InputScriptType::Spendaddress
        );
    }

    fn multisig_script_of(
        threshold: i64,
        keys: &[bitcoin::secp256k1::PublicKey],
    ) -> bitcoin::ScriptBuf {
        let mut builder = bitcoin::script::Builder::new().push_int(threshold);
        for key in keys {
            builder = builder.push_key(&bitcoin::PublicKey::new(*key));
        }
        builder
            .push_int(keys.len() as i64)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
            .into_script()
    }

    #[test]
    fn parse_multisig_reads_threshold_and_keys_in_script_order() {
        let keys = [test_key(0), test_key(1), test_key(2)];
        let script = multisig_script_of(2, &keys);
        let parsed = parse_multisig(&script, &Default::default(), &Default::default())
            .expect("multisig script");

        assert_eq!(parsed.m, 2);
        assert_eq!(parsed.signatures.len(), 3);
        assert!(parsed.signatures.iter().all(|sig| sig.is_empty()));
        assert_eq!(
            parsed
                .pubkeys
                .iter()
                .map(|entry| entry.node.public_key.clone())
                .collect::<Vec<_>>(),
            keys.iter()
                .map(|key| key.serialize().to_vec())
                .collect::<Vec<_>>()
        );
        assert!(
            parsed
                .pubkeys
                .iter()
                .all(|entry| entry.address_n.is_empty())
        );
    }

    #[test]
    fn parse_multisig_rejects_non_multisig_scripts() {
        let key = test_key(0);
        assert!(
            parse_multisig(&p2pkh_script(key), &Default::default(), &Default::default()).is_none()
        );
        assert!(
            parse_multisig(
                &bitcoin::ScriptBuf::new(),
                &Default::default(),
                &Default::default()
            )
            .is_none()
        );
    }

    #[test]
    fn parse_multisig_upgrades_nodes_from_global_xpubs() {
        let xpub = Xpub::from_str(XPUB_OURS).unwrap();
        let derived = xpub
            .derive_pub(
                &bitcoin::secp256k1::Secp256k1::verification_only(),
                &"0/7".parse::<DerivationPath>().unwrap(),
            )
            .unwrap();
        let script = multisig_script_of(1, &[derived.public_key]);
        let full_path: DerivationPath = "m/84'/1'/0'/0/7".parse().unwrap();
        let input = bitcoin::psbt::Input {
            bip32_derivation: [(derived.public_key, (ours(), full_path))].into(),
            ..Default::default()
        };
        let xpubs = [(xpub, (ours(), "m/84'/1'/0'".parse().unwrap()))].into();

        let parsed =
            parse_multisig(&script, &input.bip32_derivation, &xpubs).expect("multisig script");
        let entry = &parsed.pubkeys[0];
        assert_eq!(entry.address_n, vec![0, 7]);
        assert_eq!(entry.node.chain_code, xpub.chain_code.to_bytes());
        assert_eq!(entry.node.depth, 3);
    }

    fn sign_ctx_with(signed: &[bitcoin::secp256k1::PublicKey]) -> SignCtx {
        let ours_a = test_key(0);
        let ours_b = test_key(1);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        psbt.inputs[0].bip32_derivation = [
            (ours_a, (ours(), "m/48'/1'/0'/2'/0/0".parse().unwrap())),
            (ours_b, (ours(), "m/48'/1'/1'/2'/0/0".parse().unwrap())),
        ]
        .into();
        for key in signed {
            psbt.inputs[0].partial_sigs.insert(
                bitcoin::PublicKey::new(*key),
                bitcoin::ecdsa::Signature {
                    signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[0x01; 64])
                        .unwrap(),
                    sighash_type: bitcoin::sighash::EcdsaSighashType::All,
                },
            );
        }
        SignCtx {
            psbt: Box::new(psbt),
            tx,
            coin: "Testnet".to_string(),
            master_fp: ours(),
            signatures: Vec::new(),
            passes: 1,
            ignored: std::collections::BTreeSet::new(),
            external_inputs: false,
        }
    }

    fn tx_finished() -> btc::TxRequest {
        btc::TxRequest {
            request_type: Some(btc::tx_request::RequestType::Txfinished as i32),
            ..Default::default()
        }
    }

    #[test]
    fn signing_starts_another_pass_while_one_of_our_keys_is_unsigned() {
        let mut ctx = sign_ctx_with(&[test_key(0)]);
        let step = drive_sign(&mut ctx, tx_finished()).expect("drive sign");
        assert!(matches!(step, SignStep::Continue(_)));
        assert_eq!(ctx.passes, 2);
    }

    #[test]
    fn signing_finishes_once_every_key_of_ours_is_signed() {
        let mut ctx = sign_ctx_with(&[test_key(0), test_key(1)]);
        let step = drive_sign(&mut ctx, tx_finished()).expect("drive sign");
        assert!(matches!(step, SignStep::Done(_)));
        assert_eq!(ctx.passes, 1);
    }

    #[test]
    fn unsupported_transaction_request_branches_are_explicit() {
        for request_type in [
            btc::tx_request::RequestType::Txextradata,
            btc::tx_request::RequestType::Txpaymentreq,
            btc::tx_request::RequestType::Txoriginput,
            btc::tx_request::RequestType::Txorigoutput,
        ] {
            let mut ctx = sign_ctx_with(&[test_key(0), test_key(1)]);
            let Err(error) = drive_sign(
                &mut ctx,
                btc::TxRequest {
                    request_type: Some(request_type as i32),
                    ..Default::default()
                },
            ) else {
                panic!("unsupported request was accepted")
            };
            assert!(matches!(error, TrezorError::Unsupported(_)));
        }
    }

    #[test]
    fn signing_ignores_foreign_keys_when_deciding_to_repeat() {
        let mut ctx = sign_ctx_with(&[test_key(0)]);
        ctx.psbt.inputs[0].bip32_derivation.insert(
            test_key(2),
            (theirs(), "m/48'/1'/2'/2'/0/0".parse().unwrap()),
        );
        ctx.psbt.inputs[0]
            .partial_sigs
            .remove(&bitcoin::PublicKey::new(test_key(1)));
        ctx.psbt.inputs[0].partial_sigs.insert(
            bitcoin::PublicKey::new(test_key(1)),
            bitcoin::ecdsa::Signature {
                signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[0x01; 64]).unwrap(),
                sighash_type: bitcoin::sighash::EcdsaSighashType::All,
            },
        );
        let step = drive_sign(&mut ctx, tx_finished()).expect("drive sign");
        assert!(matches!(step, SignStep::Done(_)));
    }

    #[test]
    fn spend_script_type_rejects_non_multisig_witness_script() {
        let key = test_key(0);
        let input = bitcoin::psbt::Input {
            witness_script: Some(bitcoin::ScriptBuf::new()),
            ..Default::default()
        };
        assert!(matches!(
            spend_script_type(&input, &p2pkh_script(key), &Default::default()),
            Err(TrezorError::Unsupported(_))
        ));
    }

    #[test]
    fn unsigned_derivation_skips_foreign_fingerprint() {
        let mine = test_key(0);
        let other = test_key(1);
        let input = bitcoin::psbt::Input {
            bip32_derivation: [
                (other, (theirs(), "m/48'/1'/0'/2'/0/0".parse().unwrap())),
                (mine, (ours(), "m/84'/1'/0'/0/7".parse().unwrap())),
            ]
            .into(),
            ..Default::default()
        };
        let (key, path) = unsigned_derivation(&input, ours()).unwrap();
        assert_eq!(key, mine);
        assert_eq!(path, "m/84'/1'/0'/0/7".parse::<DerivationPath>().unwrap());
    }

    #[test]
    fn unsigned_derivation_skips_already_signed_key() {
        let key = test_key(0);
        let mut input = bitcoin::psbt::Input {
            bip32_derivation: [(key, (ours(), "m/84'/1'/0'/0/0".parse().unwrap()))].into(),
            ..Default::default()
        };
        assert!(unsigned_derivation(&input, ours()).is_some());
        input.partial_sigs.insert(
            bitcoin::PublicKey::new(key),
            bitcoin::ecdsa::Signature {
                signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64]).unwrap(),
                sighash_type: bitcoin::sighash::EcdsaSighashType::All,
            },
        );
        assert!(unsigned_derivation(&input, ours()).is_none());
    }

    #[test]
    fn taproot_derivation_requires_internal_key() {
        let key = test_key(0);
        let x_only = bitcoin::key::XOnlyPublicKey::from(key);
        let origins = [(
            x_only,
            (vec![], (ours(), "m/86'/1'/0'/0/0".parse().unwrap())),
        )];
        let without_internal_key = bitcoin::psbt::Input {
            tap_key_origins: origins.clone().into(),
            ..Default::default()
        };
        assert!(taproot_derivation(&without_internal_key, ours()).is_none());

        let with_internal_key = bitcoin::psbt::Input {
            tap_internal_key: Some(x_only),
            tap_key_origins: origins.into(),
            ..Default::default()
        };
        assert!(taproot_derivation(&with_internal_key, ours()).is_some());
    }

    #[test]
    fn change_derivation_ignores_foreign_fingerprint() {
        let key = test_key(0);
        let script = p2pkh_script(key);
        let output = bitcoin::psbt::Output {
            bip32_derivation: [(key, (theirs(), "m/84'/1'/0'/1/0".parse().unwrap()))].into(),
            ..Default::default()
        };
        assert!(change_derivation(&output, &script, ours()).is_none());
    }

    #[test]
    fn op_return_data_extracts_payload() {
        let payload: &bitcoin::script::PushBytes = b"bhwi".as_slice().try_into().unwrap();
        let script = bitcoin::ScriptBuf::new_op_return(payload);
        assert_eq!(op_return_data(&script).unwrap(), b"bhwi".to_vec());
    }

    #[test]
    fn passphrase_entry_capability_comes_from_features_not_the_model() {
        let one = mgmt::Features {
            model: Some("1".into()),
            capabilities: vec![mgmt::features::Capability::PassphraseEntry as i32],
            ..Default::default()
        };
        assert!(features_info(one, Network::Testnet).on_device_passphrase_entry);

        let model_t = mgmt::Features {
            model: Some("T".into()),
            capabilities: Vec::new(),
            ..Default::default()
        };
        assert!(!features_info(model_t, Network::Testnet).on_device_passphrase_entry);
    }

    #[test]
    fn get_xpub_encodes_hardened_path() {
        let mut interp = Interp::default();
        let transmit = interp
            .start(Command::GetXpub {
                path: "m/84'/0'/0'".parse().unwrap(),
                display: false,
            })
            .unwrap();
        let (msg_type, msg): (u16, btc::GetPublicKey) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::GetPublicKey as u16);
        assert_eq!(msg.address_n, vec![0x8000_0054, 0x8000_0000, 0x8000_0000]);
        assert_eq!(
            msg.script_type,
            Some(btc::InputScriptType::Spendwitness as i32)
        );
        assert_eq!(msg.coin_name.as_deref(), Some("Bitcoin"));
        assert_eq!(msg.ignore_xpub_magic, Some(true));
    }

    #[test]
    fn get_xpub_parses_public_key() {
        let mut interp = Interp::default();
        interp
            .start(Command::GetXpub {
                path: "m/84'/0'/0'".parse().unwrap(),
                display: false,
            })
            .unwrap();
        let reply = framed(MessageType::PublicKey, &public_key(XPUB, None));
        assert!(interp.exchange(reply).unwrap().is_none());
        match interp.end().unwrap() {
            Response::Xpub(xpub) => assert_eq!(xpub.to_string(), XPUB),
            _ => panic!("expected xpub response"),
        }
    }

    #[test]
    fn get_master_fingerprint_reads_root_fingerprint() {
        let mut interp = Interp::default();
        let transmit = interp.start(Command::GetMasterFingerprint).unwrap();
        let (msg_type, msg): (u16, btc::GetPublicKey) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::GetPublicKey as u16);
        assert!(msg.address_n.is_empty());

        let reply = framed(MessageType::PublicKey, &public_key(XPUB, Some(0x1a2b_3c4d)));
        assert!(interp.exchange(reply).unwrap().is_none());
        match interp.end().unwrap() {
            Response::MasterFingerprint(fingerprint) => {
                assert_eq!(fingerprint, Fingerprint::from([0x1a, 0x2b, 0x3c, 0x4d]))
            }
            _ => panic!("expected master fingerprint response"),
        }
    }

    #[test]
    fn get_master_fingerprint_falls_back_to_xpub() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let reply = framed(MessageType::PublicKey, &public_key(XPUB, None));
        assert!(interp.exchange(reply).unwrap().is_none());
        let expected = Xpub::from_str(XPUB).unwrap().fingerprint();
        match interp.end().unwrap() {
            Response::MasterFingerprint(fingerprint) => assert_eq!(fingerprint, expected),
            _ => panic!("expected master fingerprint response"),
        }
    }

    #[test]
    fn sign_message_encodes_the_request_then_splits_the_signature() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let transmit = interp
            .start(Command::SignMessage {
                message: b"hello".to_vec(),
                path: "m/44'/1'/0'/0/0".parse().unwrap(),
            })
            .unwrap();
        let (msg_type, msg): (u16, btc::SignMessage) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::SignMessage as u16);
        assert_eq!(msg.message, b"hello".to_vec());
        assert_eq!(msg.coin_name.as_deref(), Some("Testnet"));
        assert_eq!(
            msg.script_type,
            Some(btc::InputScriptType::Spendaddress as i32)
        );
        assert_eq!(
            msg.address_n,
            vec![0x8000_002c, 0x8000_0001, 0x8000_0000, 0, 0]
        );

        let mut signature = vec![0x1f];
        signature.extend_from_slice(&[1u8; 64]);
        let signed = framed(
            MessageType::MessageSignature,
            &btc::MessageSignature {
                address: "mtestaddress".to_string(),
                signature,
            },
        );
        assert!(interp.exchange(signed).unwrap().is_none());
        match interp.end().unwrap() {
            Response::Signature(header, signature) => {
                assert_eq!(header, 0x1f);
                assert_eq!(signature.serialize_compact(), [1u8; 64]);
            }
            _ => panic!("expected signature response"),
        }
    }

    #[test]
    fn display_address_by_path_confirms_then_returns() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let transmit = interp
            .start(Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path: "m/86'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: Some(AddressType::P2tr),
                },
                None,
            ))
            .unwrap();
        let (msg_type, msg): (u16, btc::GetAddress) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::GetAddress as u16);
        assert_eq!(
            msg.script_type,
            Some(btc::InputScriptType::Spendtaproot as i32)
        );
        assert_eq!(msg.show_display, Some(true));
        assert_eq!(msg.coin_name.as_deref(), Some("Testnet"));

        let button = framed(MessageType::ButtonRequest, &pb::ButtonRequest::default());
        let ack = interp.exchange(button).unwrap().expect("button ack");
        let (ack_type, _): (u16, pb::ButtonAck) = decode_transmit(ack);
        assert_eq!(ack_type, MessageType::ButtonAck as u16);

        let address = framed(
            MessageType::Address,
            &btc::Address {
                address: "tb1pexampleaddress".to_string(),
                mac: None,
            },
        );
        assert!(interp.exchange(address).unwrap().is_none());
        match interp.end().unwrap() {
            Response::Address(address) => assert_eq!(address, "tb1pexampleaddress"),
            _ => panic!("expected address response"),
        }
    }

    const COSIGNER_A: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const COSIGNER_B: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const OUR_COSIGNER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn multisig_keys() -> Vec<DescriptorPublicKey> {
        [
            format!("[11111111/48h/1h/0h/2h/0/0]{COSIGNER_A}"),
            format!("[22222222/48h/1h/0h/2h/0/1]{COSIGNER_B}"),
            format!("[33333333/48h/1h/0h/2h/0/2]{OUR_COSIGNER}"),
        ]
        .iter()
        .map(|key| key.parse().unwrap())
        .collect()
    }

    fn multisig_address(sorted: bool) -> DisplayAddress {
        DisplayAddress::ByMultisig(common::MultisigDisplayAddress {
            threshold: 2,
            address_type: common::MultisigAddressType::Wit,
            sorted,
            keys: multisig_keys(),
        })
    }

    fn start_multisig(interp: &mut Interp, address: DisplayAddress) -> btc::GetAddress {
        let transmit = interp
            .start(Command::DisplayAddress(address, None))
            .unwrap();
        let (msg_type, msg): (u16, btc::GetAddress) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::GetAddress as u16);
        msg
    }

    fn refuse_path(interp: &mut Interp) -> Option<btc::GetAddress> {
        let failure = pb::Failure {
            code: Some(pb::failure::FailureType::FailureProcessError as i32),
            message: Some("Failed to derive scriptPubKey".to_string()),
        };
        interp
            .exchange(framed(MessageType::Failure, &failure))
            .expect("probe the next path")
            .map(|transmit| decode_transmit::<btc::GetAddress>(transmit).1)
    }

    fn path_of(key: &DescriptorPublicKey) -> Vec<u32> {
        let DescriptorPublicKey::Single(key) = key else {
            panic!("multisig test keys are bare public keys")
        };
        key.origin.as_ref().expect("test key origin").1.to_u32_vec()
    }

    fn cosigner_pubkeys(msg: &btc::GetAddress) -> Vec<String> {
        use bitcoin::hex::DisplayHex;

        msg.multisig
            .as_ref()
            .expect("multisig script")
            .pubkeys
            .iter()
            .map(|key| key.node.public_key.to_lower_hex_string())
            .collect()
    }

    #[test]
    fn display_address_by_multisig_sends_the_cosigner_set() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let msg = start_multisig(&mut interp, multisig_address(false));

        let multisig = msg.multisig.as_ref().expect("multisig script");
        assert_eq!(multisig.m, 2);
        assert_eq!(multisig.signatures.len(), 3);
        assert!(multisig.signatures.iter().all(|sig| sig.is_empty()));
        assert_eq!(
            msg.script_type,
            Some(btc::InputScriptType::Spendwitness as i32)
        );
        assert_eq!(msg.show_display, Some(true));
        assert_eq!(msg.coin_name.as_deref(), Some("Testnet"));
        assert_eq!(
            msg.address_n,
            vec![0x8000_0030, 0x8000_0001, 0x8000_0000, 0x8000_0002, 0, 0]
        );
        assert_eq!(
            cosigner_pubkeys(&msg),
            vec![COSIGNER_A, COSIGNER_B, OUR_COSIGNER]
        );

        let address = framed(
            MessageType::Address,
            &btc::Address {
                address: "tb1qmultisig".to_string(),
                mac: None,
            },
        );
        assert!(interp.exchange(address).unwrap().is_none());
        match interp.end().unwrap() {
            Response::Address(address) => assert_eq!(address, "tb1qmultisig"),
            _ => panic!("expected address response"),
        }
    }

    #[test]
    fn display_address_by_multisig_sorts_keys_for_sortedmulti() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let msg = start_multisig(&mut interp, multisig_address(true));

        assert_eq!(
            cosigner_pubkeys(&msg),
            vec![COSIGNER_B, OUR_COSIGNER, COSIGNER_A]
        );
        assert_eq!(
            msg.address_n,
            vec![0x8000_0030, 0x8000_0001, 0x8000_0000, 0x8000_0002, 0, 0]
        );
    }

    const UNCOMPRESSED_COSIGNER: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    #[test]
    fn display_address_by_multisig_keeps_the_descriptor_key_encoding() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let address = DisplayAddress::ByMultisig(common::MultisigDisplayAddress {
            threshold: 2,
            address_type: common::MultisigAddressType::Legacy,
            sorted: false,
            keys: [
                format!("[11111111/45h/0/0]{UNCOMPRESSED_COSIGNER}"),
                format!("[33333333/45h/0/0]{OUR_COSIGNER}"),
            ]
            .iter()
            .map(|key| key.parse().unwrap())
            .collect(),
        });
        let msg = start_multisig(&mut interp, address);

        assert_eq!(
            cosigner_pubkeys(&msg),
            vec![UNCOMPRESSED_COSIGNER, OUR_COSIGNER]
        );
        assert_eq!(
            msg.script_type,
            Some(btc::InputScriptType::Spendmultisig as i32)
        );
    }

    const XPUB_COSIGNER: &str = "tpubDCHRnuvE95JrpEVTUmr36sK3K9ADf3s3aztpXzL8coBeCTE8cHV8PjxS6SjWJM3GfPn798gyEa3dRPgjoUDSuNfuC9xz4PHznwKEk2XL7X1";
    const XPUB_OURS: &str = "tpubDCZB6sR48s4T5Cr8qHUYSZEFCQMMHRg8AoVKVmvcAP5bRw7ArDKeoNwKAJujV3xCPkBvXH5ejSgbgyN6kREmF7sMd41NdbuHa8n1DZNxSMg";

    #[test]
    fn display_address_by_multisig_builds_hd_nodes_from_extended_keys() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let address = DisplayAddress::ByMultisig(common::MultisigDisplayAddress {
            threshold: 2,
            address_type: common::MultisigAddressType::Wit,
            sorted: false,
            keys: [
                format!("[f5acc2fd/49h/1h/0h]{XPUB_COSIGNER}/0/7"),
                format!("[00000000/84h/1h/0h]{XPUB_OURS}/0/7"),
            ]
            .iter()
            .map(|key| key.parse().unwrap())
            .collect(),
        });
        let msg = start_multisig(&mut interp, address);

        let xpub = Xpub::from_str(XPUB_COSIGNER).unwrap();
        let entry = &msg.multisig.as_ref().expect("multisig script").pubkeys[0];
        assert_eq!(entry.node.depth, 3);
        assert_eq!(entry.node.child_num, 0x8000_0000);
        assert_eq!(
            entry.node.fingerprint,
            u32::from_be_bytes(xpub.parent_fingerprint.to_bytes())
        );
        assert_ne!(
            entry.node.fingerprint,
            u32::from_be_bytes(xpub.fingerprint().to_bytes())
        );
        assert_eq!(entry.node.chain_code, xpub.chain_code.to_bytes());
        assert_eq!(entry.node.public_key, xpub.public_key.serialize());
        assert_eq!(entry.address_n, vec![0, 7]);
        assert_eq!(
            msg.address_n,
            vec![0x8000_0031, 0x8000_0001, 0x8000_0000, 0, 7]
        );
    }

    #[test]
    fn display_address_by_multisig_probes_each_cosigner_path() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let first = start_multisig(&mut interp, multisig_address(false));
        assert_eq!(first.address_n, path_of(&multisig_keys()[0]));

        let second = refuse_path(&mut interp).expect("second candidate");
        assert_eq!(second.address_n, path_of(&multisig_keys()[1]));
        assert_eq!(second.multisig, first.multisig);

        let third = refuse_path(&mut interp).expect("third candidate");
        assert_eq!(third.address_n, path_of(&multisig_keys()[2]));

        let address = framed(
            MessageType::Address,
            &btc::Address {
                address: "tb1qmultisig".to_string(),
                mac: None,
            },
        );
        assert!(interp.exchange(address).unwrap().is_none());
        match interp.end().unwrap() {
            Response::Address(address) => assert_eq!(address, "tb1qmultisig"),
            _ => panic!("expected address response"),
        }
    }

    #[test]
    fn display_address_by_multisig_reports_when_no_path_matches() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        start_multisig(&mut interp, multisig_address(false));
        assert!(refuse_path(&mut interp).is_some());
        assert!(refuse_path(&mut interp).is_some());

        let failure = pb::Failure {
            code: Some(pb::failure::FailureType::FailureProcessError as i32),
            message: Some("Failed to derive scriptPubKey".to_string()),
        };
        assert!(matches!(
            interp.exchange(framed(MessageType::Failure, &failure)),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn device_failure_maps_to_error() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let failure = pb::Failure {
            code: Some(pb::failure::FailureType::FailureProcessError as i32),
            message: Some("boom".to_string()),
        };
        let frame = framed(MessageType::Failure, &failure);
        assert!(matches!(interp.exchange(frame), Err(Error::Rpc(_, _))));
    }

    fn locked_features() -> mgmt::Features {
        mgmt::Features {
            pin_protection: Some(true),
            unlocked: Some(false),
            ..Default::default()
        }
    }

    fn send_pin_command(positions: &str) -> Command {
        Command::SendPin(Some(common::DeviceContext::TrezorManagement(
            crate::trezor::ManagementContext::Pin(
                crate::trezor::HostPin::new(positions.to_owned()).unwrap(),
            ),
        )))
    }

    #[test]
    fn prompt_pin_opens_a_session_then_raises_the_keypad() {
        let mut interp = Interp::default();
        let transmit = interp.start(Command::PromptPin).unwrap();
        let (msg_type, _) = decode_transmit::<mgmt::Initialize>(transmit);
        assert_eq!(msg_type, MessageType::Initialize as u16);

        let transmit = interp
            .exchange(framed(MessageType::Features, &locked_features()))
            .unwrap()
            .unwrap();
        let (msg_type, request) = decode_transmit::<btc::GetPublicKey>(transmit);
        assert_eq!(msg_type, MessageType::GetPublicKey as u16);
        assert_eq!(
            request.address_n,
            vec![0x8000_002c, 0x8000_0001, 0x8000_0000]
        );
        assert_eq!(request.show_display, Some(false));

        assert!(
            interp
                .exchange(framed(
                    MessageType::PinMatrixRequest,
                    &pb::PinMatrixRequest::default(),
                ))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(true)
        ));
    }

    #[test]
    fn prompt_pin_refuses_a_device_that_has_no_pin() {
        let mut interp = Interp::default();
        interp.start(Command::PromptPin).unwrap();
        let features = mgmt::Features {
            pin_protection: Some(false),
            ..Default::default()
        };
        assert!(matches!(
            interp.exchange(framed(MessageType::Features, &features)),
            Err(Error::DeviceAlreadyUnlocked(TrezorError::NO_PIN_NEEDED))
        ));
    }

    #[test]
    fn prompt_pin_refuses_a_device_already_unlocked() {
        let mut interp = Interp::default();
        interp.start(Command::PromptPin).unwrap();
        let features = mgmt::Features {
            pin_protection: Some(true),
            unlocked: Some(true),
            ..Default::default()
        };
        assert!(matches!(
            interp.exchange(framed(MessageType::Features, &features)),
            Err(Error::DeviceAlreadyUnlocked(TrezorError::PIN_ALREADY_SENT))
        ));
    }

    #[test]
    fn send_pin_encodes_positions_and_reports_success() {
        let mut interp = Interp::default();
        let transmit = interp.start(send_pin_command("796")).unwrap();
        let (msg_type, ack) = decode_transmit::<pb::PinMatrixAck>(transmit);
        assert_eq!(msg_type, MessageType::PinMatrixAck as u16);
        assert_eq!(ack.pin, "796");

        let frame = framed(MessageType::PublicKey, &public_key(XPUB, Some(0x0102_0304)));
        assert!(interp.exchange(frame).unwrap().is_none());
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(true)
        ));
    }

    #[test]
    fn send_pin_distinguishes_cancellation_from_rejection() {
        for code in [
            pb::failure::FailureType::FailureActionCancelled,
            pb::failure::FailureType::FailurePinCancelled,
        ] {
            let mut interp = Interp::default();
            interp.start(send_pin_command("1234")).unwrap();
            let failure = pb::Failure {
                code: Some(code as i32),
                message: None,
            };
            assert!(matches!(
                interp.exchange(framed(MessageType::Failure, &failure)),
                Err(Error::AuthenticationRefused)
            ));
        }

        let mut interp = Interp::default();
        interp.start(send_pin_command("1234")).unwrap();
        let failure = pb::Failure {
            code: Some(pb::failure::FailureType::FailurePinInvalid as i32),
            message: None,
        };
        let transmit = interp
            .exchange(framed(MessageType::Failure, &failure))
            .unwrap()
            .unwrap();
        let (msg_type, _) = decode_transmit::<mgmt::GetFeatures>(transmit);
        assert_eq!(msg_type, MessageType::GetFeatures as u16);

        assert!(
            interp
                .exchange(framed(MessageType::Features, &locked_features()))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(false)
        ));
    }

    #[test]
    fn send_pin_failure_on_an_unlocked_device_reports_already_unlocked() {
        let mut interp = Interp::default();
        interp.start(send_pin_command("1234")).unwrap();
        interp
            .exchange(framed(MessageType::Failure, &pb::Failure::default()))
            .unwrap();

        let features = mgmt::Features {
            pin_protection: Some(true),
            unlocked: Some(true),
            ..Default::default()
        };
        assert!(matches!(
            interp.exchange(framed(MessageType::Features, &features)),
            Err(Error::DeviceAlreadyUnlocked(TrezorError::PIN_ALREADY_SENT))
        ));
    }

    #[test]
    fn send_pin_answers_a_passphrase_request_then_succeeds() {
        let mut interp = Interp::default().with_on_device_passphrase(false);
        interp.start(send_pin_command("1234")).unwrap();

        let transmit = interp
            .exchange(framed(
                MessageType::PassphraseRequest,
                &pb::PassphraseRequest::default(),
            ))
            .unwrap()
            .unwrap();
        let (msg_type, ack) = decode_transmit::<pb::PassphraseAck>(transmit);
        assert_eq!(msg_type, MessageType::PassphraseAck as u16);
        assert_eq!(ack.on_device, Some(false));

        let frame = framed(MessageType::PublicKey, &public_key(XPUB, Some(0x0102_0304)));
        assert!(interp.exchange(frame).unwrap().is_none());
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(true)
        ));
    }

    #[test]
    fn a_keypad_request_outside_prompt_pin_cancels_then_points_at_the_pin_commands() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let frame = framed(
            MessageType::PinMatrixRequest,
            &pb::PinMatrixRequest::default(),
        );
        let transmit = interp.exchange(frame).unwrap().expect("cancel");
        let (msg_type, _) = decode_transmit::<mgmt::Cancel>(transmit);
        assert_eq!(msg_type, MessageType::Cancel as u16);

        let failure = framed(
            MessageType::Failure,
            &pb::Failure {
                code: Some(pb::failure::FailureType::FailureActionCancelled as i32),
                message: None,
            },
        );
        let Err(Error::Device(message)) = interp.exchange(failure) else {
            panic!("expected a locked-device error");
        };
        assert_eq!(
            message,
            "Trezor is locked. Unlock by using 'promptpin' and then 'sendpin'."
        );
    }

    #[test]
    fn host_pin_takes_digits_only() {
        use crate::trezor::HostPin;
        assert_eq!(HostPin::new("1234".to_owned()).unwrap().as_str(), "1234");
        assert!(matches!(
            HostPin::new(String::new()),
            Err(TrezorError::NonNumericPin)
        ));
        assert!(matches!(
            HostPin::new("12a4".to_owned()),
            Err(TrezorError::NonNumericPin)
        ));
        // Unicode digits are still digits, but the device only reads ASCII positions.
        assert!(matches!(
            HostPin::new("１２３".to_owned()),
            Err(TrezorError::NonNumericPin)
        ));
    }

    #[test]
    fn host_pin_debug_does_not_leak_the_positions() {
        let pin = crate::trezor::HostPin::new("8675309".to_owned()).unwrap();
        let rendered = format!("{pin:?}");
        assert_eq!(rendered, "HostPin(<redacted>)");
        assert!(!rendered.contains("8675309"));
    }

    #[test]
    fn features_report_whether_a_pin_is_still_needed() {
        assert!(features_info(locked_features(), Network::Testnet).needs_pin_sent);
        let unlocked = mgmt::Features {
            pin_protection: Some(true),
            unlocked: Some(true),
            ..Default::default()
        };
        assert!(!features_info(unlocked, Network::Testnet).needs_pin_sent);
        let no_pin = mgmt::Features {
            pin_protection: Some(false),
            ..Default::default()
        };
        assert!(!features_info(no_pin, Network::Testnet).needs_pin_sent);
    }

    #[test]
    fn send_pin_without_context_is_rejected() {
        assert!(matches!(
            TrezorCommand::try_from(Command::SendPin(None)),
            Err(TrezorError::Unsupported(_))
        ));
    }

    #[test]
    fn wipe_encodes_wipe_device_and_reports_success() {
        let mut interp = Interp::default();
        let transmit = interp.start(Command::Wipe).unwrap();
        let (msg_type, _) = decode_transmit::<mgmt::WipeDevice>(transmit);
        assert_eq!(msg_type, MessageType::WipeDevice as u16);

        let frame = framed(MessageType::Success, &pb::Success::default());
        assert!(interp.exchange(frame).unwrap().is_none());
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(true)
        ));
    }

    fn toggle_passphrase_from(enabled: bool) -> bool {
        let mut interp = Interp::default();
        interp.start(Command::TogglePassphrase).unwrap();
        let features = mgmt::Features {
            passphrase_protection: Some(enabled),
            ..Default::default()
        };
        let transmit = interp
            .exchange(framed(MessageType::Features, &features))
            .unwrap()
            .unwrap();
        let (msg_type, applied) = decode_transmit::<mgmt::ApplySettings>(transmit);
        assert_eq!(msg_type, MessageType::ApplySettings as u16);
        applied.use_passphrase.unwrap()
    }

    #[test]
    fn toggle_passphrase_inverts_the_current_setting() {
        assert!(toggle_passphrase_from(false));
        assert!(!toggle_passphrase_from(true));
    }

    #[test]
    fn unsupported_commands_rejected_at_boundary() {
        let mut interp = Interp::default();
        let display = Command::DisplayAddress(
            DisplayAddress::ByDescriptor {
                index: 0,
                change: false,
                display: true,
                descriptor_name: "x".to_string(),
            },
            None,
        );
        assert!(matches!(
            interp.start(display),
            Err(Error::UnsupportedDisplayAddress(_))
        ));
    }

    #[test]
    fn unexpected_message_type_errors() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let wrong = framed(
            MessageType::Address,
            &btc::Address {
                address: "x".to_string(),
                mac: None,
            },
        );
        assert!(matches!(
            interp.exchange(wrong),
            Err(Error::UnexpectedResult(..))
        ));
    }

    #[test]
    fn malformed_frame_errors() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        assert!(matches!(
            interp.exchange(vec![0, 1, 2]),
            Err(Error::Serialization(_))
        ));
    }

    #[test]
    fn message_without_command_in_progress_errors() {
        let mut interp = Interp::default();
        let frame = framed(MessageType::Features, &mgmt::Features::default());
        assert!(matches!(
            interp.exchange(frame),
            Err(Error::UnexpectedResult(..))
        ));
    }

    #[test]
    fn network_mismatch_rejected() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        interp
            .start(Command::GetXpub {
                path: "m/84'/1'/0'".parse().unwrap(),
                display: false,
            })
            .unwrap();
        let reply = framed(MessageType::PublicKey, &public_key(XPUB, None));
        assert!(matches!(
            interp.exchange(reply),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn passphrase_request_is_auto_acked() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let req = framed(
            MessageType::PassphraseRequest,
            &pb::PassphraseRequest::default(),
        );
        let ack = interp.exchange(req).unwrap().expect("passphrase ack");
        let (ack_type, msg): (u16, pb::PassphraseAck) = decode_transmit(ack);
        assert_eq!(ack_type, MessageType::PassphraseAck as u16);
        assert_eq!(msg.on_device, Some(true));
    }

    fn passphrase_ack(interp: &mut Interp) -> Result<Option<Transmit>, Error> {
        interp.start(Command::GetMasterFingerprint).unwrap();
        interp.exchange(framed(
            MessageType::PassphraseRequest,
            &pb::PassphraseRequest::default(),
        ))
    }

    #[test]
    fn passphrase_from_host_is_sent_when_the_device_cannot_prompt() {
        let mut interp = Interp::default()
            .with_on_device_passphrase(false)
            .with_passphrase(Some(crate::trezor::HostPassphrase::new("secret".into())));
        let ack = passphrase_ack(&mut interp)
            .unwrap()
            .expect("passphrase ack");
        let (_, msg): (u16, pb::PassphraseAck) = decode_transmit(ack);
        assert_eq!(msg.on_device, Some(false));
        assert_eq!(msg.passphrase.as_deref(), Some("secret"));
    }

    #[test]
    fn passphrase_from_host_is_ignored_when_the_device_can_prompt() {
        let mut interp = Interp::default()
            .with_passphrase(Some(crate::trezor::HostPassphrase::new("secret".into())));
        let ack = passphrase_ack(&mut interp)
            .unwrap()
            .expect("passphrase ack");
        let (_, msg): (u16, pb::PassphraseAck) = decode_transmit(ack);
        assert_eq!(msg.on_device, Some(true));
        assert_eq!(msg.passphrase, None);
    }

    #[test]
    fn missing_passphrase_defaults_to_empty_like_python_hwi() {
        let mut interp = Interp::default().with_on_device_passphrase(false);
        let ack = passphrase_ack(&mut interp)
            .unwrap()
            .expect("passphrase ack");
        let (_, msg): (u16, pb::PassphraseAck) = decode_transmit(ack);
        assert_eq!(msg.on_device, Some(false));
        assert_eq!(msg.passphrase.as_deref(), Some(""));
    }

    #[test]
    fn host_passphrase_is_normalized_to_nfkd() {
        let composed = crate::trezor::HostPassphrase::new("caf\u{e9}".into());
        assert_eq!(composed.as_str(), "cafe\u{301}");

        let mut interp = Interp::default()
            .with_on_device_passphrase(false)
            .with_passphrase(Some(crate::trezor::HostPassphrase::new("caf\u{e9}".into())));
        let ack = passphrase_ack(&mut interp)
            .unwrap()
            .expect("passphrase ack");
        let (_, msg): (u16, pb::PassphraseAck) = decode_transmit(ack);
        assert_eq!(msg.passphrase.as_deref(), Some("cafe\u{301}"));
    }

    #[test]
    fn overlong_passphrase_cancels_then_errors() {
        let mut interp = Interp::default()
            .with_on_device_passphrase(false)
            .with_passphrase(Some(crate::trezor::HostPassphrase::new("a".repeat(51))));
        let transmit = passphrase_ack(&mut interp).unwrap().expect("cancel");
        let (msg_type, _) = decode_transmit::<mgmt::Cancel>(transmit);
        assert_eq!(msg_type, MessageType::Cancel as u16);

        let failure = framed(
            MessageType::Failure,
            &pb::Failure {
                code: Some(pb::failure::FailureType::FailureActionCancelled as i32),
                message: None,
            },
        );
        assert!(matches!(
            interp.exchange(failure),
            Err(Error::InvalidInput(_))
        ));

        let mut ok = Interp::default()
            .with_on_device_passphrase(false)
            .with_passphrase(Some(crate::trezor::HostPassphrase::new("a".repeat(50))));
        assert!(passphrase_ack(&mut ok).unwrap().is_some());
    }

    #[test]
    fn setup_enables_passphrase_protection_from_the_global_passphrase() {
        assert!(
            !Interp::default()
                .with_passphrase(Some(crate::trezor::HostPassphrase::new(String::new())))
                .wants_passphrase_protection()
        );
        assert!(!Interp::default().wants_passphrase_protection());
        assert!(
            Interp::default()
                .with_passphrase(Some(crate::trezor::HostPassphrase::new("secret".into())))
                .wants_passphrase_protection()
        );
    }

    #[test]
    fn host_passphrase_is_redacted_when_formatted() {
        let passphrase = crate::trezor::HostPassphrase::new("secret".into());
        assert!(!format!("{passphrase:?}").contains("secret"));
    }

    #[test]
    fn restore_without_a_device_context_is_rejected() {
        let mut interp = Interp::default();
        assert!(matches!(
            interp.start(Command::Restore(
                crate::common::RestoreOptions::default(),
                None
            )),
            Err(Error::MissingCommandInfo(_))
        ));
    }

    #[test]
    fn restore_encodes_the_host_supplied_u2f_counter() {
        let mut interp = Interp::default();
        interp
            .start(Command::Restore(
                crate::common::RestoreOptions::default(),
                Some(common::DeviceContext::TrezorManagement(
                    crate::trezor::ManagementContext::Restore {
                        u2f_counter: 1_763_000_000,
                    },
                )),
            ))
            .unwrap();
        let features = mgmt::Features {
            initialized: Some(false),
            model: Some("T".into()),
            ..Default::default()
        };
        let transmit = interp
            .exchange(framed(MessageType::Features, &features))
            .unwrap()
            .expect("recovery device");
        let (msg_type, recovery) = decode_transmit::<mgmt::RecoveryDevice>(transmit);
        assert_eq!(msg_type, MessageType::RecoveryDevice as u16);
        assert_eq!(recovery.u2f_counter, Some(1_763_000_000));
    }
}
