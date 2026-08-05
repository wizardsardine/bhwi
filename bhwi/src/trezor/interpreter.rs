use core::marker::PhantomData;
use core::str::FromStr;

use bitcoin::address::AddressType;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{Network, NetworkKind, Transaction};

use crate::Interpreter;
use crate::common;
use crate::trezor::api::{self, MessageType};
use crate::trezor::error::TrezorError;
use crate::trezor::proto::{bitcoin as btc, common as pb, management as mgmt};

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
    SignTx(Box<Psbt>),
    Wipe,
    TogglePassphrase,
    Setup {
        label: Option<String>,
        host_entropy: [u8; 32],
    },
    PromptPin,
    SendPin(crate::trezor::HostPin),
}

/// m/44'/1'/0', the key asked for to raise the keypad. The reply is never read.
const PIN_PROMPT_PATH: [u32; 3] = [0x8000_002c, 0x8000_0001, 0x8000_0000];

pub enum TrezorResponse {
    DeviceAction(bool),
    SignedPsbt(Box<Psbt>),
    Info(common::Info),
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    Address(String),
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
    AwaitSuccess,
    AwaitPassphraseCancel,
    AwaitPassphraseSetting,
    AwaitPinPromptFeatures,
    AwaitPinMatrix,
    AwaitPinResult,
    AwaitPinFailureFeatures,
    AwaitSetupFeatures(Box<SetupCtx>),
    AwaitEntropyRequest([u8; 32]),
    AwaitSignKey(Box<Psbt>),
    AwaitTxRequest(Box<SignCtx>),
    Finished(TrezorResponse),
}

struct SetupCtx {
    label: Option<String>,
    passphrase_protection: bool,
    host_entropy: [u8; 32],
}

struct SignCtx {
    psbt: Box<Psbt>,
    tx: Transaction,
    coin: String,
    master_fp: Fingerprint,
    signatures: Vec<(u32, Vec<u8>)>,
}

pub struct TrezorInterpreter<C, T, R, E> {
    state: State,
    network: Network,
    passphrase: Option<crate::trezor::HostPassphrase>,
    on_device_passphrase: bool,
    _marker: PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for TrezorInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            state: State::New,
            network: Network::Bitcoin,
            passphrase: None,
            on_device_passphrase: true,
            _marker: PhantomData,
        }
    }
}

impl<C, T, R, E> TrezorInterpreter<C, T, R, E> {
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn with_passphrase(mut self, passphrase: Option<crate::trezor::HostPassphrase>) -> Self {
        self.passphrase = passphrase;
        self
    }

    pub fn with_on_device_passphrase(mut self, on_device: bool) -> Self {
        self.on_device_passphrase = on_device;
        self
    }

    fn wants_passphrase_protection(&self) -> bool {
        self.passphrase
            .as_ref()
            .is_some_and(|passphrase| !passphrase.as_str().is_empty())
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
        let coin = coin_name(self.network);
        let bytes = match command.try_into().map_err(E::from)? {
            TrezorCommand::Initialize(network) => {
                if let Some(network) = network {
                    self.network = network;
                }
                self.state = State::AwaitFeatures;
                api::initialize()
            }
            TrezorCommand::GetFeatures => {
                self.state = State::AwaitFeatures;
                api::get_features()
            }
            TrezorCommand::GetMasterFingerprint => {
                self.state = State::AwaitPublicKey(PublicKeyKind::Fingerprint);
                api::get_public_key(Vec::new(), false, btc::InputScriptType::Spendaddress, coin)
            }
            TrezorCommand::GetXpub { address_n, display } => {
                self.state = State::AwaitPublicKey(PublicKeyKind::Xpub);
                api::get_public_key(address_n, display, btc::InputScriptType::Spendwitness, coin)
            }
            TrezorCommand::GetAddress {
                address_n,
                display,
                script_type,
            } => {
                self.state = State::AwaitAddress;
                api::get_address(address_n, display, script_type, coin)
            }
            TrezorCommand::Wipe => {
                self.state = State::AwaitSuccess;
                api::wipe_device()
            }
            TrezorCommand::TogglePassphrase => {
                self.state = State::AwaitPassphraseSetting;
                api::get_features()
            }
            TrezorCommand::PromptPin => {
                self.state = State::AwaitPinPromptFeatures;
                api::get_features()
            }
            TrezorCommand::SendPin(pin) => {
                // Nothing may be sent before the ack, so the features exchange that reports
                // on-device passphrase entry has not happened.
                self.on_device_passphrase = false;
                self.state = State::AwaitPinResult;
                api::pin_matrix_ack(pin.as_str())
            }
            TrezorCommand::Setup {
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
            TrezorCommand::SignTx(psbt) => {
                self.state = State::AwaitSignKey(psbt);
                api::get_public_key(Vec::new(), false, btc::InputScriptType::Spendaddress, coin)
            }
        };
        Ok(T::from(bytes))
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<T>, E> {
        let (msg_type, payload) = api::parse_frame(&data).map_err(E::from)?;

        if matches!(self.state, State::New | State::Finished(_)) {
            return Err(E::from(TrezorError::UnexpectedMessage(
                msg_type,
                "no command in progress",
            )));
        }

        if matches!(self.state, State::AwaitPassphraseCancel) {
            return Err(E::from(TrezorError::PassphraseTooLong));
        }
        if msg_type == MessageType::ButtonRequest as u16 {
            return Ok(Some(T::from(api::button_ack())));
        }
        if msg_type == MessageType::PassphraseRequest as u16 {
            if self.on_device_passphrase {
                return Ok(Some(T::from(api::passphrase_ack_on_device())));
            }
            if self
                .passphrase
                .as_ref()
                .is_some_and(crate::trezor::HostPassphrase::is_too_long)
            {
                self.state = State::AwaitPassphraseCancel;
                return Ok(Some(T::from(api::cancel())));
            }
            let passphrase = self
                .passphrase
                .as_ref()
                .map_or("", crate::trezor::HostPassphrase::as_str);
            return Ok(Some(T::from(api::passphrase_ack_from_host(passphrase))));
        }
        if msg_type == MessageType::Failure as u16 && !matches!(self.state, State::AwaitPinResult) {
            let failure: pb::Failure = api::decode(&payload).map_err(E::from)?;
            return Err(E::from(failure_error(failure)));
        }
        if msg_type == MessageType::PinMatrixRequest as u16
            && !matches!(self.state, State::AwaitPinMatrix)
        {
            return Err(E::from(TrezorError::Locked(TrezorError::LOCKED)));
        }

        let response = match &self.state {
            State::AwaitFeatures => {
                let features: mgmt::Features = expect(
                    msg_type,
                    MessageType::Features,
                    &payload,
                    "reading features",
                )
                .map_err(E::from)?;
                TrezorResponse::Info(features_info(features, self.network))
            }
            State::AwaitPublicKey(kind) => {
                let pubkey: btc::PublicKey = expect(
                    msg_type,
                    MessageType::PublicKey,
                    &payload,
                    "reading public key",
                )
                .map_err(E::from)?;
                match kind {
                    PublicKeyKind::Fingerprint => {
                        let fingerprint = match pubkey.root_fingerprint {
                            Some(fingerprint) => Fingerprint::from(fingerprint.to_be_bytes()),
                            None => parse_xpub(&pubkey.xpub).map_err(E::from)?.fingerprint(),
                        };
                        TrezorResponse::MasterFingerprint(fingerprint)
                    }
                    PublicKeyKind::Xpub => {
                        let xpub = parse_xpub(&pubkey.xpub).map_err(E::from)?;
                        if xpub.network != NetworkKind::from(self.network) {
                            return Err(E::from(TrezorError::NetworkMismatch));
                        }
                        TrezorResponse::Xpub(xpub)
                    }
                }
            }
            State::AwaitAddress => {
                let address: btc::Address =
                    expect(msg_type, MessageType::Address, &payload, "reading address")
                        .map_err(E::from)?;
                TrezorResponse::Address(address.address)
            }
            State::AwaitSetupFeatures(_) => {
                let State::AwaitSetupFeatures(ctx) =
                    core::mem::replace(&mut self.state, State::New)
                else {
                    unreachable!("state checked above")
                };
                let features: mgmt::Features = expect(
                    msg_type,
                    MessageType::Features,
                    &payload,
                    "reading features before setup",
                )
                .map_err(E::from)?;
                if features.initialized.unwrap_or(false) {
                    return Err(E::from(TrezorError::AlreadyInitialized));
                }
                if features.model.as_deref() == Some("1") {
                    return Err(E::from(TrezorError::Unsupported(
                        "Trezor One setup needs host PIN entry, which is not supported in this build",
                    )));
                }
                // trezorlib's defaults: Trezor One seeds at 256 bits, later models at 128.
                let strength = if features.model.as_deref() == Some("1") {
                    256
                } else {
                    128
                };
                self.state = State::AwaitEntropyRequest(ctx.host_entropy);
                return Ok(Some(T::from(api::reset_device(
                    strength,
                    ctx.passphrase_protection,
                    ctx.label,
                ))));
            }
            State::AwaitEntropyRequest(host_entropy) => {
                let entropy = *host_entropy;
                let _: mgmt::EntropyRequest = expect(
                    msg_type,
                    MessageType::EntropyRequest,
                    &payload,
                    "reading entropy request",
                )
                .map_err(E::from)?;
                self.state = State::AwaitSuccess;
                return Ok(Some(T::from(api::entropy_ack(&entropy))));
            }
            State::AwaitPassphraseSetting => {
                let features: mgmt::Features = expect(
                    msg_type,
                    MessageType::Features,
                    &payload,
                    "reading passphrase setting",
                )
                .map_err(E::from)?;
                let enabled = features.passphrase_protection.unwrap_or(false);
                self.state = State::AwaitSuccess;
                return Ok(Some(T::from(api::apply_settings(!enabled))));
            }
            State::AwaitPinPromptFeatures => {
                let features: mgmt::Features = expect(
                    msg_type,
                    MessageType::Features,
                    &payload,
                    "reading features before PIN entry",
                )
                .map_err(E::from)?;
                check_pin_needed(&features).map_err(E::from)?;
                self.state = State::AwaitPinMatrix;
                return Ok(Some(T::from(api::get_public_key(
                    PIN_PROMPT_PATH.to_vec(),
                    false,
                    btc::InputScriptType::Spendaddress,
                    coin_name(self.network),
                ))));
            }
            State::AwaitPinMatrix => TrezorResponse::DeviceAction(true),
            State::AwaitPinResult => {
                if msg_type == MessageType::Failure as u16 {
                    self.state = State::AwaitPinFailureFeatures;
                    return Ok(Some(T::from(api::get_features())));
                }
                TrezorResponse::DeviceAction(true)
            }
            State::AwaitPinFailureFeatures => {
                let features: mgmt::Features = expect(
                    msg_type,
                    MessageType::Features,
                    &payload,
                    "reading features after a rejected PIN",
                )
                .map_err(E::from)?;
                check_pin_needed(&features).map_err(E::from)?;
                TrezorResponse::DeviceAction(false)
            }
            State::AwaitSuccess => {
                let _: pb::Success = expect(
                    msg_type,
                    MessageType::Success,
                    &payload,
                    "reading device action result",
                )
                .map_err(E::from)?;
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
                )
                .map_err(E::from)?;
                let master_fp = match pubkey.root_fingerprint {
                    Some(fingerprint) => Fingerprint::from(fingerprint.to_be_bytes()),
                    None => parse_xpub(&pubkey.xpub).map_err(E::from)?.fingerprint(),
                };
                let tx = psbt.unsigned_tx.clone();
                let bytes = api::sign_tx(
                    tx.input.len() as u32,
                    tx.output.len() as u32,
                    tx.version.0 as u32,
                    tx.lock_time.to_consensus_u32(),
                    &coin_name(self.network),
                );
                self.state = State::AwaitTxRequest(Box::new(SignCtx {
                    psbt,
                    tx,
                    coin: coin_name(self.network),
                    master_fp,
                    signatures: Vec::new(),
                }));
                return Ok(Some(T::from(bytes)));
            }
            State::AwaitTxRequest(_) => {
                let State::AwaitTxRequest(mut ctx) =
                    core::mem::replace(&mut self.state, State::New)
                else {
                    unreachable!("state checked above")
                };
                let request: btc::TxRequest = expect(
                    msg_type,
                    MessageType::TxRequest,
                    &payload,
                    "signing transaction",
                )
                .map_err(E::from)?;
                match drive_sign(&mut ctx, request).map_err(E::from)? {
                    SignStep::Continue(bytes) => {
                        self.state = State::AwaitTxRequest(ctx);
                        return Ok(Some(T::from(bytes)));
                    }
                    SignStep::Done(psbt) => TrezorResponse::SignedPsbt(psbt),
                }
            }
            State::AwaitPassphraseCancel => {
                return Err(E::from(TrezorError::PassphraseTooLong));
            }
            State::New | State::Finished(_) => {
                return Err(E::from(TrezorError::UnexpectedMessage(
                    msg_type,
                    "no command in progress",
                )));
            }
        };
        self.state = State::Finished(response);
        Ok(None)
    }

    fn end(self) -> Result<R, E> {
        match self.state {
            State::Finished(response) => Ok(R::from(response)),
            _ => Err(E::from(TrezorError::InvalidInput(
                "interpreter did not reach a response".into(),
            ))),
        }
    }
}

impl TryFrom<common::Command> for TrezorCommand {
    type Error = TrezorError;

    fn try_from(command: common::Command) -> Result<Self, TrezorError> {
        use common::Command;
        Ok(match command {
            Command::Unlock { options } => TrezorCommand::Initialize(options.network),
            Command::GetVersion => TrezorCommand::GetFeatures,
            Command::GetMasterFingerprint => TrezorCommand::GetMasterFingerprint,
            Command::GetXpub { path, display } => TrezorCommand::GetXpub {
                address_n: address_n(&path),
                display,
            },
            Command::DisplayAddress(
                common::DisplayAddress::ByPath {
                    path,
                    display,
                    address_format,
                },
                _,
            ) => TrezorCommand::GetAddress {
                address_n: address_n(&path),
                display,
                script_type: script_type(address_format, &path),
            },
            Command::DisplayAddress(common::DisplayAddress::ByDescriptor { .. }, _) => {
                return Err(TrezorError::UnsupportedDisplayAddress(
                    "descriptor address display is not yet supported",
                ));
            }
            Command::DisplayAddress(common::DisplayAddress::ByMultisig(_), _) => {
                return Err(TrezorError::UnsupportedDisplayAddress(
                    "multisig address display is not yet supported",
                ));
            }
            Command::SignTx(psbt, context) => {
                if context.is_some() {
                    return Err(TrezorError::Unsupported(
                        "Trezor SignTx does not support device context",
                    ));
                }
                TrezorCommand::SignTx(Box::new(psbt))
            }
            Command::SignMessage { .. } => {
                return Err(TrezorError::Unsupported(
                    "sign_message is not yet supported",
                ));
            }
            Command::RegisterWallet { .. } => {
                return Err(TrezorError::Unsupported("register_wallet is not supported"));
            }
            Command::Backup => {
                return Err(TrezorError::Unsupported("backup is not yet supported"));
            }
            Command::Setup(options, context) => {
                let Some(common::DeviceContext::TrezorManagement(
                    crate::trezor::ManagementContext::Setup { host_entropy },
                )) = context
                else {
                    return Err(TrezorError::Unsupported(
                        "Trezor setup requires host entropy in the device context",
                    ));
                };
                TrezorCommand::Setup {
                    label: (!options.label.is_empty()).then_some(options.label),
                    host_entropy,
                }
            }
            Command::Wipe => TrezorCommand::Wipe,
            Command::Restore(..) => {
                return Err(TrezorError::Unsupported("restore is not yet supported"));
            }
            Command::TogglePassphrase => TrezorCommand::TogglePassphrase,
            Command::PromptPin => TrezorCommand::PromptPin,
            Command::SendPin(context) => {
                let Some(common::DeviceContext::TrezorManagement(
                    crate::trezor::ManagementContext::Pin(pin),
                )) = context
                else {
                    return Err(TrezorError::Unsupported(
                        "Trezor sendpin requires the PIN positions in the device context",
                    ));
                };
                TrezorCommand::SendPin(pin)
            }
        })
    }
}

impl From<TrezorResponse> for common::Response {
    fn from(response: TrezorResponse) -> Self {
        match response {
            TrezorResponse::Info(info) => common::Response::Info(info),
            TrezorResponse::MasterFingerprint(fingerprint) => {
                common::Response::MasterFingerprint(fingerprint)
            }
            TrezorResponse::Xpub(xpub) => common::Response::Xpub(xpub),
            TrezorResponse::Address(address) => common::Response::Address(address),
            TrezorResponse::SignedPsbt(psbt) => common::Response::SignedPsbt(*psbt),
            TrezorResponse::DeviceAction(success) => common::Response::DeviceAction(success),
        }
    }
}

fn check_pin_needed(features: &mgmt::Features) -> Result<(), TrezorError> {
    if !features.pin_protection.unwrap_or(false) {
        return Err(TrezorError::AlreadyUnlocked(TrezorError::NO_PIN_NEEDED));
    }
    if features.unlocked.unwrap_or(false) {
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

fn features_info(features: mgmt::Features, network: Network) -> common::Info {
    let on_device = on_device_passphrase_entry(&features);
    common::Info {
        version: format!(
            "{}.{}.{}",
            features.major_version, features.minor_version, features.patch_version
        ),
        networks: vec![network],
        firmware: features.model,
        initialized: features.initialized,
        label: features.label,
        on_device_passphrase_entry: Some(on_device),
        needs_pin_sent: Some(
            features.pin_protection.unwrap_or(false) && !features.unlocked.unwrap_or(false),
        ),
    }
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
) -> Result<btc::InputScriptType, TrezorError> {
    let p2sh = script_pubkey.is_p2sh();
    let script = if p2sh {
        input
            .redeem_script
            .clone()
            .ok_or(TrezorError::InvalidInput(
                "p2sh input has no redeem script".into(),
            ))?
    } else {
        script_pubkey.to_owned()
    };
    if input.witness_script.is_some() {
        return Err(TrezorError::Unsupported(
            "multisig and script path signing are not yet supported",
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

fn our_input(ctx: &SignCtx, index: usize) -> Result<TxType, TrezorError> {
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
    let script_type = spend_script_type(psbt_input, &utxo.script_pubkey)?;
    let path = match script_type {
        btc::InputScriptType::Spendtaproot => taproot_derivation(psbt_input, ctx.master_fp),
        _ => unsigned_derivation(psbt_input, ctx.master_fp).map(|(_, path)| path),
    }
    .ok_or(TrezorError::InvalidInput(
        "psbt input has no unsigned key derivation for this device".into(),
    ))?;
    Ok(TxType {
        inputs: vec![AckInput {
            address_n: address_n(&path),
            prev_hash: prev_hash_bytes(txin.previous_output.txid),
            prev_index: txin.previous_output.vout,
            sequence: Some(txin.sequence.to_consensus_u32()),
            script_type: Some(script_type as i32),
            amount: Some(utxo.value.to_sat()),
            ..Default::default()
        }],
        ..Default::default()
    })
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
    } else if script_pubkey.is_p2wpkh() {
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
    for (index, signature) in core::mem::take(&mut ctx.signatures) {
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
            return Ok(SignStep::Done(psbt));
        }
        (btc::tx_request::RequestType::Txmeta, Some(prev)) => prev_meta(&prev),
        (btc::tx_request::RequestType::Txmeta, None) => tx_meta(&ctx.tx),
        (btc::tx_request::RequestType::Txinput, Some(prev)) => prev_input(&prev, index)?,
        (btc::tx_request::RequestType::Txinput, None) => our_input(ctx, index)?,
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

fn address_n(path: &DerivationPath) -> Vec<u32> {
    path.into_iter().map(|child| u32::from(*child)).collect()
}

fn parse_xpub(xpub: &str) -> Result<Xpub, TrezorError> {
    Xpub::from_str(xpub).map_err(|e| TrezorError::InvalidInput(e.to_string()))
}

fn script_type(format: Option<AddressType>, path: &DerivationPath) -> btc::InputScriptType {
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
            spend_script_type(&input, &p2pkh_script(key)).unwrap(),
            btc::InputScriptType::Spendaddress
        );
    }

    #[test]
    fn spend_script_type_rejects_witness_script() {
        let key = test_key(0);
        let input = bitcoin::psbt::Input {
            witness_script: Some(bitcoin::ScriptBuf::new()),
            ..Default::default()
        };
        assert!(matches!(
            spend_script_type(&input, &p2pkh_script(key)),
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
        assert_eq!(
            features_info(one, Network::Testnet).on_device_passphrase_entry,
            Some(true)
        );

        let model_t = mgmt::Features {
            model: Some("T".into()),
            capabilities: Vec::new(),
            ..Default::default()
        };
        assert_eq!(
            features_info(model_t, Network::Testnet).on_device_passphrase_entry,
            Some(false)
        );
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
    fn prompt_pin_reads_features_then_raises_the_keypad() {
        let mut interp = Interp::default();
        let transmit = interp.start(Command::PromptPin).unwrap();
        let (msg_type, _) = decode_transmit::<mgmt::GetFeatures>(transmit);
        assert_eq!(msg_type, MessageType::GetFeatures as u16);

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
    fn send_pin_rechecks_features_before_reporting_a_wrong_pin() {
        let mut interp = Interp::default();
        interp.start(send_pin_command("1234")).unwrap();

        let transmit = interp
            .exchange(framed(MessageType::Failure, &pb::Failure::default()))
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
    fn a_keypad_request_outside_prompt_pin_points_at_the_pin_commands() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let frame = framed(
            MessageType::PinMatrixRequest,
            &pb::PinMatrixRequest::default(),
        );
        let Err(Error::Device(message)) = interp.exchange(frame) else {
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
        assert_eq!(
            features_info(locked_features(), Network::Testnet).needs_pin_sent,
            Some(true)
        );
        let unlocked = mgmt::Features {
            pin_protection: Some(true),
            unlocked: Some(true),
            ..Default::default()
        };
        assert_eq!(
            features_info(unlocked, Network::Testnet).needs_pin_sent,
            Some(false)
        );
        let no_pin = mgmt::Features {
            pin_protection: Some(false),
            ..Default::default()
        };
        assert_eq!(
            features_info(no_pin, Network::Testnet).needs_pin_sent,
            Some(false)
        );
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
}
