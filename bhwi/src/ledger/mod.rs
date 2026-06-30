pub mod command;
mod merkle;
pub mod store;

pub mod apdu;
pub mod error;
pub mod psbt;
pub mod wallet;

use std::str::FromStr;

use apdu::{ApduCommand, ApduError, ApduResponse, StatusWord};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::consensus::encode::deserialize_partial;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;
use store::{DelegatedStore, StoreError};
pub use wallet::{AddressType, LedgerWalletPolicy, Version, WalletError, singlesig_wallet_policy};

use crate::Interpreter;
use crate::common::{Command, DeviceContext, DisplayAddress, Error, Info, Response};
use crate::device::DeviceId;

pub const LEDGER_DEVICE_ID: DeviceId = DeviceId::new(0x2c97)
    .with_usage_page(0xffa0)
    .with_emulator_path("tcp:127.0.0.1:9999");

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("missing command info: {0}")]
    MissingCommandInfo(&'static str),

    #[error("no error or result returned")]
    NoErrorOrResult,

    #[error("APDU error")]
    Apdu(#[from] ApduError),

    #[error("store error")]
    Store(#[from] StoreError),

    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),

    #[error("operation interrupted")]
    Interrupted,

    #[error("unexpected result for {1}: {0:x?}")]
    UnexpectedResult(Vec<u8>, String),

    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(String),

    #[error("failed to open app: {0:x?}")]
    FailedToOpenApp(Vec<u8>),

    #[error("invalid psbt: {0}")]
    InvalidPsbt(String),
}

impl LedgerError {
    pub fn unexpected_result(data: Vec<u8>, context: impl Into<String>) -> Self {
        LedgerError::UnexpectedResult(data, context.into())
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LedgerCommand {
    OpenApp(Network),
    GetAppInfo,
    GetMasterFingerprint,
    GetXpub {
        path: DerivationPath,
        display: bool,
    },
    GetWalletAddress {
        address: DisplayAddress,
        context: Option<DeviceContext>,
    },
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    RegisterWallet {
        policy: LedgerWalletPolicy,
    },
    SignPsbt {
        psbt: Psbt,
        policy: LedgerWalletPolicy,
        hmac: Option<[u8; 32]>,
    },
}

/// Parsed response from the `GetAppInfo` APDU command.
///
/// The raw response format from the device is:
/// - 1 byte: version tag (0x01)
/// - length-prefixed string: app name
/// - length-prefixed string: app version
/// - length-prefixed bytes: state flags
#[derive(Debug, Clone)]
pub struct GetAppInfoResponse {
    pub app_name: String,
    pub version: String,
    pub flags: Vec<u8>,
}

impl GetAppInfoResponse {
    pub fn network(&self) -> Network {
        if self.app_name == "Bitcoin" {
            Network::Bitcoin
        } else {
            Network::Testnet
        }
    }
}

impl TryFrom<Vec<u8>> for GetAppInfoResponse {
    type Error = String;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        if data.is_empty() || data[0] != 0x01 {
            return Err(format!(
                "invalid version response header: expected 0x01, got {:02x}",
                data.first().map_or(0, |b| *b)
            ));
        }
        let (app_name, i): (String, usize) = deserialize_partial(&data[1..])
            .map_err(|e| format!("failed to parse app name: {e}"))?;
        let (version, j): (String, usize) = deserialize_partial(&data[1 + i..])
            .map_err(|e| format!("failed to parse version: {e}"))?;
        let (flags, _): (Vec<u8>, usize) = deserialize_partial(&data[1 + i + j..])
            .map_err(|e| format!("failed to parse flags: {e}"))?;
        Ok(GetAppInfoResponse {
            app_name,
            version,
            flags,
        })
    }
}

pub enum LedgerResponse {
    AppInfo(GetAppInfoResponse),
    MasterFingerprint(Fingerprint),
    Signature(u8, Signature),
    TaskDone,
    Xpub(Xpub),
    Address(String),
    WalletHmac([u8; 32]),
    SignedPsbt(Psbt),
}

#[derive(Default)]
#[allow(clippy::large_enum_variant)]
enum State {
    #[default]
    New,
    Running {
        command: LedgerCommand,
        store: Option<DelegatedStore>,
    },
    GetWalletAddress(GetWalletAddressStep),
    Finished(LedgerResponse),
}

enum GetWalletAddressStep {
    Fingerprint {
        address: DisplayAddress,
        context: Option<DeviceContext>,
    },
    Xpub {
        address: DisplayAddress,
        fingerprint: Fingerprint,
        display: bool,
        context: Option<DeviceContext>,
    },
    WalletAddress {
        store: Option<DelegatedStore>,
    },
}

pub struct LedgerInterpreter<C, T, R, E> {
    state: State,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for LedgerInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            state: State::default(),
            _marker: std::marker::PhantomData,
        }
    }
}

fn apply_psbt_signature(psbt: &mut Psbt, yielded: &[u8]) -> Result<(), LedgerError> {
    let (input_index, yielded_object) = parse_sign_psbt_yielded(yielded)?;
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or_else(|| LedgerError::InvalidPsbt(format!("invalid input index {input_index}")))?;

    let SignPsbtYieldedObject::Partial(partial_signature) = yielded_object else {
        return Ok(());
    };

    match partial_signature {
        psbt::PartialSignature::Sig(pubkey, sig) => {
            input.partial_sigs.insert(pubkey, sig);
        }
        psbt::PartialSignature::TapScriptSig(pubkey, Some(leaf_hash), sig) => {
            input.tap_script_sigs.insert((pubkey, leaf_hash), sig);
        }
        psbt::PartialSignature::TapScriptSig(_, None, sig) => {
            input.tap_key_sig = Some(sig);
        }
    }
    Ok(())
}

enum SignPsbtYieldedObject {
    Partial(psbt::PartialSignature),
    Ignored,
}

fn parse_sign_psbt_yielded(data: &[u8]) -> Result<(usize, SignPsbtYieldedObject), LedgerError> {
    let (tag, read) = deserialize_unchecked_varint(data)?;
    match tag {
        // TODO: Parse and store MuSig2 yields once rust-bitcoin exposes the
        // corresponding PSBT fields.
        tag if tag >= 0x80000000 => {
            let (input_index, _) = deserialize_unchecked_varint(&data[read..])?;
            Ok((
                input_index_to_usize(input_index)?,
                SignPsbtYieldedObject::Ignored,
            ))
        }
        input_index => {
            let partial_signature =
                psbt::PartialSignature::from_slice(&data[read..]).map_err(|_| {
                    LedgerError::InvalidPsbt("invalid partial signature yield".to_string())
                })?;
            Ok((
                input_index_to_usize(input_index)?,
                SignPsbtYieldedObject::Partial(partial_signature),
            ))
        }
    }
}

fn input_index_to_usize(input_index: u64) -> Result<usize, LedgerError> {
    usize::try_from(input_index).map_err(|_| {
        LedgerError::InvalidPsbt(format!("input index does not fit usize: {input_index}"))
    })
}

fn deserialize_unchecked_varint(data: &[u8]) -> Result<(u64, usize), LedgerError> {
    let first = data
        .first()
        .ok_or_else(|| LedgerError::InvalidPsbt("missing sign_psbt yield tag".to_string()))?;
    match first {
        0x00..=0xFC => Ok((*first as u64, 1)),
        0xFD => {
            let bytes = data.get(1..3).ok_or_else(|| {
                LedgerError::InvalidPsbt("truncated sign_psbt yield varint".to_string())
            })?;
            let value = u16::from_le_bytes(bytes.try_into().expect("slice length checked")) as u64;
            if value < 0xFD {
                return Err(LedgerError::InvalidPsbt(
                    "non-minimal sign_psbt yield varint".to_string(),
                ));
            }
            Ok((value, 3))
        }
        0xFE => {
            let bytes = data.get(1..5).ok_or_else(|| {
                LedgerError::InvalidPsbt("truncated sign_psbt yield varint".to_string())
            })?;
            let value = u32::from_le_bytes(bytes.try_into().expect("slice length checked")) as u64;
            if value < 0x10000 {
                return Err(LedgerError::InvalidPsbt(
                    "non-minimal sign_psbt yield varint".to_string(),
                ));
            }
            Ok((value, 5))
        }
        0xFF => {
            let bytes = data.get(1..9).ok_or_else(|| {
                LedgerError::InvalidPsbt("truncated sign_psbt yield varint".to_string())
            })?;
            let value = u64::from_le_bytes(bytes.try_into().expect("slice length checked"));
            if value < 0x1_0000_0000 {
                return Err(LedgerError::InvalidPsbt(
                    "non-minimal sign_psbt yield varint".to_string(),
                ));
            }
            Ok((value, 9))
        }
    }
}

impl<C, T, R, E> Interpreter for LedgerInterpreter<C, T, R, E>
where
    C: TryInto<LedgerCommand, Error = LedgerError>,
    T: From<ApduCommand>,
    R: From<LedgerResponse>,
    E: From<LedgerError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: LedgerCommand = command.try_into()?;
        let (transmit, store) = match command {
            LedgerCommand::GetAppInfo => (Self::Transmit::from(command::get_version()), None),
            LedgerCommand::GetMasterFingerprint => (
                Self::Transmit::from(command::get_master_fingerprint()),
                None,
            ),
            LedgerCommand::GetXpub { ref path, display } => (
                Self::Transmit::from(command::get_extended_pubkey(path, display)),
                None,
            ),
            LedgerCommand::OpenApp(network) => {
                (Self::Transmit::from(command::open_app(network)), None)
            }
            LedgerCommand::SignMessage {
                ref message,
                ref path,
            } => {
                let message_length = message.len();
                let chunks = message.chunks(64).collect::<Vec<&[u8]>>();
                let mut store = DelegatedStore::new();
                let message_commitment_root = store.add_known_list(&chunks);
                (
                    Self::Transmit::from(command::sign_message(
                        message_length,
                        &message_commitment_root,
                        path,
                    )),
                    Some(store),
                )
            }
            LedgerCommand::GetWalletAddress { address, context } => {
                self.state =
                    State::GetWalletAddress(GetWalletAddressStep::Fingerprint { address, context });
                return Ok(Self::Transmit::from(command::get_master_fingerprint()));
            }
            LedgerCommand::RegisterWallet { ref policy } => (
                Self::Transmit::from(command::register_wallet(policy).map_err(LedgerError::from)?),
                Some(policy.to_store().map_err(LedgerError::from)?),
            ),
            LedgerCommand::SignPsbt {
                ref psbt,
                ref policy,
                ref hmac,
            } => {
                if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
                    return Err(LedgerError::InvalidPsbt(
                        "psbt input count does not match unsigned transaction".to_string(),
                    )
                    .into());
                }
                if psbt.outputs.len() != psbt.unsigned_tx.output.len() {
                    return Err(LedgerError::InvalidPsbt(
                        "psbt output count does not match unsigned transaction".to_string(),
                    )
                    .into());
                }

                let global_map = psbt::get_v2_global_pairs(psbt)
                    .into_iter()
                    .map(psbt::deserialize_pair)
                    .collect::<Vec<_>>();
                let input_maps = psbt
                    .inputs
                    .iter()
                    .zip(&psbt.unsigned_tx.input)
                    .map(|(input, txin)| {
                        psbt::get_v2_input_pairs(input, txin)
                            .into_iter()
                            .map(psbt::deserialize_pair)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let output_maps = psbt
                    .outputs
                    .iter()
                    .zip(&psbt.unsigned_tx.output)
                    .map(|(output, txout)| {
                        psbt::get_v2_output_pairs(output, txout)
                            .into_iter()
                            .map(psbt::deserialize_pair)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let global_commitment = store::get_merkleized_map_commitment(&global_map);
                let input_commitments = input_maps
                    .iter()
                    .map(|map| store::get_merkleized_map_commitment(map))
                    .collect::<Vec<_>>();
                let output_commitments = output_maps
                    .iter()
                    .map(|map| store::get_merkleized_map_commitment(map))
                    .collect::<Vec<_>>();

                let mut store = policy.to_store().map_err(LedgerError::from)?;
                store.add_known_mapping(&global_map);
                for map in &input_maps {
                    store.add_known_mapping(map);
                }
                for map in &output_maps {
                    store.add_known_mapping(map);
                }
                let input_commitments_root = store.add_known_list(&input_commitments);
                let output_commitments_root = store.add_known_list(&output_commitments);

                (
                    Self::Transmit::from(
                        command::sign_psbt(
                            &global_commitment,
                            psbt.inputs.len(),
                            &input_commitments_root,
                            psbt.outputs.len(),
                            &output_commitments_root,
                            policy,
                            hmac.as_ref(),
                        )
                        .map_err(LedgerError::from)?,
                    ),
                    Some(store),
                )
            }
        };
        self.state = State::Running { command, store };
        Ok(transmit)
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        let res = ApduResponse::try_from(data).map_err(LedgerError::from)?;
        let state = std::mem::take(&mut self.state);
        let (next_state, result) = match state {
            State::GetWalletAddress(GetWalletAddressStep::Fingerprint {
                mut address,
                context,
            }) => {
                if res.data.len() < 4 {
                    return Err(LedgerError::unexpected_result(
                        res.data,
                        "display address: master fingerprint",
                    )
                    .into());
                }
                let mut fg = [0x00; 4];
                fg.copy_from_slice(&res.data[0..4]);
                let fingerprint = Fingerprint::from(fg);
                match &mut address {
                    DisplayAddress::ByPath { path, display, .. } => {
                        let children: Vec<_> = path.as_ref().to_vec();
                        if children.len() < 5 {
                            return Err(LedgerError::UnsupportedDisplayAddress(
                                "Ledger requires a full 5-level derivation path (e.g. m/84'/0'/0'/0/0)".into(),
                            )
                            .into());
                        }
                        let account_path = DerivationPath::from(children[..3].to_vec());
                        let display = *display;
                        let cmd = Self::Transmit::from(command::get_extended_pubkey(
                            &account_path,
                            false,
                        ));
                        (
                            State::GetWalletAddress(GetWalletAddressStep::Xpub {
                                address,
                                fingerprint,
                                display,
                                context,
                            }),
                            Some(cmd),
                        )
                    }
                    DisplayAddress::ByDescriptor {
                        index,
                        change,
                        display,
                        ..
                    } => {
                        let (ledger_policy, wallet_hmac) = context
                            .as_ref()
                            .map(|ctx| match ctx {
                                DeviceContext::Ledger { wallet_policy, wallet_hmac } => {
                                    (wallet_policy.clone(), *wallet_hmac)
                                }
                            })
                            .ok_or(LedgerError::MissingCommandInfo(
                                "Ledger requires DeviceContext::Ledger for descriptor-based address display",
                            ))?;
                        let store = Some(ledger_policy.to_store().map_err(LedgerError::from)?);
                        let cmd = Self::Transmit::from(
                            command::get_wallet_address(
                                &ledger_policy,
                                wallet_hmac.as_ref(),
                                *change,
                                *index,
                                *display,
                            )
                            .map_err(LedgerError::from)?,
                        );
                        (
                            State::GetWalletAddress(GetWalletAddressStep::WalletAddress { store }),
                            Some(cmd),
                        )
                    }
                }
            }
            State::GetWalletAddress(GetWalletAddressStep::Xpub {
                address,
                fingerprint,
                display,
                context,
            }) => {
                let xpub = Xpub::from_str(&String::from_utf8_lossy(&res.data)).map_err(|_| {
                    LedgerError::unexpected_result(res.data, "display address: xpub")
                })?;
                let (ledger_policy, wallet_hmac, change, address_index) = match address {
                    DisplayAddress::ByPath { path, .. } => {
                        let children: Vec<_> = path.as_ref().to_vec();
                        let change =
                            children[3] == bitcoin::bip32::ChildNumber::from_normal_idx(1).unwrap();
                        let address_index = u32::from(children[4]);
                        let policy = singlesig_wallet_policy(&path, fingerprint, xpub)
                            .map_err(LedgerError::from)?;
                        (
                            LedgerWalletPolicy::new(String::new(), Version::V2, policy),
                            None,
                            change,
                            address_index,
                        )
                    }
                    DisplayAddress::ByDescriptor { index, change, .. } => {
                        let (wallet_policy, wallet_hmac) = context
                            .as_ref()
                            .map(|ctx| match ctx {
                                DeviceContext::Ledger { wallet_policy, wallet_hmac } => {
                                    (wallet_policy.clone(), *wallet_hmac)
                                }
                            })
                            .ok_or(LedgerError::MissingCommandInfo(
                                "Ledger requires DeviceContext::Ledger for descriptor-based address display",
                            ))?;
                        (wallet_policy, wallet_hmac, change, index)
                    }
                };
                let store = Some(ledger_policy.to_store().map_err(LedgerError::from)?);
                let cmd = Self::Transmit::from(
                    command::get_wallet_address(
                        &ledger_policy,
                        wallet_hmac.as_ref(),
                        change,
                        address_index,
                        display,
                    )
                    .map_err(LedgerError::from)?,
                );
                (
                    State::GetWalletAddress(GetWalletAddressStep::WalletAddress { store }),
                    Some(cmd),
                )
            }
            State::GetWalletAddress(GetWalletAddressStep::WalletAddress { mut store }) => {
                if res.status_word == StatusWord::Deny {
                    (State::Finished(LedgerResponse::TaskDone), None)
                } else if res.status_word == StatusWord::InterruptedExecution {
                    if let Some(ref mut s) = store {
                        let transmit = s.execute(res.data).map_err(LedgerError::from)?;
                        let cmd = Self::Transmit::from(command::continue_interrupted(transmit));
                        self.state =
                            State::GetWalletAddress(GetWalletAddressStep::WalletAddress { store });
                        return Ok(Some(cmd));
                    } else {
                        return Err(LedgerError::Interrupted.into());
                    }
                } else if res.status_word != StatusWord::OK {
                    return Err(
                        LedgerError::unexpected_result(res.data, "display address status").into(),
                    );
                } else {
                    let address = String::from_utf8(res.data)
                        .map_err(|e| LedgerError::unexpected_result(vec![], e.to_string()))?;
                    (State::Finished(LedgerResponse::Address(address)), None)
                }
            }
            State::Running { mut store, command } => {
                if res.status_word == StatusWord::InterruptedExecution {
                    if let Some(ref mut s) = store {
                        let transmit = s.execute(res.data).map_err(LedgerError::from)?;
                        let cmd = Self::Transmit::from(command::continue_interrupted(transmit));
                        self.state = State::Running { store, command };
                        return Ok(Some(cmd));
                    } else {
                        return Err(LedgerError::Interrupted.into());
                    }
                }
                match command {
                    LedgerCommand::GetAppInfo => {
                        if res.status_word != StatusWord::OK {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "get_version response",
                            )
                            .into());
                        }
                        let response = GetAppInfoResponse::try_from(res.data.clone())
                            .map_err(|e| LedgerError::unexpected_result(res.data, e))?;
                        (State::Finished(LedgerResponse::AppInfo(response)), None)
                    }
                    LedgerCommand::GetMasterFingerprint => {
                        if res.data.len() < 4 {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "master fingerprint response",
                            )
                            .into());
                        } else {
                            let mut fg = [0x00; 4];
                            fg.copy_from_slice(&res.data[0..4]);
                            (
                                State::Finished(LedgerResponse::MasterFingerprint(
                                    Fingerprint::from(fg),
                                )),
                                None,
                            )
                        }
                    }
                    LedgerCommand::GetXpub { .. } => {
                        let xpub = Xpub::from_str(&String::from_utf8_lossy(&res.data))
                            .map_err(|_| LedgerError::unexpected_result(res.data, "xpub string"))?;
                        (State::Finished(LedgerResponse::Xpub(xpub)), None)
                    }
                    LedgerCommand::OpenApp(..) => {
                        if matches!(
                            res.status_word,
                            StatusWord::OK | StatusWord::ClaNotSupported
                        ) {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        } else {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "open app response",
                            )
                            .into());
                        }
                    }
                    LedgerCommand::SignMessage { .. } => match res.status_word {
                        StatusWord::Deny
                        | StatusWord::ClaNotSupported
                        | StatusWord::SignatureFail => {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        }
                        StatusWord::OK => {
                            let header = res.data[0];
                            let sig = Signature::from_compact(&res.data[1..]).map_err(|_| {
                                LedgerError::unexpected_result(res.data, "signature compact data")
                            })?;
                            (
                                State::Finished(LedgerResponse::Signature(header, sig)),
                                None,
                            )
                        }
                        _ => {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "sign message status",
                            )
                            .into());
                        }
                    },
                    LedgerCommand::GetWalletAddress { .. } => {
                        if res.status_word == StatusWord::Deny {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        } else if res.status_word == StatusWord::OK {
                            let address = String::from_utf8(res.data).map_err(|e| {
                                LedgerError::unexpected_result(vec![], e.to_string())
                            })?;
                            (State::Finished(LedgerResponse::Address(address)), None)
                        } else {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "display address status",
                            )
                            .into());
                        }
                    }
                    LedgerCommand::RegisterWallet { .. } => {
                        if res.status_word != StatusWord::OK {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "register wallet status",
                            )
                            .into());
                        }
                        if res.data.len() < 64 {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "register wallet: response too short",
                            )
                            .into());
                        }
                        let mut hmac = [0u8; 32];
                        hmac.copy_from_slice(&res.data[32..64]);
                        (State::Finished(LedgerResponse::WalletHmac(hmac)), None)
                    }
                    LedgerCommand::SignPsbt { mut psbt, .. } => match res.status_word {
                        StatusWord::Deny
                        | StatusWord::ClaNotSupported
                        | StatusWord::SignatureFail => {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        }
                        StatusWord::OK => {
                            let store = store.ok_or(LedgerError::Interrupted)?;
                            for yielded in store.yielded() {
                                apply_psbt_signature(&mut psbt, &yielded)?;
                            }
                            (State::Finished(LedgerResponse::SignedPsbt(psbt)), None)
                        }
                        _ => {
                            return Err(LedgerError::unexpected_result(
                                res.data,
                                "sign psbt status",
                            )
                            .into());
                        }
                    },
                }
            }
            State::New => (State::New, None),
            State::Finished(_) => (state, None),
        };
        self.state = next_state;
        Ok(result)
    }

    fn end(self) -> Result<Self::Response, Self::Error> {
        if let State::Finished(res) = self.state {
            Ok(Self::Response::from(res))
        } else {
            Err(LedgerError::NoErrorOrResult.into())
        }
    }
}

impl TryFrom<Command> for LedgerCommand {
    type Error = LedgerError;
    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Unlock { options } => options
                .network
                .map(Self::OpenApp)
                .ok_or(LedgerError::MissingCommandInfo("network")),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, display } => Ok(Self::GetXpub { path, display }),
            Command::DisplayAddress(addr, ctx) => Ok(Self::GetWalletAddress {
                address: addr,
                context: ctx,
            }),
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetAppInfo),
            Command::RegisterWallet { name, policy } => Ok(Self::RegisterWallet {
                policy: LedgerWalletPolicy::new(name, Version::V2, policy),
            }),
            Command::SignTx(psbt, context) => {
                let (ledger_policy, wallet_hmac) = context
                    .map(|ctx| match ctx {
                        DeviceContext::Ledger {
                            wallet_policy,
                            wallet_hmac,
                        } => (wallet_policy, wallet_hmac),
                    })
                    .ok_or(LedgerError::MissingCommandInfo("ledger sign tx context"))?;
                Ok(Self::SignPsbt {
                    psbt,
                    policy: ledger_policy,
                    hmac: wallet_hmac,
                })
            }
        }
    }
}

impl From<LedgerResponse> for Response {
    fn from(res: LedgerResponse) -> Response {
        match res {
            LedgerResponse::AppInfo(res) => Response::Info(Info {
                version: res.version.to_string(),
                networks: vec![res.network()],
                firmware: Some(res.app_name),
            }),
            LedgerResponse::Signature(header, signature) => Response::Signature(header, signature),
            LedgerResponse::TaskDone => Response::TaskDone,
            LedgerResponse::Xpub(xpub) => Response::Xpub(xpub),
            LedgerResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            LedgerResponse::Address(address) => Response::Address(address),
            LedgerResponse::WalletHmac(hmac) => Response::WalletHmac(hmac),
            LedgerResponse::SignedPsbt(psbt) => Response::SignedPsbt(psbt),
        }
    }
}

impl From<LedgerError> for Error {
    fn from(error: LedgerError) -> Error {
        match error {
            LedgerError::MissingCommandInfo(e) => Error::MissingCommandInfo(e),
            LedgerError::NoErrorOrResult => Error::NoErrorOrResult,
            LedgerError::Apdu(e) => Error::Serialization(format!("{:?}", e)),
            LedgerError::Store(_) => Error::Request("Store operation failed"),
            LedgerError::Wallet(_) => Error::Request("Wallet operation failed"),
            LedgerError::Interrupted => Error::Request("Operation interrupted"),
            LedgerError::UnexpectedResult(data, ctx) => Error::unexpected_result(data, ctx),
            LedgerError::UnsupportedDisplayAddress(ctx) => Error::UnsupportedDisplayAddress(ctx),
            LedgerError::FailedToOpenApp(_) => Error::AuthenticationRefused,
            LedgerError::InvalidPsbt(e) => Error::Serialization(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XONLY: [u8; 32] = [
        0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61, 0x5d,
        0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07, 0x58,
        0x71, 0xaa,
    ];

    fn encode_unchecked_varint(value: u64) -> Vec<u8> {
        match value {
            0..=0xFC => vec![value as u8],
            0xFD..=0xFFFF => {
                let mut out = vec![0xFD];
                out.extend_from_slice(&(value as u16).to_le_bytes());
                out
            }
            0x1_0000..=0xFFFF_FFFF => {
                let mut out = vec![0xFE];
                out.extend_from_slice(&(value as u32).to_le_bytes());
                out
            }
            _ => {
                let mut out = vec![0xFF];
                out.extend_from_slice(&value.to_le_bytes());
                out
            }
        }
    }

    fn assert_ignored(payload: &[u8], expected_input_index: usize) {
        let (input_index, object) = parse_sign_psbt_yielded(payload).expect("payload should parse");
        assert_eq!(input_index, expected_input_index);
        assert!(matches!(object, SignPsbtYieldedObject::Ignored));
    }

    #[test]
    fn parse_legacy_partial_taproot_without_tapleaf() {
        let mut payload = encode_unchecked_varint(3);
        payload.push(32);
        payload.extend_from_slice(&XONLY);
        payload.extend_from_slice(&[0xaa; 64]);

        let (input_index, object) =
            parse_sign_psbt_yielded(&payload).expect("payload should parse");
        assert_eq!(input_index, 3);
        assert!(matches!(
            object,
            SignPsbtYieldedObject::Partial(psbt::PartialSignature::TapScriptSig(_, None, _))
        ));
    }

    #[test]
    fn parse_reserved_musig_pubnonce_tag_is_ignored() {
        let mut payload = encode_unchecked_varint(0xFFFF_FFFF);
        payload.extend(encode_unchecked_varint(7));
        payload.extend_from_slice(&[0xaa; 164]);

        assert_ignored(&payload, 7);
    }

    #[test]
    fn parse_reserved_musig_partial_signature_tag_is_ignored() {
        let mut payload = encode_unchecked_varint(0xFFFF_FFFE);
        payload.extend(encode_unchecked_varint(2));
        payload.extend_from_slice(&[0xbb; 98]);

        assert_ignored(&payload, 2);
    }

    #[test]
    fn parse_unknown_reserved_tag_is_ignored() {
        let mut payload = encode_unchecked_varint(0x89AB_CDEF);
        payload.extend(encode_unchecked_varint(11));
        payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert_ignored(&payload, 11);
    }
}
