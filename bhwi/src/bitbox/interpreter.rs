use std::marker::PhantomData;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use prost::Message;

use crate::Interpreter;
use crate::common::{
    Command, DeviceBackup, DeviceContext, DisplayAddress, Error, Info, Recipient, Response,
    Transmit,
};

use super::api;
use super::error::BitBoxError;
use super::noise::{HandshakeState, NoiseState};
use super::proto as pb;
use super::sign::{OurKey, Transaction, TxOutput, apply_signatures, is_schnorr};
use super::{
    OP_HER_COMEZ_TEH_HANDSHAEK, OP_I_CAN_HAS_HANDSHAEK, OP_I_CAN_HAS_PAIRIN_VERIFICASHUN,
    OP_NOISE_MSG, OP_UNLOCK, RESPONSE_SUCCESS,
};
use super::{antiklepto, policy};

/// Public BitBox02 command surface. Mirrors the shape of Coldcard/Ledger command enums
/// in this crate: converted from `common::Command` by `TryFrom`. The target network is not
/// carried per-command; it is interpreter state (see `BitBoxInterpreter::with_network`).
#[derive(Clone, Debug)]
pub enum BitBoxCommand {
    UnlockAndPair,
    GetVersion,
    GetMasterFingerprint,
    GetXpub {
        keypath: DerivationPath,
        display: bool,
    },
    /// P2WPKH (bip84) address at a plain BIP-32 keypath.
    ShowSimpleAddress {
        keypath: DerivationPath,
        simple_type: pb::btc_script_config::SimpleType,
        display: bool,
    },
    /// Address derived from a registered miniscript policy.
    ShowPolicyAddress {
        keypath: DerivationPath,
        policy: policy::Policy,
        display: bool,
    },
    IsScriptConfigRegistered {
        policy: policy::Policy,
    },
    RegisterScriptConfig {
        policy: policy::Policy,
        name: String,
    },
    SignPsbt {
        psbt: Box<Psbt>,
        /// Optional pre-computed script config with keypath. If `None`, the interpreter
        /// infers per-input from the PSBT's redeem/witness scripts (single-sig only).
        force_script_config: Option<pb::BtcScriptConfigWithKeypath>,
        /// Optional registered wallet policy to sign under. Resolved into a forced script
        /// config once the device fingerprint is known (needed for multisig/miniscript).
        policy: Option<policy::Policy>,
    },
    /// Sign a message with a single-sig key at `keypath`.
    SignMessage {
        keypath: DerivationPath,
        simple_type: pb::btc_script_config::SimpleType,
        message: Vec<u8>,
    },
    /// Address derived from a registered policy at `change`/`index`. The account keypath is
    /// resolved from the policy key matching the device's own fingerprint.
    ShowDescriptorAddress {
        policy: policy::Policy,
        change: bool,
        index: u32,
        display: bool,
    },
    /// Restore the device from its currently-loaded mnemonic (simulator seeding).
    RestoreFromMnemonic {
        timestamp: u32,
        timezone_offset: i32,
    },
    /// Start the BitBox02 mnemonic backup display flow.
    Backup,
}

#[derive(Debug)]
pub enum BitBoxResponse {
    TaskDone,
    Info(Info),
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    Address(String),
    IsRegistered(bool),
    /// A policy was registered on the device. BitBox02 has no equivalent of Ledger's wallet
    /// hmac (address display re-sends the policy), so registration carries no token.
    Registered,
    SignedPsbt(Box<Psbt>),
    Signature(u8, bitcoin::secp256k1::ecdsa::Signature),
    Backup,
}

/// Internal state machine.
enum State {
    New,
    // Unlock/pair flow.
    WaitUnlockAck,
    WaitHandshakeInit,
    WaitHandshake1(HandshakeState),
    WaitHandshake2(HandshakeState),
    WaitPairingConfirm(HandshakeState, Option<String>),
    // Standard encrypted query flow.
    WaitEncryptedResponse(EncryptedContext),
    // Sign PSBT: two-phase — first fetch our fingerprint, then drive the sign loop.
    SignPsbtWaitFingerprint(SignInit),
    SignPsbtWaitNext(Box<SignCtx>),
    // Sign message: two-phase anti-klepto handshake.
    SignMessageWaitCommitment {
        host_nonce: [u8; 32],
    },
    SignMessageWaitSig {
        host_nonce: [u8; 32],
        signer_commitment: Vec<u8>,
    },
    // Descriptor address: first fetch our fingerprint to resolve the account keypath.
    ShowAddrWaitFingerprint(ShowAddrInit),
    Finished(BitBoxResponse),
}

struct SignInit {
    psbt: Box<Psbt>,
    force_script_config: Option<pb::BtcScriptConfigWithKeypath>,
    policy: Option<policy::Policy>,
}

struct ShowAddrInit {
    policy: policy::Policy,
    change: bool,
    index: u32,
    display: bool,
}

/// Context threaded through every round of the `btc_sign` loop.
struct SignCtx {
    psbt: Box<Psbt>,
    transaction: Transaction,
    our_keys: Vec<OurKey>,
    sigs: Vec<Vec<u8>>,
    is_inputs_pass2: bool,
    phase: SignPhase,
}

/// What the previous round of the sign loop just did — determines how the next response
/// bytes are interpreted before dispatching on `BtcSignNextResponse.type`.
#[allow(clippy::enum_variant_names)]
enum SignPhase {
    /// Waiting for an ordinary next-response; no signature expected in it.
    ExpectNext,
    /// Sent a pass-2 `BtcSignInput` for a schnorr input; the next response carries the
    /// signature directly.
    ExpectNextWithSig,
    /// Sent a pass-2 `BtcSignInput(commitment)` for a non-schnorr input; expecting a
    /// `HostNonce` response with the anti-klepto signer commitment.
    ExpectHostNonce { host_nonce: [u8; 32] },
    /// Sent an `AntikleptoSignature` request; the next response carries a verifiable
    /// signature that must be anti-klepto-checked before use.
    ExpectAntikleptoSig {
        host_nonce: [u8; 32],
        signer_commitment: Vec<u8>,
    },
}

enum SignStep {
    Continue { ctx: Box<SignCtx>, bytes: Vec<u8> },
    Done { psbt: Box<Psbt> },
}

/// What the interpreter expects back from the device after an encrypted query, so it can
/// convert the decoded protobuf into a `BitBoxResponse`.
enum EncryptedContext {
    Version,
    MasterFingerprint,
    Xpub,
    Address,
    IsRegistered,
    RegisterScriptConfig,
    RestoreFromMnemonic,
    Backup,
}

pub struct BitBoxInterpreter<'a, C, T, R, E> {
    state: State,
    noise: &'a mut NoiseState,
    network: bitcoin::Network,
    _marker: PhantomData<(C, T, R, E)>,
}

impl<'a, C, T, R, E> BitBoxInterpreter<'a, C, T, R, E> {
    pub fn new(noise: &'a mut NoiseState) -> Self {
        Self {
            state: State::New,
            noise,
            network: bitcoin::Network::Bitcoin,
            _marker: PhantomData,
        }
    }

    /// Set the network used for coin selection and xpub encoding. Defaults to mainnet.
    pub fn with_network(mut self, network: bitcoin::Network) -> Self {
        self.network = network;
        self
    }
}

fn framed(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(op);
    out.extend_from_slice(payload);
    out
}

fn expect_success(response: &[u8]) -> Result<&[u8], BitBoxError> {
    if response.is_empty() || response[0] != RESPONSE_SUCCESS {
        return Err(BitBoxError::UnexpectedResponse);
    }
    Ok(&response[1..])
}

fn encrypted_transmit(bytes: Vec<u8>) -> Transmit {
    Transmit {
        recipient: Recipient::Device,
        payload: bytes,
        encrypted: true,
    }
}

fn plain_transmit(bytes: Vec<u8>) -> Transmit {
    Transmit {
        recipient: Recipient::Device,
        payload: bytes,
        encrypted: false,
    }
}

fn build_sign_init_request(coin: pb::BtcCoin, tx: &Transaction) -> pb::request::Request {
    pb::request::Request::BtcSignInit(pb::BtcSignInitRequest {
        coin: coin as _,
        script_configs: tx.script_configs.clone(),
        output_script_configs: vec![],
        version: tx.version,
        num_inputs: tx.inputs.len() as _,
        num_outputs: tx.outputs.len() as _,
        locktime: tx.locktime,
        format_unit: pb::btc_sign_init_request::FormatUnit::Default as _,
        contains_silent_payment_outputs: false,
    })
}

/// Pick the single-sig script type BitBox02 signs a message under, from the BIP-44-style
/// purpose in the keypath. Defaults to native segwit.
fn simple_type_from_path(path: &DerivationPath) -> pb::btc_script_config::SimpleType {
    use pb::btc_script_config::SimpleType;
    match path.into_iter().next() {
        Some(ChildNumber::Hardened { index: 49 }) => SimpleType::P2wpkhP2sh,
        Some(ChildNumber::Hardened { index: 86 }) => SimpleType::P2tr,
        _ => SimpleType::P2wpkh,
    }
}

/// Build the full address keypath for a policy address: our account origin path (identified
/// by the device fingerprint) followed by `change`/`index`.
fn descriptor_keypath(
    policy: &policy::Policy,
    our_fingerprint: Fingerprint,
    change: bool,
    index: u32,
) -> Result<DerivationPath, BitBoxError> {
    let our_key = policy
        .pubkeys
        .iter()
        .find(|k| k.master_fingerprint == Some(our_fingerprint))
        .ok_or(BitBoxError::InvalidInput(
            "device key not found in descriptor policy",
        ))?;
    let account = our_key.path.as_ref().ok_or(BitBoxError::InvalidInput(
        "device key has no origin path in descriptor policy",
    ))?;
    let full = account.extend([
        ChildNumber::from_normal_idx(u32::from(change))
            .map_err(|_| BitBoxError::InvalidInput("invalid change value"))?,
        ChildNumber::from_normal_idx(index)
            .map_err(|_| BitBoxError::InvalidInput("invalid address index"))?,
    ]);
    Ok(full)
}

/// Build the forced script config a policy PSBT signs under: the registered policy's script
/// config plus the account-level keypath of the device's own key (identified by fingerprint).
fn policy_script_config(
    policy: &policy::Policy,
    fingerprint: &[u8],
) -> Result<pb::BtcScriptConfigWithKeypath, BitBoxError> {
    let our_key = policy
        .pubkeys
        .iter()
        .find(|k| {
            k.master_fingerprint
                .map(|fp| fp.as_bytes().to_vec())
                .as_deref()
                == Some(fingerprint)
        })
        .ok_or(BitBoxError::InvalidInput(
            "device key not found in descriptor policy",
        ))?;
    let account = our_key.path.clone().ok_or(BitBoxError::InvalidInput(
        "device key has no origin path in descriptor policy",
    ))?;
    Ok(pb::BtcScriptConfigWithKeypath {
        script_config: Some(policy.clone().into()),
        keypath: account.to_u32_vec(),
    })
}

/// Decode a `BtcSignNextResponse` from a top-level `Response`, accepting either the direct
/// `BtcSignNext` variant or the nested `Btc(BtcResponse::SignNext)` variant.
fn decode_sign_next(
    response: pb::response::Response,
) -> Result<pb::BtcSignNextResponse, BitBoxError> {
    match response {
        pb::response::Response::BtcSignNext(next) => Ok(next),
        pb::response::Response::Btc(pb::BtcResponse {
            response: Some(pb::btc_response::Response::SignNext(next)),
        }) => Ok(next),
        _ => Err(BitBoxError::UnexpectedResponse),
    }
}

impl<C, T, R, E> BitBoxInterpreter<'_, C, T, R, E> {
    fn drive_sign(
        &mut self,
        mut ctx: Box<SignCtx>,
        data: Vec<u8>,
    ) -> Result<SignStep, BitBoxError> {
        let body = expect_success(&data)?;
        let decrypted = self.noise.decrypt(body)?;
        let response = api::decode_response(&decrypted)?;

        // Resolve any prior phase (signature extraction / anti-klepto handshake).
        let next_response = match std::mem::replace(&mut ctx.phase, SignPhase::ExpectNext) {
            SignPhase::ExpectNext => decode_sign_next(response)?,
            SignPhase::ExpectNextWithSig => {
                let next = decode_sign_next(response)?;
                if !next.has_signature {
                    return Err(BitBoxError::BtcSign("missing schnorr signature".into()));
                }
                ctx.sigs.push(next.signature.clone());
                next
            }
            SignPhase::ExpectHostNonce { host_nonce } => {
                let next = decode_sign_next(response)?;
                let ty = pb::btc_sign_next_response::Type::try_from(next.r#type)
                    .map_err(|_| BitBoxError::UnexpectedResponse)?;
                if ty != pb::btc_sign_next_response::Type::HostNonce {
                    return Err(BitBoxError::UnexpectedResponse);
                }
                let signer_commitment = next
                    .anti_klepto_signer_commitment
                    .as_ref()
                    .ok_or(BitBoxError::UnexpectedResponse)?
                    .commitment
                    .clone();
                let request = pb::request::Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::AntikleptoSignature(
                        pb::AntiKleptoSignatureRequest {
                            host_nonce: host_nonce.to_vec(),
                        },
                    )),
                });
                let bytes = self.build_encrypted(request)?;
                ctx.phase = SignPhase::ExpectAntikleptoSig {
                    host_nonce,
                    signer_commitment,
                };
                return Ok(SignStep::Continue { ctx, bytes });
            }
            SignPhase::ExpectAntikleptoSig {
                host_nonce,
                signer_commitment,
            } => {
                let next = decode_sign_next(response)?;
                if !next.has_signature {
                    return Err(BitBoxError::BtcSign("missing anti-klepto signature".into()));
                }
                antiklepto::verify_ecdsa(&host_nonce, &signer_commitment, &next.signature)?;
                ctx.sigs.push(next.signature.clone());
                next
            }
        };

        let ty = pb::btc_sign_next_response::Type::try_from(next_response.r#type)
            .map_err(|_| BitBoxError::UnexpectedResponse)?;
        match ty {
            pb::btc_sign_next_response::Type::Input => {
                let input_index = next_response.index as usize;
                if input_index >= ctx.transaction.inputs.len() {
                    return Err(BitBoxError::UnexpectedResponse);
                }
                let input = &ctx.transaction.inputs[input_index];
                let script_config_index = input.script_config_index as usize;
                let input_is_schnorr =
                    is_schnorr(&ctx.transaction.script_configs[script_config_index]);
                let perform_antiklepto = ctx.is_inputs_pass2 && !input_is_schnorr;
                let host_nonce = if perform_antiklepto {
                    Some(antiklepto::gen_host_nonce()?)
                } else {
                    None
                };
                let request = pb::request::Request::BtcSignInput(pb::BtcSignInputRequest {
                    prev_out_hash: input.prev_out_hash.clone(),
                    prev_out_index: input.prev_out_index,
                    prev_out_value: input.prev_out_value,
                    sequence: input.sequence,
                    keypath: input.keypath.to_u32_vec(),
                    script_config_index: input.script_config_index,
                    host_nonce_commitment: host_nonce.as_ref().map(|n| {
                        pb::AntiKleptoHostNonceCommitment {
                            commitment: antiklepto::host_commit(n).to_vec(),
                        }
                    }),
                });
                let bytes = self.build_encrypted(request)?;

                if let Some(nonce) = host_nonce {
                    ctx.phase = SignPhase::ExpectHostNonce { host_nonce: nonce };
                } else if ctx.is_inputs_pass2 {
                    ctx.phase = SignPhase::ExpectNextWithSig;
                } else {
                    ctx.phase = SignPhase::ExpectNext;
                }

                // After the last input of pass 1, the next input round is pass 2.
                if !ctx.is_inputs_pass2 && input_index == ctx.transaction.inputs.len() - 1 {
                    ctx.is_inputs_pass2 = true;
                }

                Ok(SignStep::Continue { ctx, bytes })
            }
            pb::btc_sign_next_response::Type::PrevtxInit => {
                let prevtx = ctx.transaction.inputs[next_response.index as usize].get_prev_tx()?;
                let request = pb::request::Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::PrevtxInit(
                        pb::BtcPrevTxInitRequest {
                            version: prevtx.version,
                            num_inputs: prevtx.inputs.len() as _,
                            num_outputs: prevtx.outputs.len() as _,
                            locktime: prevtx.locktime,
                        },
                    )),
                });
                let bytes = self.build_encrypted(request)?;
                Ok(SignStep::Continue { ctx, bytes })
            }
            pb::btc_sign_next_response::Type::PrevtxInput => {
                let prevtx = ctx.transaction.inputs[next_response.index as usize].get_prev_tx()?;
                let prev_input = &prevtx.inputs[next_response.prev_index as usize];
                let request = pb::request::Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::PrevtxInput(
                        pb::BtcPrevTxInputRequest {
                            prev_out_hash: prev_input.prev_out_hash.clone(),
                            prev_out_index: prev_input.prev_out_index,
                            signature_script: prev_input.signature_script.clone(),
                            sequence: prev_input.sequence,
                        },
                    )),
                });
                let bytes = self.build_encrypted(request)?;
                Ok(SignStep::Continue { ctx, bytes })
            }
            pb::btc_sign_next_response::Type::PrevtxOutput => {
                let prevtx = ctx.transaction.inputs[next_response.index as usize].get_prev_tx()?;
                let prev_output = &prevtx.outputs[next_response.prev_index as usize];
                let request = pb::request::Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::PrevtxOutput(
                        pb::BtcPrevTxOutputRequest {
                            value: prev_output.value,
                            pubkey_script: prev_output.pubkey_script.clone(),
                        },
                    )),
                });
                let bytes = self.build_encrypted(request)?;
                Ok(SignStep::Continue { ctx, bytes })
            }
            pb::btc_sign_next_response::Type::Output => {
                let output = &ctx.transaction.outputs[next_response.index as usize];
                let request = pb::request::Request::BtcSignOutput(match output {
                    TxOutput::Internal(o) => pb::BtcSignOutputRequest {
                        ours: true,
                        value: o.value,
                        keypath: o.keypath.to_u32_vec(),
                        script_config_index: o.script_config_index,
                        ..Default::default()
                    },
                    TxOutput::External(o) => pb::BtcSignOutputRequest {
                        ours: false,
                        value: o.value,
                        r#type: o.payload.output_type as _,
                        payload: o.payload.data.clone(),
                        ..Default::default()
                    },
                });
                let bytes = self.build_encrypted(request)?;
                Ok(SignStep::Continue { ctx, bytes })
            }
            pb::btc_sign_next_response::Type::Done => {
                let SignCtx {
                    mut psbt,
                    sigs,
                    our_keys,
                    ..
                } = *ctx;
                apply_signatures(&mut psbt, &sigs, &our_keys)?;
                Ok(SignStep::Done { psbt })
            }
            pb::btc_sign_next_response::Type::HostNonce
            | pb::btc_sign_next_response::Type::PaymentRequest => {
                Err(BitBoxError::UnexpectedResponse)
            }
        }
    }

    fn build_encrypted(&mut self, request: pb::request::Request) -> Result<Vec<u8>, BitBoxError> {
        let proto_msg = pb::Request {
            request: Some(request),
        };
        let encoded = proto_msg.encode_to_vec();
        let encrypted = self.noise.encrypt(&encoded)?;
        Ok(framed(OP_NOISE_MSG, &encrypted))
    }

    fn start_encrypted_query(
        &mut self,
        request: pb::request::Request,
        ctx: EncryptedContext,
    ) -> Result<Vec<u8>, BitBoxError> {
        let bytes = self.build_encrypted(request)?;
        self.state = State::WaitEncryptedResponse(ctx);
        Ok(bytes)
    }

    fn handle_encrypted_response(
        &mut self,
        ctx: EncryptedContext,
        data: Vec<u8>,
    ) -> Result<BitBoxResponse, BitBoxError> {
        let body = expect_success(&data)?;
        let decrypted = self.noise.decrypt(body)?;
        let response = api::decode_response(&decrypted)?;
        use pb::response::Response as R;
        match (ctx, response) {
            (EncryptedContext::Version, R::DeviceInfo(info)) => Ok(BitBoxResponse::Info(Info {
                version: info.version,
                networks: vec![],
                firmware: Some(info.name),
            })),
            (EncryptedContext::MasterFingerprint, R::Fingerprint(f)) => {
                if f.fingerprint.len() != 4 {
                    return Err(BitBoxError::InvalidSignature);
                }
                let mut fp = [0u8; 4];
                fp.copy_from_slice(&f.fingerprint);
                Ok(BitBoxResponse::MasterFingerprint(Fingerprint::from(&fp)))
            }
            (EncryptedContext::Xpub, R::Pub(p)) => {
                use std::str::FromStr;
                let xpub = Xpub::from_str(&p.r#pub)
                    .map_err(|e| BitBoxError::BtcSign(format!("bad xpub: {e}")))?;
                Ok(BitBoxResponse::Xpub(xpub))
            }
            (EncryptedContext::Address, R::Pub(p)) => Ok(BitBoxResponse::Address(p.r#pub)),
            (
                EncryptedContext::IsRegistered,
                R::Btc(pb::BtcResponse {
                    response: Some(pb::btc_response::Response::IsScriptConfigRegistered(x)),
                }),
            ) => Ok(BitBoxResponse::IsRegistered(x.is_registered)),
            (
                EncryptedContext::RegisterScriptConfig,
                R::Btc(pb::BtcResponse {
                    response: Some(pb::btc_response::Response::Success(_)),
                }),
            ) => Ok(BitBoxResponse::Registered),
            (EncryptedContext::RestoreFromMnemonic, R::Success(_)) => Ok(BitBoxResponse::TaskDone),
            (EncryptedContext::Backup, R::Success(_)) => Ok(BitBoxResponse::Backup),
            _ => Err(BitBoxError::UnexpectedResponse),
        }
    }
}

impl<C, T, R, E> Interpreter for BitBoxInterpreter<'_, C, T, R, E>
where
    C: TryInto<BitBoxCommand, Error = BitBoxError>,
    T: From<Transmit>,
    R: From<BitBoxResponse>,
    E: From<BitBoxError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: BitBoxCommand = command.try_into()?;
        match command {
            BitBoxCommand::UnlockAndPair => {
                self.state = State::WaitUnlockAck;
                Ok(plain_transmit(vec![OP_UNLOCK]).into())
            }
            BitBoxCommand::GetVersion => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let bytes = self
                    .start_encrypted_query(api::device_info_request(), EncryptedContext::Version)?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::GetMasterFingerprint => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let bytes = self.start_encrypted_query(
                    api::root_fingerprint_request(),
                    EncryptedContext::MasterFingerprint,
                )?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::GetXpub { keypath, display } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let coin = api::coin_from_network(self.network);
                let xpub_type = api::xpub_type_from_network(self.network);
                let bytes = self.start_encrypted_query(
                    api::xpub_request(coin, &keypath, xpub_type, display),
                    EncryptedContext::Xpub,
                )?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::ShowSimpleAddress {
                keypath,
                simple_type,
                display,
            } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let coin = api::coin_from_network(self.network);
                let script_config = api::make_script_config_simple(simple_type);
                let bytes = self.start_encrypted_query(
                    api::address_request(coin, &keypath, script_config, display),
                    EncryptedContext::Address,
                )?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::ShowPolicyAddress {
                keypath,
                policy,
                display,
            } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let coin = api::coin_from_network(self.network);
                let script_config: pb::BtcScriptConfig = policy.into();
                let bytes = self.start_encrypted_query(
                    api::address_request(coin, &keypath, script_config, display),
                    EncryptedContext::Address,
                )?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::IsScriptConfigRegistered { policy } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let coin = api::coin_from_network(self.network);
                let script_config: pb::BtcScriptConfig = policy.into();
                let bytes = self.start_encrypted_query(
                    api::is_script_config_registered_request(coin, script_config, None),
                    EncryptedContext::IsRegistered,
                )?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::RegisterScriptConfig { policy, name } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let coin = api::coin_from_network(self.network);
                let script_config: pb::BtcScriptConfig = policy.into();
                let bytes = self.start_encrypted_query(
                    api::register_script_config_request(
                        coin,
                        script_config,
                        None,
                        pb::btc_register_script_config_request::XPubType::AutoXpubTpub,
                        Some(&name),
                    ),
                    EncryptedContext::RegisterScriptConfig,
                )?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::SignPsbt {
                psbt,
                force_script_config,
                policy,
            } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                // Fetch our master fingerprint before doing the PSBT lowering.
                let bytes = self.build_encrypted(api::root_fingerprint_request())?;
                self.state = State::SignPsbtWaitFingerprint(SignInit {
                    psbt,
                    force_script_config,
                    policy,
                });
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::SignMessage {
                keypath,
                simple_type,
                message,
            } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let host_nonce = antiklepto::gen_host_nonce()?;
                let coin = api::coin_from_network(self.network);
                let request = pb::request::Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::SignMessage(
                        pb::BtcSignMessageRequest {
                            coin: coin as _,
                            script_config: Some(pb::BtcScriptConfigWithKeypath {
                                script_config: Some(api::make_script_config_simple(simple_type)),
                                keypath: keypath.to_u32_vec(),
                            }),
                            msg: message,
                            host_nonce_commitment: Some(pb::AntiKleptoHostNonceCommitment {
                                commitment: antiklepto::host_commit(&host_nonce).to_vec(),
                            }),
                        },
                    )),
                });
                let bytes = self.build_encrypted(request)?;
                self.state = State::SignMessageWaitCommitment { host_nonce };
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::ShowDescriptorAddress {
                policy,
                change,
                index,
                display,
            } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                // The address keypath depends on which policy key is ours, so fetch our
                // fingerprint first; the address request follows once it resolves.
                let bytes = self.build_encrypted(api::root_fingerprint_request())?;
                self.state = State::ShowAddrWaitFingerprint(ShowAddrInit {
                    policy,
                    change,
                    index,
                    display,
                });
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::RestoreFromMnemonic {
                timestamp,
                timezone_offset,
            } => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let request =
                    pb::request::Request::RestoreFromMnemonic(pb::RestoreFromMnemonicRequest {
                        timestamp,
                        timezone_offset,
                    });
                let bytes =
                    self.start_encrypted_query(request, EncryptedContext::RestoreFromMnemonic)?;
                Ok(encrypted_transmit(bytes).into())
            }
            BitBoxCommand::Backup => {
                if !self.noise.is_paired() {
                    return Err(BitBoxError::Noise("not paired").into());
                }
                let bytes = self.start_encrypted_query(
                    api::show_mnemonic_request(),
                    EncryptedContext::Backup,
                )?;
                Ok(encrypted_transmit(bytes).into())
            }
        }
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        let state = std::mem::replace(&mut self.state, State::New);
        match state {
            State::New | State::Finished(_) => Ok(None),
            State::WaitUnlockAck => {
                // Response may be empty (no data) or contain acknowledgement bytes; either
                // way the next step is to initiate the noise handshake.
                let _ = data;
                self.state = State::WaitHandshakeInit;
                Ok(Some(plain_transmit(vec![OP_I_CAN_HAS_HANDSHAEK]).into()))
            }
            State::WaitHandshakeInit => {
                if data.as_slice() != [RESPONSE_SUCCESS] {
                    return Err(BitBoxError::Noise("handshake init rejected").into());
                }
                let (host, msg1) = self.noise.start_handshake()?;
                self.state = State::WaitHandshake1(host);
                Ok(Some(
                    plain_transmit(framed(OP_HER_COMEZ_TEH_HANDSHAEK, &msg1)).into(),
                ))
            }
            State::WaitHandshake1(mut host) => {
                let bb02_msg_1 = expect_success(&data)?.to_vec();
                let host_msg_2 = NoiseState::handshake_read_write(&mut host, &bb02_msg_1)?;
                self.state = State::WaitHandshake2(host);
                Ok(Some(
                    plain_transmit(framed(OP_HER_COMEZ_TEH_HANDSHAEK, &host_msg_2)).into(),
                ))
            }
            State::WaitHandshake2(mut host) => {
                let bb02_msg_2 = expect_success(&data)?.to_vec();
                let (device_wants_verify, remote_static) =
                    NoiseState::handshake_finalize(&mut host, &bb02_msg_2)?;
                let already_paired = self
                    .noise
                    .data()
                    .contains_device_static_pubkey(&remote_static);
                if !already_paired || device_wants_verify {
                    let hash: [u8; 32] = host
                        .get_hash()
                        .try_into()
                        .map_err(|_| BitBoxError::Noise("bad handshake hash"))?;
                    let pairing_code = NoiseState::pairing_code_from_hash(&hash);
                    // Fire the hook synchronously so the caller (CLI/UI) can display the
                    // code before we block on the device's verification response.
                    self.noise.on_pairing_code(&pairing_code);
                    self.state = State::WaitPairingConfirm(host, Some(pairing_code));
                    Ok(Some(
                        plain_transmit(vec![OP_I_CAN_HAS_PAIRIN_VERIFICASHUN]).into(),
                    ))
                } else {
                    self.noise.finalize(host, None)?;
                    self.state = State::Finished(BitBoxResponse::TaskDone);
                    Ok(None)
                }
            }
            State::WaitPairingConfirm(host, pairing_code) => {
                if data.as_slice() != [RESPONSE_SUCCESS] {
                    return Err(BitBoxError::NoisePairingRejected.into());
                }
                let remote_static = host
                    .get_rs()
                    .ok_or(BitBoxError::Noise("no remote static key"))?
                    .to_vec();
                self.noise.confirm_pairing(&remote_static)?;
                self.noise.finalize(host, pairing_code)?;
                self.state = State::Finished(BitBoxResponse::TaskDone);
                Ok(None)
            }
            State::WaitEncryptedResponse(ctx) => {
                let result = self.handle_encrypted_response(ctx, data)?;
                self.state = State::Finished(result);
                Ok(None)
            }
            State::SignPsbtWaitFingerprint(init) => {
                let body = expect_success(&data)?;
                let decrypted = self.noise.decrypt(body)?;
                let response = api::decode_response(&decrypted)?;
                let fingerprint = match response {
                    pb::response::Response::Fingerprint(f) => f.fingerprint,
                    _ => return Err(BitBoxError::UnexpectedResponse.into()),
                };
                let SignInit {
                    psbt,
                    force_script_config,
                    policy,
                } = init;
                // A registered policy needs the device fingerprint (only known now) to resolve
                // the account keypath, so build the forced script config here rather than at
                // command-conversion time.
                let force_script_config = match (force_script_config, policy) {
                    (Some(config), _) => Some(config),
                    (None, Some(policy)) => Some(policy_script_config(&policy, &fingerprint)?),
                    (None, None) => None,
                };
                let (transaction, our_keys) =
                    Transaction::from_psbt(&fingerprint, &psbt, force_script_config)?;
                let coin = api::coin_from_network(self.network);

                let init_request = build_sign_init_request(coin, &transaction);
                let bytes = self.build_encrypted(init_request)?;
                self.state = State::SignPsbtWaitNext(Box::new(SignCtx {
                    psbt,
                    transaction,
                    our_keys,
                    sigs: Vec::new(),
                    is_inputs_pass2: false,
                    phase: SignPhase::ExpectNext,
                }));
                Ok(Some(encrypted_transmit(bytes).into()))
            }
            State::SignPsbtWaitNext(ctx) => match self.drive_sign(ctx, data)? {
                SignStep::Continue { ctx, bytes } => {
                    self.state = State::SignPsbtWaitNext(ctx);
                    Ok(Some(encrypted_transmit(bytes).into()))
                }
                SignStep::Done { psbt } => {
                    self.state = State::Finished(BitBoxResponse::SignedPsbt(psbt));
                    Ok(None)
                }
            },
            State::SignMessageWaitCommitment { host_nonce } => {
                let body = expect_success(&data)?;
                let decrypted = self.noise.decrypt(body)?;
                let response = api::decode_response(&decrypted)?;
                let signer_commitment = match response {
                    pb::response::Response::Btc(pb::BtcResponse {
                        response: Some(pb::btc_response::Response::AntikleptoSignerCommitment(c)),
                    }) => c.commitment,
                    _ => return Err(BitBoxError::UnexpectedResponse.into()),
                };
                let request = pb::request::Request::Btc(pb::BtcRequest {
                    request: Some(pb::btc_request::Request::AntikleptoSignature(
                        pb::AntiKleptoSignatureRequest {
                            host_nonce: host_nonce.to_vec(),
                        },
                    )),
                });
                let bytes = self.build_encrypted(request)?;
                self.state = State::SignMessageWaitSig {
                    host_nonce,
                    signer_commitment,
                };
                Ok(Some(encrypted_transmit(bytes).into()))
            }
            State::SignMessageWaitSig {
                host_nonce,
                signer_commitment,
            } => {
                let body = expect_success(&data)?;
                let decrypted = self.noise.decrypt(body)?;
                let response = api::decode_response(&decrypted)?;
                let signature = match response {
                    pb::response::Response::Btc(pb::BtcResponse {
                        response: Some(pb::btc_response::Response::SignMessage(m)),
                    }) => m.signature,
                    _ => return Err(BitBoxError::UnexpectedResponse.into()),
                };
                if signature.len() != 65 {
                    return Err(BitBoxError::InvalidSignature.into());
                }
                antiklepto::verify_ecdsa(&host_nonce, &signer_commitment, &signature)?;
                let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&signature[..64])
                    .map_err(|_| BitBoxError::InvalidSignature)?;
                // BIP-137 header for a compressed pubkey: 27 + 4 + recid.
                let header = 27 + 4 + signature[64];
                self.state = State::Finished(BitBoxResponse::Signature(header, sig));
                Ok(None)
            }
            State::ShowAddrWaitFingerprint(init) => {
                let body = expect_success(&data)?;
                let decrypted = self.noise.decrypt(body)?;
                let response = api::decode_response(&decrypted)?;
                let fingerprint = match response {
                    pb::response::Response::Fingerprint(f) => f.fingerprint,
                    _ => return Err(BitBoxError::UnexpectedResponse.into()),
                };
                if fingerprint.len() != 4 {
                    return Err(BitBoxError::InvalidSignature.into());
                }
                let mut fp = [0u8; 4];
                fp.copy_from_slice(&fingerprint);
                let ShowAddrInit {
                    policy,
                    change,
                    index,
                    display,
                } = init;
                let keypath = descriptor_keypath(&policy, Fingerprint::from(&fp), change, index)?;
                let coin = api::coin_from_network(self.network);
                let script_config: pb::BtcScriptConfig = policy.into();
                let bytes = self.build_encrypted(api::address_request(
                    coin,
                    &keypath,
                    script_config,
                    display,
                ))?;
                self.state = State::WaitEncryptedResponse(EncryptedContext::Address);
                Ok(Some(encrypted_transmit(bytes).into()))
            }
        }
    }

    fn end(self) -> Result<Self::Response, Self::Error> {
        match self.state {
            State::Finished(response) => Ok(response.into()),
            _ => Err(BitBoxError::UnexpectedResponse.into()),
        }
    }
}

impl TryFrom<Command> for BitBoxCommand {
    type Error = BitBoxError;
    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Unlock { .. } => Ok(BitBoxCommand::UnlockAndPair),
            Command::GetVersion => Ok(BitBoxCommand::GetVersion),
            Command::GetMasterFingerprint => Ok(BitBoxCommand::GetMasterFingerprint),
            Command::GetXpub { path, display } => Ok(BitBoxCommand::GetXpub {
                keypath: path,
                display,
            }),
            Command::DisplayAddress(DisplayAddress::ByPath { path, display, .. }, _) => {
                Ok(BitBoxCommand::ShowSimpleAddress {
                    keypath: path,
                    simple_type: pb::btc_script_config::SimpleType::P2wpkh,
                    display,
                })
            }
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    index,
                    change,
                    display,
                    ..
                },
                context,
            ) => {
                let policy = match context {
                    Some(DeviceContext::BitBox { policy }) => {
                        policy::Policy::from_wallet_policy(&policy)?
                    }
                    _ => {
                        return Err(BitBoxError::InvalidInput(
                            "BitBox requires DeviceContext::BitBox for descriptor address display",
                        ));
                    }
                };
                Ok(BitBoxCommand::ShowDescriptorAddress {
                    policy,
                    change,
                    index,
                    display,
                })
            }
            Command::RegisterWallet { name, policy } => Ok(BitBoxCommand::RegisterScriptConfig {
                policy: policy::Policy::from_wallet_policy(&policy)?,
                name,
            }),
            Command::SignTx(psbt, context) => {
                // A `DeviceContext::BitBox` carries the registered wallet policy to sign under;
                // without it, only single-sig inputs (inferred from the PSBT) can be signed.
                let policy = match context {
                    None => None,
                    Some(DeviceContext::BitBox { policy }) => {
                        Some(policy::Policy::from_wallet_policy(&policy)?)
                    }
                    Some(_) => {
                        return Err(BitBoxError::InvalidInput(
                            "BitBox requires DeviceContext::BitBox for policy signing",
                        ));
                    }
                };
                Ok(BitBoxCommand::SignPsbt {
                    psbt: Box::new(psbt),
                    force_script_config: None,
                    policy,
                })
            }
            Command::SignMessage { message, path } => Ok(BitBoxCommand::SignMessage {
                simple_type: simple_type_from_path(&path),
                keypath: path,
                message,
            }),
            Command::Backup => Ok(BitBoxCommand::Backup),
        }
    }
}

impl From<BitBoxResponse> for Response {
    fn from(res: BitBoxResponse) -> Response {
        match res {
            BitBoxResponse::TaskDone => Response::TaskDone,
            BitBoxResponse::Info(info) => Response::Info(info),
            BitBoxResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            BitBoxResponse::Xpub(xpub) => Response::Xpub(xpub),
            BitBoxResponse::Address(addr) => Response::Address(addr),
            BitBoxResponse::IsRegistered(_) => Response::TaskDone,
            BitBoxResponse::Registered => {
                Response::WalletRegistration(crate::common::WalletRegistration::Complete {
                    hmac: None,
                })
            }
            BitBoxResponse::SignedPsbt(psbt) => Response::SignedPsbt(*psbt),
            BitBoxResponse::Signature(header, sig) => Response::Signature(header, sig),
            BitBoxResponse::Backup => Response::Backup(DeviceBackup::Complete),
        }
    }
}

impl From<BitBoxError> for Error {
    fn from(e: BitBoxError) -> Error {
        match e {
            BitBoxError::Device(super::error::BitBoxDeviceError::UserAbort) => {
                Error::AuthenticationRefused
            }
            BitBoxError::NoisePairingRejected => Error::AuthenticationRefused,
            BitBoxError::ProtobufDecode(s) | BitBoxError::ProtobufEncode(s) => {
                Error::Serialization(s)
            }
            other => Error::Serialization(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::DerivationPath;
    use miniscript::descriptor::WalletPolicy;
    use std::str::FromStr;

    fn simple(path: &str) -> pb::btc_script_config::SimpleType {
        simple_type_from_path(&DerivationPath::from_str(path).unwrap())
    }

    fn policy_from(descriptor: &str) -> policy::Policy {
        policy::Policy::from_wallet_policy(&WalletPolicy::from_str(descriptor).unwrap()).unwrap()
    }

    #[test]
    fn simple_type_matches_purpose() {
        use pb::btc_script_config::SimpleType;
        assert_eq!(simple("m/84'/0'/0'/0/0"), SimpleType::P2wpkh);
        assert_eq!(simple("m/49'/0'/0'/0/0"), SimpleType::P2wpkhP2sh);
        assert_eq!(simple("m/86'/0'/0'/0/0"), SimpleType::P2tr);
        // Unknown/legacy purposes fall back to native segwit.
        assert_eq!(simple("m/44'/0'/0'/0/0"), SimpleType::P2wpkh);
    }

    #[test]
    fn descriptor_keypath_appends_change_and_index() {
        let policy = policy_from(
            "wsh(or_d(pk([f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*),and_v(v:pkh([00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*),older(100))))",
        );
        let our_fp = Fingerprint::from_str("f5acc2fd").unwrap();
        let keypath = descriptor_keypath(&policy, our_fp, true, 7).unwrap();
        // m/48'/1'/0'/2' + change(1) + index(7)
        assert_eq!(
            keypath,
            DerivationPath::from_str("m/48'/1'/0'/2'/1/7").unwrap()
        );
    }

    #[test]
    fn descriptor_keypath_requires_our_key() {
        let policy = policy_from(
            "wsh(pk([f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*))",
        );
        let unknown = Fingerprint::from_str("deadbeef").unwrap();
        assert!(descriptor_keypath(&policy, unknown, false, 0).is_err());
    }

    // A Liana-style decaying policy: device key spends immediately, recovery key after a
    // relative timelock. Signing must force this registered policy's script config.
    const DECAYING_POLICY: &str = "wsh(or_d(pk([f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*),and_v(v:pkh([00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*),older(100))))";

    #[test]
    fn policy_script_config_uses_account_keypath() {
        let policy = policy_from(DECAYING_POLICY);
        let fingerprint = Fingerprint::from_str("f5acc2fd").unwrap();
        let config = policy_script_config(&policy, &fingerprint.as_bytes()[..]).unwrap();
        assert_eq!(
            config.keypath,
            DerivationPath::from_str("m/48'/1'/0'/2'")
                .unwrap()
                .to_u32_vec()
        );
        assert!(matches!(
            config.script_config,
            Some(pb::BtcScriptConfig {
                config: Some(pb::btc_script_config::Config::Policy(_))
            })
        ));
    }

    #[test]
    fn policy_script_config_requires_our_key() {
        let policy = policy_from(DECAYING_POLICY);
        let unknown = Fingerprint::from_str("deadbeef").unwrap();
        assert!(policy_script_config(&policy, &unknown.as_bytes()[..]).is_err());
    }

    #[test]
    fn common_backup_maps_to_bitbox_backup() {
        let command = BitBoxCommand::try_from(Command::Backup).unwrap();
        assert!(matches!(command, BitBoxCommand::Backup));
    }

    #[test]
    fn bitbox_backup_response_maps_to_completed_backup() {
        let response = Response::from(BitBoxResponse::Backup);
        assert!(matches!(response, Response::Backup(DeviceBackup::Complete)));
    }
}
