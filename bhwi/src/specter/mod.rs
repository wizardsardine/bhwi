//! Sans-I/O implementation of the pinned Specter-DIY USB text protocol.

use core::str::FromStr;

use base64ct::{Base64, Encoding};
use bitcoin::Network;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;
use miniscript::descriptor::{DescriptorPublicKey, ShInner, WalletPolicy};
use miniscript::{Descriptor, Translator};

use crate::Interpreter;

/// Maximum accepted final response size. This is deliberately large enough for
/// firmware PSBT replies while preventing an unbounded browser or serial buffer.
pub const MAX_RESPONSE_SIZE: usize = 4 * 1024 * 1024;

const ACK_FRAME: &[u8] = b"ACK\r\n";
const CRLF_LEN: usize = 2;

/// Maximum complete response framing size, including the ACK and final CRLF.
///
/// Transports retain this many raw bytes so the interpreter can validate the
/// same framing after the transport has completed its exchange.
pub const MAX_RESPONSE_FRAME_SIZE: usize = MAX_RESPONSE_SIZE + ACK_FRAME.len() + CRLF_LEN;

#[derive(Debug, thiserror::Error)]
pub enum SpecterError {
    #[error("missing command context: {0}")]
    MissingContext(&'static str),
    #[error("unsupported command: {0}")]
    UnsupportedCommand(&'static str),
    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("malformed Specter framing: {0}")]
    MalformedFraming(&'static str),
    #[error("Specter response is too large")]
    ResponseTooLarge,
    #[error("malformed Specter payload: {0}")]
    MalformedPayload(String),
    #[error("Specter refused the request: {0}")]
    Refused(String),
    #[error("Specter request was cancelled by the user")]
    UserCancelled,
    #[error("Specter network mismatch: {0}")]
    NetworkMismatch(String),
    #[error("Specter request timed out")]
    Timeout,
    #[error("Specter transport disconnected")]
    Disconnected,
    #[error("unexpected interpreter state: {0}")]
    State(&'static str),
}

/// Command expressed in Specter-DIY protocol terms.
pub enum SpecterCommand {
    Fingerprint,
    Xpub {
        path: DerivationPath,
    },
    SignPsbt {
        psbt: Psbt,
    },
    SignMessage {
        path: DerivationPath,
        message: Vec<u8>,
    },
    RegisterWallet {
        name: String,
        policy: WalletPolicy,
    },
    ShowAddress {
        script_type: SpecterAddressType,
        derivation: String,
        script: Option<Vec<u8>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecterAddressType {
    Pkh,
    ShWpkh,
    Wpkh,
    Sh,
    ShWsh,
    Wsh,
}

impl SpecterAddressType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pkh => "pkh",
            Self::ShWpkh => "sh-wpkh",
            Self::Wpkh => "wpkh",
            Self::Sh => "sh",
            Self::ShWsh => "sh-wsh",
            Self::Wsh => "wsh",
        }
    }
}

pub struct SpecterTransmit {
    pub payload: Vec<u8>,
}

pub enum SpecterResponse {
    TaskDone,
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    SignedPsbt(Psbt),
    Signature(u8, Signature),
    Address(String),
}

/// Decode the ACK and final response incrementally. Transports retain this
/// decoder for the complete request so fragmented and coalesced reads work.
#[derive(Default)]
pub struct ResponseDecoder {
    buffer: Vec<u8>,
    saw_ack: bool,
    scan_from: usize,
}

impl ResponseDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, SpecterError> {
        if self.buffer.len().saturating_add(bytes.len()) > MAX_RESPONSE_FRAME_SIZE {
            return Err(SpecterError::ResponseTooLarge);
        }
        self.buffer.extend_from_slice(bytes);

        if !self.saw_ack {
            let Some(end) = find_crlf(&self.buffer) else {
                if !ACK_FRAME.starts_with(&self.buffer) {
                    return Err(SpecterError::MalformedFraming(
                        "expected ACK before final response",
                    ));
                }
                return Ok(None);
            };
            if self.buffer[..end] != *b"ACK" {
                return Err(SpecterError::MalformedFraming(
                    "expected ACK before final response",
                ));
            }
            self.buffer.drain(..end + 2);
            self.saw_ack = true;
            self.scan_from = 0;
        }

        let Some(end) = find_crlf_from(&self.buffer, self.scan_from) else {
            self.scan_from = self.buffer.len().saturating_sub(1);
            // A final CRLF can begin at the last buffered byte, so leave room
            // for that partial delimiter while enforcing the payload limit.
            if self.buffer.len() > MAX_RESPONSE_SIZE + CRLF_LEN - 1 {
                return Err(SpecterError::ResponseTooLarge);
            }
            return Ok(None);
        };
        if end > MAX_RESPONSE_SIZE {
            return Err(SpecterError::ResponseTooLarge);
        }
        let response = self.buffer[..end].to_vec();
        self.buffer.drain(..end + 2);
        if !self.buffer.is_empty() {
            return Err(SpecterError::MalformedFraming("bytes after final response"));
        }
        Ok(Some(response))
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn find_crlf_from(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start.saturating_sub(1)..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| offset + start.saturating_sub(1))
}

enum State {
    New,
    Awaiting {
        command: SpecterCommand,
        decoder: ResponseDecoder,
    },
    Finished(SpecterResponse),
}

pub struct SpecterInterpreter<C, T, R, E> {
    state: State,
    network: Option<Network>,
    _marker: core::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for SpecterInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            state: State::New,
            network: None,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<C, T, R, E> SpecterInterpreter<C, T, R, E> {
    /// Set the user-selected firmware network for response validation.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }
}

impl<C, T, R, E> Interpreter for SpecterInterpreter<C, T, R, E>
where
    C: TryInto<SpecterCommand, Error = SpecterError>,
    T: From<SpecterTransmit>,
    R: From<SpecterResponse>,
    E: From<SpecterError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        if !matches!(self.state, State::New) {
            return Err(SpecterError::State("start called after a request was started").into());
        }
        let command = command.try_into()?;
        let payload = frame_request(&command)?;
        self.state = State::Awaiting {
            command,
            decoder: ResponseDecoder::default(),
        };
        Ok(SpecterTransmit { payload }.into())
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        let State::Awaiting { command, decoder } = &mut self.state else {
            return Err(SpecterError::State("exchange called without a pending request").into());
        };
        let Some(response) = decoder.push(&data)? else {
            return Ok(None);
        };
        let result = parse_response(command, response, self.network)?;
        self.state = State::Finished(result);
        Ok(None)
    }

    fn end(self) -> Result<Self::Response, Self::Error> {
        match self.state {
            State::Finished(response) => Ok(response.into()),
            State::Awaiting { .. } => {
                Err(SpecterError::State("request has no final response").into())
            }
            State::New => Err(SpecterError::State("no request was started").into()),
        }
    }
}

fn frame_request(command: &SpecterCommand) -> Result<Vec<u8>, SpecterError> {
    let body = match command {
        SpecterCommand::Fingerprint => "fingerprint".into(),
        SpecterCommand::Xpub { path } => format!("xpub {path}"),
        SpecterCommand::SignPsbt { psbt } => {
            format!("sign {}", Base64::encode_string(&psbt.serialize()))
        }
        SpecterCommand::SignMessage { path, message } => {
            format!(
                "signmessage m/{path} base64:{}",
                Base64::encode_string(message)
            )
        }
        SpecterCommand::RegisterWallet { name, policy } => {
            validate_wallet_name(name)?;
            let descriptor = policy.clone().into_descriptor().map_err(|error| {
                SpecterError::InvalidInput(format!("invalid wallet policy: {error}"))
            })?;
            format!("addwallet {name}&{descriptor:#}")
        }
        SpecterCommand::ShowAddress {
            script_type,
            derivation,
            script,
        } => {
            validate_derivation(derivation)?;
            match script {
                Some(script) => format!(
                    "showaddr {} {derivation} {}",
                    script_type.as_str(),
                    hex(script)
                ),
                None => format!("showaddr {} {derivation}", script_type.as_str()),
            }
        }
    };
    if body.contains(['\r', '\n']) {
        return Err(SpecterError::InvalidInput(
            "command contains a line delimiter".into(),
        ));
    }
    Ok([b"\r\n\r\n".as_slice(), body.as_bytes(), b"\r\n"].concat())
}

fn parse_response(
    command: &SpecterCommand,
    response: Vec<u8>,
    network: Option<Network>,
) -> Result<SpecterResponse, SpecterError> {
    let response = core::str::from_utf8(&response)
        .map_err(|_| SpecterError::MalformedPayload("response is not UTF-8".into()))?;
    if let Some(reason) = response.strip_prefix("error: ") {
        if reason == "User cancelled" {
            return Err(SpecterError::UserCancelled);
        }
        return Err(SpecterError::Refused(reason.into()));
    }
    match command {
        SpecterCommand::Fingerprint => Fingerprint::from_str(response)
            .map(SpecterResponse::MasterFingerprint)
            .map_err(|error| {
                SpecterError::MalformedPayload(format!("invalid fingerprint: {error}"))
            }),
        SpecterCommand::Xpub { .. } => {
            let xpub = Xpub::from_str(response).map_err(|error| {
                SpecterError::MalformedPayload(format!("invalid xpub: {error}"))
            })?;
            if let Some(network) = network
                && xpub.network.is_mainnet() != (network == Network::Bitcoin)
            {
                return Err(SpecterError::NetworkMismatch(
                    "xpub version does not match the selected network".into(),
                ));
            }
            Ok(SpecterResponse::Xpub(xpub))
        }
        SpecterCommand::SignPsbt { psbt } => {
            let bytes = Base64::decode_vec(response).map_err(|error| {
                SpecterError::MalformedPayload(format!("invalid signed PSBT encoding: {error}"))
            })?;
            let reply = Psbt::deserialize(&bytes).map_err(|error| {
                SpecterError::MalformedPayload(format!("invalid signed PSBT: {error}"))
            })?;
            merge_signed_psbt(psbt, reply).map(SpecterResponse::SignedPsbt)
        }
        SpecterCommand::SignMessage { .. } => {
            let signature = Base64::decode_vec(response).map_err(|error| {
                SpecterError::MalformedPayload(format!("invalid message signature: {error}"))
            })?;
            if signature.len() != 65 || !(31..=34).contains(&signature[0]) {
                return Err(SpecterError::MalformedPayload(
                    "invalid compact message signature".into(),
                ));
            }
            let value = Signature::from_compact(&signature[1..]).map_err(|error| {
                SpecterError::MalformedPayload(format!("invalid compact signature: {error}"))
            })?;
            Ok(SpecterResponse::Signature(signature[0], value))
        }
        SpecterCommand::RegisterWallet { .. } => {
            if response == "success" {
                Ok(SpecterResponse::TaskDone)
            } else {
                Err(SpecterError::MalformedPayload(
                    "unexpected wallet registration response".into(),
                ))
            }
        }
        SpecterCommand::ShowAddress { .. } => {
            if response.is_empty() || response.contains(char::is_whitespace) {
                return Err(SpecterError::MalformedPayload(
                    "invalid displayed address".into(),
                ));
            }
            let address = response
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .map_err(|error| {
                    SpecterError::MalformedPayload(format!("invalid displayed address: {error}"))
                })?;
            if let Some(network) = network {
                address.require_network(network).map_err(|_| {
                    SpecterError::NetworkMismatch(
                        "displayed address does not match the selected network".into(),
                    )
                })?;
            }
            Ok(SpecterResponse::Address(response.into()))
        }
    }
}

/// Merge only signer-owned additions so the original PSBT's metadata survives.
pub fn merge_signed_psbt(original: &Psbt, reply: Psbt) -> Result<Psbt, SpecterError> {
    if original.unsigned_tx != reply.unsigned_tx {
        return Err(SpecterError::MalformedPayload(
            "signed PSBT changes the unsigned transaction".into(),
        ));
    }
    if original.inputs.len() != reply.inputs.len() || original.outputs.len() != reply.outputs.len()
    {
        return Err(SpecterError::MalformedPayload(
            "signed PSBT has inconsistent map counts".into(),
        ));
    }
    let mut merged = original.clone();
    for (input, signed) in merged.inputs.iter_mut().zip(reply.inputs) {
        for (key, signature) in signed.partial_sigs {
            merge_field(&mut input.partial_sigs, key, signature, "partial signature")?;
        }
        for (key, signature) in signed.tap_script_sigs {
            merge_field(
                &mut input.tap_script_sigs,
                key,
                signature,
                "Taproot script signature",
            )?;
        }
        merge_optional_field(
            &mut input.final_script_sig,
            signed.final_script_sig,
            "final script signature",
        )?;
        merge_optional_field(
            &mut input.final_script_witness,
            signed.final_script_witness,
            "final script witness",
        )?;
        merge_optional_field(
            &mut input.tap_key_sig,
            signed.tap_key_sig,
            "Taproot key signature",
        )?;
    }
    Ok(merged)
}

fn merge_field<K: Ord, V: Eq>(
    target: &mut std::collections::BTreeMap<K, V>,
    key: K,
    value: V,
    field: &'static str,
) -> Result<(), SpecterError> {
    match target.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &value => Ok(()),
        std::collections::btree_map::Entry::Occupied(_) => Err(SpecterError::MalformedPayload(
            format!("signed PSBT conflicts with existing {field}"),
        )),
    }
}

fn merge_optional_field<V: Eq>(
    target: &mut Option<V>,
    value: Option<V>,
    field: &'static str,
) -> Result<(), SpecterError> {
    let Some(value) = value else { return Ok(()) };
    match target {
        None => {
            *target = Some(value);
            Ok(())
        }
        Some(existing) if *existing == value => Ok(()),
        Some(_) => Err(SpecterError::MalformedPayload(format!(
            "signed PSBT conflicts with existing {field}"
        ))),
    }
}

fn validate_wallet_name(name: &str) -> Result<(), SpecterError> {
    if name.is_empty() || name.contains(['\r', '\n', '&']) {
        return Err(SpecterError::InvalidInput(
            "wallet name contains a protocol delimiter".into(),
        ));
    }
    Ok(())
}

fn validate_derivation(path: &str) -> Result<(), SpecterError> {
    if path.contains(['\r', '\n', ' '])
        || path
            .split(',')
            .any(|item| item.is_empty() || !valid_specter_path(item))
    {
        return Err(SpecterError::InvalidInput("invalid derivation path".into()));
    }
    Ok(())
}

fn valid_specter_path(path: &str) -> bool {
    DerivationPath::from_str(path).is_ok()
        || (path.len() > 8
            && path.as_bytes()[..8].iter().all(u8::is_ascii_hexdigit)
            && DerivationPath::from_str(&format!("m{}", &path[8..])).is_ok())
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(TABLE[(byte >> 4) as usize] as char);
        result.push(TABLE[(byte & 15) as usize] as char);
    }
    result
}

pub(crate) fn descriptor_address(
    policy: &WalletPolicy,
    change: bool,
    index: u32,
) -> Result<(SpecterAddressType, String, Option<Vec<u8>>), SpecterError> {
    let descriptor = policy.clone().into_descriptor().map_err(|error| {
        SpecterError::InvalidInput(format!("invalid descriptor policy: {error}"))
    })?;
    let mut selector = BranchSelector {
        branch: usize::from(change),
    };
    let descriptor = descriptor
        .translate_pk(&mut selector)
        .map_err(|error| error.expect_translator_err("selecting descriptor branch"))?;
    let index_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(index).map_err(
        |error| {
            SpecterError::UnsupportedDisplayAddress(format!(
                "descriptor index is not a normal derivation: {error}"
            ))
        },
    )?]);
    let paths = descriptor
        .iter_pk()
        .map(|key| {
            let path = key.full_derivation_path().ok_or_else(|| {
                SpecterError::UnsupportedDisplayAddress(
                    "descriptor key has no concrete derivation path".into(),
                )
            })?;
            // Firmware expects the fingerprint and a root-relative path without `m`.
            let path = path.extend(&index_path).to_string();
            Ok(format!(
                "{}/{}",
                key.master_fingerprint(),
                path.trim_start_matches('m').trim_start_matches('/')
            ))
        })
        .collect::<Result<Vec<_>, SpecterError>>()?;
    if paths.is_empty() {
        return Err(SpecterError::UnsupportedDisplayAddress(
            "descriptor has no key derivation".into(),
        ));
    }
    let derivation = paths.join(",");
    let derived = descriptor.derive_at_index(index).map_err(|error| {
        SpecterError::UnsupportedDisplayAddress(format!(
            "descriptor must have one unhardened wildcard: {error}"
        ))
    })?;
    let script_type = match &descriptor {
        Descriptor::Pkh(_) => SpecterAddressType::Pkh,
        Descriptor::Wpkh(_) => SpecterAddressType::Wpkh,
        Descriptor::Sh(sh) if matches!(sh.as_inner(), ShInner::Wpkh(_)) => {
            SpecterAddressType::ShWpkh
        }
        Descriptor::Sh(sh) if matches!(sh.as_inner(), ShInner::Wsh(_)) => SpecterAddressType::ShWsh,
        Descriptor::Sh(_) => SpecterAddressType::Sh,
        Descriptor::Wsh(_) => SpecterAddressType::Wsh,
        Descriptor::Tr(_) => {
            return Err(SpecterError::UnsupportedDisplayAddress(
                "Taproot display is unsupported by Specter-DIY firmware".into(),
            ));
        }
        Descriptor::Bare(_) => {
            return Err(SpecterError::UnsupportedDisplayAddress(
                "bare descriptors have no address".into(),
            ));
        }
    };
    let script = match script_type {
        SpecterAddressType::Pkh | SpecterAddressType::ShWpkh | SpecterAddressType::Wpkh => None,
        SpecterAddressType::Sh | SpecterAddressType::ShWsh | SpecterAddressType::Wsh => Some(
            derived
                .derived_descriptor(&bitcoin::secp256k1::Secp256k1::verification_only())
                .explicit_script()
                .map_err(|error| SpecterError::UnsupportedDisplayAddress(error.to_string()))?
                .into_bytes(),
        ),
    };
    Ok((script_type, derivation, script))
}

struct BranchSelector {
    branch: usize,
}

impl Translator<DescriptorPublicKey> for BranchSelector {
    type TargetPk = DescriptorPublicKey;
    type Error = SpecterError;

    fn pk(&mut self, key: &DescriptorPublicKey) -> Result<Self::TargetPk, Self::Error> {
        if !key.is_multipath() {
            return if self.branch == 0 {
                Ok(key.clone())
            } else {
                Err(SpecterError::UnsupportedDisplayAddress(
                    "descriptor does not provide a change derivation branch".into(),
                ))
            };
        }
        let keys = key.clone().into_single_keys();
        keys.get(self.branch).cloned().ok_or_else(|| {
            SpecterError::UnsupportedDisplayAddress(
                "descriptor branch does not provide both receive and change paths".into(),
            )
        })
    }
    fn sha256(
        &mut self,
        value: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Sha256,
    ) -> Result<<Self::TargetPk as miniscript::MiniscriptKey>::Sha256, Self::Error> {
        Ok(*value)
    }
    fn hash256(
        &mut self,
        value: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Hash256,
    ) -> Result<<Self::TargetPk as miniscript::MiniscriptKey>::Hash256, Self::Error> {
        Ok(*value)
    }
    fn ripemd160(
        &mut self,
        value: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Ripemd160,
    ) -> Result<<Self::TargetPk as miniscript::MiniscriptKey>::Ripemd160, Self::Error> {
        Ok(*value)
    }
    fn hash160(
        &mut self,
        value: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Hash160,
    ) -> Result<<Self::TargetPk as miniscript::MiniscriptKey>::Hash160, Self::Error> {
        Ok(*value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Interpreter;
    use bitcoin::absolute::LockTime;
    use bitcoin::ecdsa;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::raw::Key;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, EcdsaSighashType, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut,
        Witness,
    };

    #[test]
    fn decoder_accepts_fragmented_and_coalesced_framing() {
        let mut decoder = ResponseDecoder::default();
        assert_eq!(decoder.push(b"A").unwrap(), None);
        assert_eq!(decoder.push(b"CK\r\nhello").unwrap(), None);
        assert_eq!(decoder.push(b"\r\n").unwrap(), Some(b"hello".to_vec()));
        let mut decoder = ResponseDecoder::default();
        assert_eq!(
            decoder.push(b"ACK\r\nsuccess\r\n").unwrap(),
            Some(b"success".to_vec())
        );
    }

    #[test]
    fn decoder_rejects_missing_ack_and_trailing_data() {
        assert!(matches!(
            ResponseDecoder::default().push(b"NOPE\r\n"),
            Err(SpecterError::MalformedFraming(_))
        ));
        assert!(matches!(
            ResponseDecoder::default().push(b"ACK\r\nok\r\nextra"),
            Err(SpecterError::MalformedFraming(_))
        ));
    }

    #[test]
    fn decoder_rejects_an_oversized_reply() {
        let mut decoder = ResponseDecoder::default();
        assert_eq!(decoder.push(ACK_FRAME).unwrap(), None);
        assert!(matches!(
            decoder.push(&vec![0; MAX_RESPONSE_SIZE + CRLF_LEN]),
            Err(SpecterError::ResponseTooLarge)
        ));
    }

    #[test]
    fn decoder_accepts_a_maximum_sized_final_response() {
        let mut decoder = ResponseDecoder::default();
        let mut frame = Vec::with_capacity(MAX_RESPONSE_FRAME_SIZE);
        frame.extend_from_slice(ACK_FRAME);
        frame.extend(std::iter::repeat_n(b'x', MAX_RESPONSE_SIZE));
        frame.extend_from_slice(b"\r\n");

        let response = decoder.push(&frame).unwrap().unwrap();

        assert_eq!(response.len(), MAX_RESPONSE_SIZE);
    }

    #[test]
    fn command_frame_matches_pinned_firmware_client() {
        let request = frame_request(&SpecterCommand::Fingerprint).unwrap();
        assert_eq!(request, b"\r\n\r\nfingerprint\r\n");
    }

    #[test]
    fn command_injection_is_rejected() {
        assert!(matches!(
            frame_request(&SpecterCommand::RegisterWallet {
                name: "bad&wallet".into(),
                policy: WalletPolicy::from_str("wpkh(@0/**)").unwrap()
            }),
            Err(SpecterError::InvalidInput(_))
        ));
    }

    #[test]
    fn wallet_registration_preserves_standard_branch_syntax() {
        let policy = WalletPolicy::from_str(
            "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*)",
        )
        .unwrap();
        let request = frame_request(&SpecterCommand::RegisterWallet {
            name: "synthetic".into(),
            policy,
        })
        .unwrap();
        assert!(core::str::from_utf8(&request).unwrap().contains("/<0;1>/*"));
    }

    #[test]
    fn message_signing_uses_a_single_line_base64_payload_and_compact_reply() {
        let command = SpecterCommand::SignMessage {
            path: "m/84'/0'/0'/0/0".parse().unwrap(),
            message: b"synthetic\r\nmessage".to_vec(),
        };
        let request = frame_request(&command).unwrap();
        let request = core::str::from_utf8(&request).unwrap();
        assert!(request.starts_with("\r\n\r\nsignmessage m/84'/0'/0'/0/0 base64:"));
        assert!(request.contains("base64:c3ludGhldGljDQptZXNzYWdl"));
        assert_eq!(request.matches('\n').count(), 3);

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[9; 32]).unwrap();
        let signature = secp
            .sign_ecdsa(&Message::from_digest([8; 32]), &secret)
            .serialize_compact();
        let mut reply = vec![31];
        reply.extend_from_slice(&signature);
        let reply = Base64::encode_string(&reply);
        assert!(matches!(
            parse_response(&command, reply.into_bytes(), None),
            Ok(SpecterResponse::Signature(31, _))
        ));
        let mut unsupported_header = vec![35];
        unsupported_header.extend_from_slice(&signature);
        assert!(matches!(
            parse_response(
                &command,
                Base64::encode_string(&unsupported_header).into_bytes(),
                None,
            ),
            Err(SpecterError::MalformedPayload(_))
        ));
    }

    #[test]
    fn script_display_uses_the_underlying_witness_or_redeem_script() {
        let key = "[f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*";
        let sh = WalletPolicy::from_str(&format!("sh(pk({key}))")).unwrap();
        let sh_wsh = WalletPolicy::from_str(&format!("sh(wsh(pk({key})))")).unwrap();
        let (sh_type, _, sh_script) = descriptor_address(&sh, false, 0).unwrap();
        let (sh_wsh_type, _, sh_wsh_script) = descriptor_address(&sh_wsh, false, 0).unwrap();
        assert_eq!(sh_type, SpecterAddressType::Sh);
        assert_eq!(sh_wsh_type, SpecterAddressType::ShWsh);
        assert_eq!(sh_script, sh_wsh_script);
        assert_eq!(sh_script.unwrap().last(), Some(&0xac));
    }

    #[test]
    fn descriptor_change_requires_an_explicit_change_branch() {
        let policy = WalletPolicy::from_str(
            "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/0/*)",
        )
        .unwrap();
        assert!(matches!(
            descriptor_address(&policy, true, 0),
            Err(SpecterError::UnsupportedDisplayAddress(_))
        ));
    }

    #[test]
    fn interpreter_waits_for_final_response() {
        let mut interpreter = SpecterInterpreter::<
            crate::common::Command,
            crate::common::Transmit,
            crate::common::Response,
            crate::common::Error,
        >::default();
        interpreter
            .start(crate::common::Command::GetMasterFingerprint)
            .unwrap();
        assert!(interpreter.exchange(b"ACK\r\n".to_vec()).unwrap().is_none());
        interpreter.exchange(b"d34db33f\r\n".to_vec()).unwrap();
        assert!(matches!(
            interpreter.end().unwrap(),
            crate::common::Response::MasterFingerprint(_)
        ));
    }

    #[test]
    fn cancellation_is_typed() {
        let command = SpecterCommand::Fingerprint;
        assert!(matches!(
            parse_response(&command, b"error: User cancelled".to_vec(), None),
            Err(SpecterError::UserCancelled)
        ));
    }

    #[test]
    fn refusal_and_malformed_payload_are_typed() {
        assert!(matches!(
            parse_response(
                &SpecterCommand::Fingerprint,
                b"error: wallet missing".to_vec(),
                None
            ),
            Err(SpecterError::Refused(_))
        ));
        assert!(matches!(
            parse_response(
                &SpecterCommand::Fingerprint,
                b"not-a-fingerprint".to_vec(),
                None
            ),
            Err(SpecterError::MalformedPayload(_))
        ));
    }

    #[test]
    fn selected_network_validates_xpub_and_displayed_address() {
        let xpub = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";
        assert!(matches!(
            parse_response(
                &SpecterCommand::Xpub {
                    path: DerivationPath::master()
                },
                xpub.as_bytes().to_vec(),
                Some(Network::Bitcoin),
            ),
            Err(SpecterError::NetworkMismatch(_))
        ));
        assert!(matches!(
            parse_response(
                &SpecterCommand::ShowAddress {
                    script_type: SpecterAddressType::Pkh,
                    derivation: "m/0".into(),
                    script: None
                },
                b"1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_vec(),
                Some(Network::Testnet),
            ),
            Err(SpecterError::NetworkMismatch(_))
        ));
        assert!(matches!(
            parse_response(
                &SpecterCommand::ShowAddress {
                    script_type: SpecterAddressType::Pkh,
                    derivation: "m/0".into(),
                    script: None,
                },
                b"not-an-address".to_vec(),
                None,
            ),
            Err(SpecterError::MalformedPayload(_))
        ));
    }

    #[test]
    fn signing_merge_preserves_metadata_and_final_taproot_witness() {
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                sequence: Sequence::MAX,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut original = Psbt::from_unsigned_tx(transaction).unwrap();
        original.unknown.insert(
            Key {
                type_value: 0x50,
                key: vec![0],
            },
            vec![1],
        );
        original.inputs[0].unknown.insert(
            Key {
                type_value: 0x51,
                key: vec![1],
            },
            vec![2],
        );
        original.outputs[0].unknown.insert(
            Key {
                type_value: 0x52,
                key: vec![2],
            },
            vec![3],
        );

        let mut reply = original.clone();
        // The device reply intentionally contains only signer-owned fields.
        reply.unknown.clear();
        reply.inputs[0].unknown.clear();
        reply.outputs[0].unknown.clear();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let message = Message::from_digest([2; 32]);
        let public_key = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &secret,
        ));
        reply.inputs[0].partial_sigs.insert(
            public_key,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&message, &secret),
                sighash_type: EcdsaSighashType::All,
            },
        );
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        let tap_signature = bitcoin::taproot::Signature {
            signature: secp.sign_schnorr_no_aux_rand(&message, &keypair),
            sighash_type: bitcoin::TapSighashType::Default,
        };
        reply.inputs[0].tap_script_sigs.insert(
            (xonly, TapLeafHash::from_byte_array([3; 32])),
            tap_signature,
        );
        reply.inputs[0].tap_key_sig = Some(tap_signature);
        reply.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
        reply.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![4; 64]]));

        let mut identical = original.clone();
        identical.inputs[0].partial_sigs = reply.inputs[0].partial_sigs.clone();
        identical.inputs[0].tap_script_sigs = reply.inputs[0].tap_script_sigs.clone();
        identical.inputs[0].tap_key_sig = reply.inputs[0].tap_key_sig;
        identical.inputs[0].final_script_sig = reply.inputs[0].final_script_sig.clone();
        identical.inputs[0].final_script_witness = reply.inputs[0].final_script_witness.clone();
        assert!(merge_signed_psbt(&identical, reply.clone()).is_ok());

        let mut ecdsa_conflict = original.clone();
        ecdsa_conflict.inputs[0].partial_sigs.insert(
            public_key,
            ecdsa::Signature {
                signature: secp.sign_ecdsa(&Message::from_digest([3; 32]), &secret),
                sighash_type: EcdsaSighashType::All,
            },
        );
        assert!(matches!(
            merge_signed_psbt(&ecdsa_conflict, reply.clone()),
            Err(SpecterError::MalformedPayload(_))
        ));

        let mut tap_script_conflict = original.clone();
        tap_script_conflict.inputs[0].tap_script_sigs.insert(
            (xonly, TapLeafHash::from_byte_array([3; 32])),
            bitcoin::taproot::Signature {
                signature: secp.sign_schnorr_no_aux_rand(&Message::from_digest([3; 32]), &keypair),
                sighash_type: bitcoin::TapSighashType::Default,
            },
        );
        assert!(matches!(
            merge_signed_psbt(&tap_script_conflict, reply.clone()),
            Err(SpecterError::MalformedPayload(_))
        ));

        let mut tap_key_conflict = original.clone();
        tap_key_conflict.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: secp.sign_schnorr_no_aux_rand(&Message::from_digest([3; 32]), &keypair),
            sighash_type: bitcoin::TapSighashType::Default,
        });
        assert!(matches!(
            merge_signed_psbt(&tap_key_conflict, reply.clone()),
            Err(SpecterError::MalformedPayload(_))
        ));
        let mut final_script_sig_conflict = original.clone();
        final_script_sig_conflict.inputs[0].final_script_sig =
            Some(ScriptBuf::from_bytes(vec![0x52]));
        assert!(matches!(
            merge_signed_psbt(&final_script_sig_conflict, reply.clone()),
            Err(SpecterError::MalformedPayload(_))
        ));
        let mut final_witness_conflict = original.clone();
        final_witness_conflict.inputs[0].final_script_witness =
            Some(Witness::from_slice(&[vec![5; 64]]));
        assert!(matches!(
            merge_signed_psbt(&final_witness_conflict, reply.clone()),
            Err(SpecterError::MalformedPayload(_))
        ));

        let merged = merge_signed_psbt(&original, reply).unwrap();
        assert_eq!(merged.unknown.len(), 1);
        assert_eq!(merged.inputs[0].unknown.len(), 1);
        assert_eq!(merged.outputs[0].unknown.len(), 1);
        assert_eq!(merged.inputs[0].partial_sigs.len(), 1);
        assert_eq!(merged.inputs[0].tap_script_sigs.len(), 1);
        assert_eq!(
            merged.inputs[0].final_script_witness,
            Some(Witness::from_slice(&[vec![4; 64]]))
        );
    }

    #[test]
    fn signing_merge_rejects_another_transaction() {
        let original = Psbt::from_unsigned_tx(Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
        .unwrap();
        let reply = Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
        .unwrap();
        assert!(matches!(
            merge_signed_psbt(&original, reply),
            Err(SpecterError::MalformedPayload(_))
        ));
    }
}
