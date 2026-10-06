//! Jade CBOR RPC envelopes, parameters, and device-reported information.
//!
// See https://github.com/Blockstream/Jade/blob/master/docs/index.rst
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Display};

use super::JadeError;

/// A Jade RPC request envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request<'a, T: Serialize> {
    /// Caller-selected request identifier.
    pub id: &'a str,
    /// RPC method name.
    pub method: &'a str,
    /// Method parameters, or `None` for parameterless requests.
    pub params: Option<T>,
}

/// An empty parameter type for parameterless requests.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmptyRequest;

/// A Jade RPC response envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response<T> {
    /// Identifier of the corresponding request.
    pub id: String,
    /// Total fragment count, when the result is fragmented.
    pub seqlen: Option<u32>,
    /// One-based fragment number, when the result is fragmented.
    pub seqnum: Option<u32>,
    /// Successful result, if supplied.
    pub result: Option<T>,
    /// Device-reported RPC error, if supplied.
    pub error: Option<Error>,
}

impl<T> Response<T> {
    /// Returns the result, preferring a reported error when both are present.
    pub fn into_result(self) -> Result<T, JadeError> {
        if let Some(e) = self.error {
            return Err(JadeError::Rpc(e));
        }

        self.result.ok_or(JadeError::NoErrorOrResult)
    }
}

/// Known Jade RPC error codes.
#[derive(Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    /// Invalid request envelope.
    InvalidRequest = -32600,
    /// Unrecognized RPC method.
    UnknownMethod = -32601,
    /// Invalid method parameters.
    BadParameters = -32602,
    /// Internal firmware failure.
    InternalError = -32603,
    /// User cancellation.
    UserCancelled = -32000,
    /// Protocol state error.
    ProtocolError = -32001,
    /// Device locked.
    HwLocked = -32002,
    /// Requested network differs from the device network.
    NetworkMismatch = -32003,
}

/// An RPC error reported by Jade.
#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    /// Numeric RPC error code, including codes not listed in [`ErrorCode`].
    pub code: i32,
    /// Human-readable error message, when supplied.
    pub message: Option<String>,
    /// Additional device-provided error bytes, when supplied.
    pub data: Option<Vec<u8>>,
}

/// Parameters for an extended-public-key request.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetXpubParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// BIP-32 child numbers with the hardened bit encoded.
    pub path: Vec<u32>,
}

/// Parameters for user authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthUserParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// Unix time in seconds, or `None` when not supplied.
    pub epoch: Option<u64>,
}

/// Authentication completion or a request for PIN-server interaction.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthUserResponse {
    /// Whether authentication succeeded.
    Authenticated(
        /// Authentication status reported by the device.
        bool,
    ),
    /// Authentication requires an HTTP request relayed by the caller.
    PinServerRequired {
        /// HTTP request instructions from the device.
        http_request: PinServerRequest,
    },
}

/// HTTP instructions issued by Jade during PIN authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct PinServerRequest {
    /// HTTP endpoints and request body.
    pub params: PinServerRequestParams,
    /// Device RPC method that accepts the HTTP response.
    #[serde(alias = "on-reply")]
    pub onreply: String,
}

/// PIN-server HTTP request parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct PinServerRequestParams {
    /// Candidate PIN-server endpoints.
    pub urls: PinServerUrls,
    /// HTTP method.
    pub method: String,
    /// Accepted HTTP response content type.
    pub accept: String,
    /// JSON body containing the encoded PIN protocol data.
    pub data: PinParams,
}

/// Supported endpoint shapes in a Jade PIN-server request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PinServerUrls {
    /// Ordered endpoint URLs.
    Array(
        /// Candidate endpoint URLs in device-provided order.
        Vec<String>,
    ),
    /// Separate clearnet and Tor endpoint URLs.
    Object {
        /// Clearnet URL.
        url: String,
        /// Tor onion URL.
        onion: String,
    },
}

/// Encoded Jade PIN protocol data for an HTTP JSON body.
#[derive(Debug, Serialize, Deserialize)]
pub struct PinParams {
    /// Opaque protocol data string, relayed without decoding.
    pub data: String,
}

/// Firmware, state, and network information reported by Jade.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetInfoResponse {
    /// Firmware version string.
    #[serde(alias = "JADE_VERSION")]
    pub jade_version: String,
    /// Current wallet state.
    #[serde(alias = "JADE_STATE")]
    pub jade_state: JadeState,
    /// Network families allowed by the device.
    #[serde(alias = "JADE_NETWORKS")]
    pub jade_networks: JadeNetworks,
}

/// Wallet states reported by Jade.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JadeState {
    /// No initialized wallet.
    #[serde(alias = "UNINIT")]
    Uninit,
    /// Wallet not yet saved to persistent storage.
    #[serde(alias = "UNSAVED")]
    Unsaved,
    /// Wallet locked.
    #[serde(alias = "LOCKED")]
    Locked,
    /// Wallet ready for use.
    #[serde(alias = "READY")]
    Ready,
    /// Temporary wallet session.
    #[serde(alias = "TEMP")]
    Temp,
}

/// Network families reported by Jade.
///
/// Conversion to Bitcoin networks includes testnet and testnet4 for `Test`;
/// `All` additionally includes signet and regtest.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JadeNetworks {
    /// Bitcoin mainnet only.
    #[serde(alias = "MAIN")]
    Main,
    /// Testnet-family networks.
    #[serde(alias = "TEST")]
    Test,
    /// Mainnet and test networks, including local test networks.
    #[serde(alias = "ALL")]
    All,
}

impl From<JadeNetworks> for Vec<Network> {
    fn from(networks: JadeNetworks) -> Self {
        let main = [Network::Bitcoin];
        let testnets = [Network::Testnet, Network::Testnet4];
        match networks {
            JadeNetworks::Main => main.to_vec(),
            JadeNetworks::Test => testnets.to_vec(),
            JadeNetworks::All => main
                .iter()
                .chain(testnets.iter())
                .chain([Network::Signet, Network::Regtest].iter())
                .copied()
                .collect(),
        }
    }
}

impl Display for JadeNetworks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                JadeNetworks::Main => "main",
                JadeNetworks::Test => "test",
                JadeNetworks::All => "all",
            }
        )
    }
}

/// Size information for a registered descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct DescriptorInfoResponse {
    /// Descriptor length reported by the device.
    pub descriptor_len: u32,
    /// Number of placeholder substitutions.
    pub num_datavalues: u32,
}

/// Parameters for retrieving a registered descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetRegisteredDescriptorParams<'a> {
    /// Registered descriptor name.
    pub descriptor_name: &'a str,
}

/// A registered descriptor template and its key substitutions.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetRegisteredDescriptorResponse {
    /// Registered descriptor name.
    pub descriptor_name: String,
    /// Descriptor template.
    pub descriptor: String,
    /// Placeholder-to-key substitutions.
    pub datavalues: BTreeMap<String, String>,
}

/// Parameters for registering a descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDescriptorParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// User-visible descriptor name.
    pub descriptor_name: &'a str,
    /// Descriptor template.
    pub descriptor: String,
    /// Placeholder-to-key substitutions.
    pub datavalues: BTreeMap<String, String>,
}

/// Parameters for displaying an address from a registered descriptor.
#[derive(Debug, Serialize, Deserialize)]
pub struct DescriptorAddressParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// Derivation branch; the common adapter uses 0 for receive and 1 for change.
    pub branch: u32,
    /// Address index within the branch.
    pub pointer: u32,
    /// Registered descriptor name.
    pub descriptor_name: &'a str,
}

/// Parameters for displaying a single-key address.
#[derive(Debug, Serialize, Deserialize)]
pub struct PathAddressParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// BIP-32 child numbers with the hardened bit encoded.
    pub path: Vec<u32>,
    /// Jade script variant, such as `wpkh(k)`.
    pub variant: &'a str,
}

/// Parameters for displaying a registered multisig address.
#[derive(Debug, Serialize, Deserialize)]
pub struct MultisigAddressParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// Derivation suffix for each signer.
    pub paths: Vec<Vec<u32>>,
    /// Registered multisig wallet name.
    pub multisig_name: &'a str,
}

/// An extended key and origin used by a Jade multisig wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSigner {
    /// Master fingerprint bytes.
    #[serde(with = "serde_bytes")]
    pub fingerprint: Vec<u8>,
    /// Origin path as BIP-32 child numbers.
    pub derivation: Vec<u32>,
    /// Base58-encoded extended public key.
    pub xpub: String,
    /// Derivation suffix relative to the extended key.
    pub path: Vec<u32>,
}

/// A Jade multisig script and its signers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigDescriptor {
    /// Jade multisig script variant.
    pub variant: String,
    /// Whether derived keys are sorted before constructing the script.
    pub sorted: bool,
    /// Number of required signatures.
    pub threshold: u8,
    /// Signer keys and origins.
    pub signers: Vec<MultisigSigner>,
    /// Elements master blinding key, or `None` for Bitcoin wallets.
    pub master_blinding_key: Option<Vec<u8>>,
}

/// Parameters for registering a multisig wallet.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterMultisigParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// User-visible multisig wallet name.
    pub multisig_name: &'a str,
    /// Multisig script and signer description.
    pub descriptor: MultisigDescriptor,
}

/// Parameters for signing a PSBT.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignPsbtParams<'a> {
    /// Jade network identifier.
    pub network: &'a str,
    /// Binary serialized PSBT bytes.
    #[serde(with = "serde_bytes")]
    pub psbt: Vec<u8>,
}

/// Parameters for signing a message.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessageParams<'a> {
    /// Signing path as BIP-32 child numbers.
    pub path: Vec<u32>,
    /// UTF-8 message text.
    pub message: &'a str,
}

/// Parameters for requesting another fragment of a prior result.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetExtendedDataParams<'a> {
    /// Original request identifier.
    pub origid: &'a str,
    /// Original RPC method.
    pub orig: &'a str,
    /// One-based fragment number to retrieve.
    pub seqnum: u32,
    /// Total fragment count.
    pub seqlen: u32,
}

/// A Jade response whose successful result is a CBOR byte string.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseBytes {
    /// Identifier of the corresponding request.
    pub id: String,
    /// Total fragment count, when supplied.
    pub seqlen: Option<u32>,
    /// One-based fragment number, when supplied.
    pub seqnum: Option<u32>,
    /// Result bytes, or `None` when no result was supplied.
    #[serde(with = "serde_bytes")]
    pub result: Option<Vec<u8>>,
    /// Device-reported RPC error, if supplied.
    pub error: Option<Error>,
}
