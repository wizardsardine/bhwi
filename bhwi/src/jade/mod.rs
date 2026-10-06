//! Jade CBOR commands and PIN-server authentication routing.

pub mod api;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64ct::{Base64, Encoding};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Interpreter;
use crate::device::DeviceId;
use crate::jade::api::GetInfoResponse;

/// Jade network identifier for Bitcoin mainnet.
pub const JADE_NETWORK_MAINNET: &str = "mainnet";
/// Jade network identifier for test networks.
pub const JADE_NETWORK_TESTNET: &str = "testnet";
/// Jade network identifier for regtest.
pub const JADE_NETWORK_LOCALTEST: &str = "localtest";

/// USB identifiers used by supported Jade serial interfaces.
pub const JADE_DEVICE_IDS: [DeviceId; 6] = [
    DeviceId::new(0x10c4).with_pid(0xea60),
    DeviceId::new(0x1a86).with_pid(0x55d4),
    DeviceId::new(0x0403).with_pid(0x6001),
    DeviceId::new(0x1a86).with_pid(0x7523),
    DeviceId::new(0x303a).with_pid(0x4001),
    DeviceId::new(0x303a).with_pid(0x1001),
];

/// Errors in Jade request encoding, authentication, and response handling.
#[derive(Debug)]
pub enum JadeError {
    /// A response containing neither an error nor a result.
    NoErrorOrResult,
    /// An RPC error reported by the device.
    Rpc(
        /// Device-reported RPC failure.
        api::Error,
    ),
    /// Invalid CBOR data.
    Cbor,
    /// Encoding or Bitcoin data conversion failure.
    Serialization(
        /// Conversion failure description.
        String,
    ),
    /// A result incompatible with the current protocol step.
    UnexpectedResult(
        /// Unexpected-result description.
        String,
    ),
    /// Device authentication refused.
    HandshakeRefused,
    /// An unsupported address-display format.
    UnsupportedDisplayAddress,
}

/// A Jade command using the interpreter's selected network.
pub enum JadeCommand {
    /// Authenticates the user, routing PIN-server requests to the caller.
    Auth,
    /// Requests the active wallet's master fingerprint.
    GetMasterFingerprint,
    /// Requests firmware, device state, and network information.
    GetInfo,
    /// Requests an extended public key at the given path.
    GetXpub(
        /// Key derivation path.
        DerivationPath,
    ),
    /// Displays a receive or change address.
    GetReceiveAddress(
        /// Address derivation settings.
        ReceiveAddress,
    ),
    /// Registers a descriptor template and its substituted keys.
    RegisterDescriptor {
        /// User-visible descriptor name.
        descriptor_name: String,
        /// Descriptor template with Jade derivation suffixes.
        descriptor: String,
        /// Placeholder-to-key substitutions.
        datavalues: BTreeMap<String, String>,
    },
    /// Registers a multisig wallet, then displays its requested address.
    RegisterMultisig {
        /// User-visible multisig wallet name.
        multisig_name: String,
        /// Multisig script and signer description.
        descriptor: api::MultisigDescriptor,
        /// Concrete derivation suffixes used for the subsequent address display.
        paths: Vec<Vec<u32>>,
    },
    /// Signs a UTF-8 message; non-UTF-8 bytes return a serialization error.
    SignMessage {
        /// UTF-8 message bytes.
        message: Vec<u8>,
        /// Signing key derivation path.
        path: DerivationPath,
    },
    /// Signs a PSBT and collects fragmented results when necessary.
    SignPsbt {
        /// PSBT to sign.
        psbt: Psbt,
    },
}

/// A Jade address-display request.
pub enum ReceiveAddress {
    /// An address from a registered descriptor.
    Descriptor {
        /// Address index within the branch.
        index: u32,
        /// Whether to use the change branch.
        change: bool,
        /// Registered descriptor name.
        descriptor_name: String,
    },
    /// A single-key address at a concrete derivation path.
    Path {
        /// Address derivation path.
        path: DerivationPath,
        /// Jade script variant, such as `wpkh(k)`.
        variant: &'static str,
    },
    /// An address from a registered multisig wallet.
    Multisig {
        /// Derivation suffix for each signer.
        paths: Vec<Vec<u32>>,
        /// Registered multisig wallet name.
        multisig_name: String,
    },
}

/// A completed Jade command result.
pub enum JadeResponse {
    /// Firmware, device state, and network information.
    GetInfo(
        /// Device-reported information.
        GetInfoResponse,
    ),
    /// Master fingerprint of the active wallet.
    MasterFingerprint(
        /// Active wallet master fingerprint.
        Fingerprint,
    ),
    /// Message-signature header byte and ECDSA signature.
    Signature(
        /// Device-returned compact signature header.
        u8,
        /// Message signature.
        Signature,
    ),
    /// A terminal outcome without a returned value.
    ///
    /// The interpreter discards the boolean in [`api::AuthUserResponse::Authenticated`],
    /// including `false`, so this does not confirm successful authentication.
    TaskDone,
    /// Extended public key of the requested path.
    Xpub(
        /// Requested extended public key.
        Xpub,
    ),
    /// Encoded Bitcoin address.
    Address(
        /// Encoded address text.
        String,
    ),
    /// Successful descriptor registration, without an authentication token.
    RegisteredDescriptor,
    /// PSBT containing returned signatures.
    SignedPsbt(
        /// Updated PSBT.
        Psbt,
    ),
}

/// Destination of the next Jade protocol transmission.
pub enum JadeRecipient {
    /// The connected Jade device.
    Device,
    /// A PIN-server HTTP endpoint selected from the device request.
    PinServer {
        /// Endpoint URL.
        url: String,
    },
}

/// An encoded Jade transmission routed to a device or PIN server.
pub struct JadeTransmit {
    /// Destination of the payload.
    pub recipient: JadeRecipient,
    /// CBOR device request or JSON PIN-server request body bytes.
    pub payload: Vec<u8>,
}

enum State {
    New,
    Running(JadeCommand),
    WaitingPinServer,
    WaitingFinalHandshake,
    GettingExtendedData {
        origid: String,
        orig: String,
        next_seqnum: u32,
        seqlen: u32,
        chunks: Vec<u8>,
    },
}

/// A sans-I/O Jade interpreter, defaulting to Bitcoin mainnet.
///
/// # Panics
///
/// Exchanging a message-signing response panics if its decoded signature bytes
/// are empty.
pub struct JadeInterpreter<C, T, R, E> {
    network: &'static str,
    state: State,
    response: Option<JadeResponse>,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for JadeInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            network: JADE_NETWORK_MAINNET,
            state: State::New,
            response: None,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C, T, R, E> JadeInterpreter<C, T, R, E> {
    /// Selects the network for subsequent commands.
    ///
    /// Bitcoin maps to `mainnet`, regtest to `localtest`, and all other networks
    /// to `testnet`.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = match network {
            Network::Bitcoin => JADE_NETWORK_MAINNET,
            Network::Regtest => JADE_NETWORK_LOCALTEST,
            _ => JADE_NETWORK_TESTNET,
        };
        self
    }
}

// Initialize a static atomic counter
static REQUEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

fn generate_request_id() -> usize {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn request<S, T, E>(method: &str, params: Option<S>) -> Result<T, E>
where
    S: Serialize + Unpin,
    T: From<JadeTransmit>,
    E: From<JadeError>,
{
    let id = generate_request_id();
    let payload = serde_cbor::to_vec(&api::Request {
        id: &id.to_string(),
        method,
        params,
    })
    .map_err(|_| JadeError::Serialization("failed to serialize".to_string()))?;

    Ok(JadeTransmit {
        payload,
        recipient: JadeRecipient::Device,
    }
    .into())
}

fn from_response<D: DeserializeOwned>(buffer: &[u8]) -> Result<api::Response<D>, JadeError> {
    serde_cbor::from_slice(buffer).map_err(|_| JadeError::Cbor)
}

fn from_response_bytes(buffer: &[u8]) -> Result<api::ResponseBytes, JadeError> {
    serde_cbor::from_slice(buffer).map_err(|_| JadeError::Cbor)
}

fn parse_signed_psbt(bytes: &[u8]) -> Result<JadeResponse, JadeError> {
    Psbt::deserialize(bytes)
        .map(JadeResponse::SignedPsbt)
        .map_err(|e| JadeError::Serialization(e.to_string()))
}

impl<C, T, R, E> Interpreter for JadeInterpreter<C, T, R, E>
where
    C: TryInto<JadeCommand, Error = E>,
    T: From<JadeTransmit>,
    R: From<JadeResponse>,
    E: From<JadeError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: JadeCommand = command.try_into()?;
        let req = match &command {
            JadeCommand::Auth => request(
                "auth_user",
                Some(api::AuthUserParams {
                    network: self.network,
                    epoch: None,
                }),
            ),
            JadeCommand::GetMasterFingerprint => request(
                "get_xpub",
                Some(api::GetXpubParams {
                    network: self.network,
                    path: DerivationPath::master().to_u32_vec(),
                }),
            ),
            JadeCommand::GetXpub(path) => request(
                "get_xpub",
                Some(api::GetXpubParams {
                    network: self.network,
                    path: path.to_u32_vec(),
                }),
            ),
            JadeCommand::SignMessage { message, path } => request(
                "sign_message",
                Some(api::SignMessageParams {
                    path: path.to_u32_vec(),
                    message: &String::from_utf8(message.to_vec())
                        .map_err(|e| JadeError::Serialization(e.to_string()))?,
                }),
            ),
            JadeCommand::SignPsbt { psbt } => request(
                "sign_psbt",
                Some(api::SignPsbtParams {
                    network: self.network,
                    psbt: psbt.serialize(),
                }),
            ),
            JadeCommand::GetReceiveAddress(address) => match address {
                ReceiveAddress::Descriptor {
                    index,
                    change,
                    descriptor_name,
                } => request(
                    "get_receive_address",
                    Some(api::DescriptorAddressParams {
                        network: self.network,
                        branch: u32::from(*change),
                        pointer: *index,
                        descriptor_name,
                    }),
                ),
                ReceiveAddress::Path { path, variant } => request(
                    "get_receive_address",
                    Some(api::PathAddressParams {
                        network: self.network,
                        path: path.to_u32_vec(),
                        variant,
                    }),
                ),
                ReceiveAddress::Multisig {
                    paths,
                    multisig_name,
                } => request(
                    "get_receive_address",
                    Some(api::MultisigAddressParams {
                        network: self.network,
                        paths: paths.clone(),
                        multisig_name,
                    }),
                ),
            },
            JadeCommand::RegisterDescriptor {
                descriptor_name,
                descriptor,
                datavalues,
            } => request(
                "register_descriptor",
                Some(api::RegisterDescriptorParams {
                    network: self.network,
                    descriptor_name,
                    descriptor: descriptor.clone(),
                    datavalues: datavalues.clone(),
                }),
            ),
            JadeCommand::RegisterMultisig {
                multisig_name,
                descriptor,
                ..
            } => request(
                "register_multisig",
                Some(api::RegisterMultisigParams {
                    network: self.network,
                    multisig_name,
                    descriptor: descriptor.clone(),
                }),
            ),
            JadeCommand::GetInfo => request("get_version_info", None::<api::EmptyRequest>),
        };

        self.state = State::Running(command);
        req
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        if let State::GettingExtendedData {
            origid,
            orig,
            next_seqnum,
            seqlen,
            chunks,
        } = &mut self.state
        {
            let res = from_response_bytes(&data)?;
            if let Some(e) = res.error {
                return Err(JadeError::Rpc(e).into());
            }
            let chunk = res.result.ok_or(JadeError::NoErrorOrResult)?;
            let seqnum = res.seqnum.unwrap_or(*next_seqnum);
            if seqnum != *next_seqnum {
                return Err(JadeError::UnexpectedResult(format!(
                    "unexpected sign_psbt fragment {seqnum}, wanted {next_seqnum}"
                ))
                .into());
            }
            chunks.extend_from_slice(&chunk);
            if seqnum >= *seqlen {
                self.response = Some(parse_signed_psbt(chunks)?);
                return Ok(None);
            }

            *next_seqnum = seqnum + 1;
            return Ok(Some(request(
                "get_extended_data",
                Some(api::GetExtendedDataParams {
                    origid,
                    orig,
                    seqnum: *next_seqnum,
                    seqlen: *seqlen,
                }),
            )?));
        }

        let mut next_state = None;
        let mut response = None;

        let transmit = match &self.state {
            State::New => None,
            State::Running(JadeCommand::Auth) => {
                let res: api::AuthUserResponse = from_response(&data)?.into_result()?;
                match res {
                    api::AuthUserResponse::PinServerRequired { http_request } => {
                        next_state = Some(State::WaitingPinServer);
                        let url = match &http_request.params.urls {
                            api::PinServerUrls::Array(urls) => urls.first().ok_or(
                                JadeError::UnexpectedResult("No url provided".to_string()),
                            )?,
                            api::PinServerUrls::Object { url, .. } => url,
                        };
                        Some(
                            JadeTransmit {
                                recipient: JadeRecipient::PinServer {
                                    url: url.to_string(),
                                },
                                payload: serde_json::to_vec(&http_request.params.data)
                                    .map_err(|e| JadeError::Serialization(e.to_string()))?,
                            }
                            .into(),
                        )
                    }
                    api::AuthUserResponse::Authenticated(_) => {
                        response = Some(JadeResponse::TaskDone);
                        None
                    }
                }
            }
            State::WaitingPinServer => {
                let pin_params: api::PinParams = serde_json::from_slice(&data).map_err(|_| {
                    JadeError::Serialization("Wrong response from pin server".to_string())
                })?;
                next_state = Some(State::WaitingFinalHandshake);
                Some(request("pin", Some(pin_params))?)
            }
            State::WaitingFinalHandshake => {
                let handshake_completed: bool = from_response(&data)?.into_result()?;
                if !handshake_completed {
                    return Err(JadeError::HandshakeRefused.into());
                }
                response = Some(JadeResponse::TaskDone);
                None
            }
            State::Running(JadeCommand::GetMasterFingerprint) => {
                let s: String = from_response(&data)?.into_result()?;
                let xpub =
                    Xpub::from_str(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                response = Some(JadeResponse::MasterFingerprint(xpub.fingerprint()));
                None
            }
            State::Running(JadeCommand::GetXpub(..)) => {
                let s: String = from_response(&data)?.into_result()?;
                let xpub =
                    Xpub::from_str(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                response = Some(JadeResponse::Xpub(xpub));
                None
            }
            State::Running(JadeCommand::SignMessage { .. }) => {
                let s: String = from_response(&data)?.into_result()?;
                let sig_bytes =
                    Base64::decode_vec(&s).map_err(|e| JadeError::Serialization(e.to_string()))?;
                let sig = Signature::from_compact(&sig_bytes[1..])
                    .map_err(|e| JadeError::Serialization(e.to_string()))?;
                response = Some(JadeResponse::Signature(sig_bytes[0], sig));
                None
            }
            State::Running(JadeCommand::SignPsbt { .. }) => {
                let res = from_response_bytes(&data)?;
                if let Some(e) = res.error {
                    return Err(JadeError::Rpc(e).into());
                }
                let chunk = res.result.ok_or(JadeError::NoErrorOrResult)?;
                let seqnum = res.seqnum.unwrap_or(1);
                let seqlen = res.seqlen.unwrap_or(1);
                if seqnum != 1 {
                    return Err(JadeError::UnexpectedResult(format!(
                        "unexpected first sign_psbt fragment {seqnum}"
                    ))
                    .into());
                }
                if seqlen <= 1 {
                    response = Some(parse_signed_psbt(&chunk)?);
                    None
                } else {
                    let next_seqnum = seqnum + 1;
                    next_state = Some(State::GettingExtendedData {
                        origid: res.id.clone(),
                        orig: "sign_psbt".to_string(),
                        next_seqnum,
                        seqlen,
                        chunks: chunk,
                    });
                    Some(request(
                        "get_extended_data",
                        Some(api::GetExtendedDataParams {
                            origid: &res.id,
                            orig: "sign_psbt",
                            seqnum: next_seqnum,
                            seqlen,
                        }),
                    )?)
                }
            }
            State::GettingExtendedData { .. } => unreachable!("handled before immutable match"),
            State::Running(JadeCommand::GetReceiveAddress(_)) => {
                let address: String = from_response(&data)?.into_result()?;
                response = Some(JadeResponse::Address(address));
                None
            }
            State::Running(JadeCommand::RegisterDescriptor { .. }) => {
                let registered: bool = from_response(&data)?.into_result()?;
                if !registered {
                    return Err(JadeError::UnexpectedResult(
                        "register_descriptor returned false".to_string(),
                    )
                    .into());
                }
                response = Some(JadeResponse::RegisteredDescriptor);
                None
            }
            State::Running(JadeCommand::RegisterMultisig {
                multisig_name,
                paths,
                ..
            }) => {
                let registered: bool = from_response(&data)?.into_result()?;
                if !registered {
                    return Err(JadeError::UnexpectedResult(
                        "register_multisig returned false".to_string(),
                    )
                    .into());
                }
                next_state = Some(State::Running(JadeCommand::GetReceiveAddress(
                    ReceiveAddress::Multisig {
                        paths: paths.clone(),
                        multisig_name: multisig_name.clone(),
                    },
                )));
                Some(request(
                    "get_receive_address",
                    Some(api::MultisigAddressParams {
                        network: self.network,
                        paths: paths.clone(),
                        multisig_name,
                    }),
                )?)
            }
            State::Running(JadeCommand::GetInfo) => {
                let info: GetInfoResponse = from_response(&data)?.into_result()?;
                response = Some(JadeResponse::GetInfo(info));
                None
            }
        };

        if let Some(state) = next_state {
            self.state = state;
        }
        if response.is_some() {
            self.response = response;
        }
        Ok(transmit)
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        self.response
            .map(Self::Response::from)
            .ok_or_else(|| JadeError::NoErrorOrResult.into())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::address::AddressType;

    use super::*;
    use crate::Interpreter;
    use crate::common::{Command, DisplayAddress, JadeInterpreter, Response, WalletRegistration};
    use crate::miniscript::descriptor::WalletPolicy;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct OwnedRequest {
        method: String,
        params: Option<OwnedPathAddressParams>,
    }

    #[derive(Debug, Deserialize)]
    struct OwnedPathAddressParams {
        network: String,
        path: Vec<u32>,
        variant: String,
    }

    #[derive(Debug, Deserialize)]
    struct OwnedRegistrationRequest {
        method: String,
        params: Option<OwnedRegistrationParams>,
    }

    #[derive(Debug, Deserialize)]
    struct OwnedRegistrationParams {
        network: String,
        descriptor_name: String,
        descriptor: String,
        datavalues: BTreeMap<String, String>,
    }

    const REGISTRATION_POLICY: &str = "wsh(or_d(pk([f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*),and_v(v:pkh([00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*),older(100))))";

    #[test]
    fn path_display_request_encodes_jade_path_params() {
        let mut interpreter = JadeInterpreter::default().with_network(Network::Testnet);
        let transmit = interpreter
            .start(Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path: "m/49'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: Some(AddressType::P2sh),
                },
                None,
            ))
            .unwrap();

        let request: OwnedRequest = serde_cbor::from_slice(&transmit.payload).unwrap();
        let params = request.params.unwrap();
        assert_eq!(request.method, "get_receive_address");
        assert_eq!(params.network, JADE_NETWORK_TESTNET);
        assert_eq!(params.variant, "sh(wpkh(k))");
        assert_eq!(
            params.path,
            vec![0x8000_0031, 0x8000_0001, 0x8000_0000, 0, 0]
        );
    }

    #[test]
    fn register_wallet_encodes_jade_descriptor_params() {
        let mut interpreter = JadeInterpreter::default().with_network(Network::Testnet);
        let transmit = interpreter
            .start(Command::RegisterWallet {
                name: "inheritance".to_string(),
                policy: WalletPolicy::from_str(REGISTRATION_POLICY).unwrap(),
            })
            .unwrap();

        let request: OwnedRegistrationRequest = serde_cbor::from_slice(&transmit.payload).unwrap();
        let params = request.params.unwrap();
        assert_eq!(request.method, "register_descriptor");
        assert_eq!(params.network, JADE_NETWORK_TESTNET);
        assert_eq!(params.descriptor_name, "inheritance");
        assert_eq!(
            params.descriptor,
            "wsh(or_d(pk(@0/<0;1>/*),and_v(v:pkh(@1/<0;1>/*),older(100))))"
        );
        assert_eq!(params.datavalues.len(), 2);
        assert_eq!(
            params.datavalues.get("@0").unwrap(),
            "[f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP"
        );
        assert_eq!(
            params.datavalues.get("@1").unwrap(),
            "[00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S"
        );
    }

    #[test]
    fn register_wallet_maps_true_to_completed_registration() {
        let mut interpreter = JadeInterpreter::default();
        interpreter
            .start(Command::RegisterWallet {
                name: "inheritance".to_string(),
                policy: WalletPolicy::from_str(REGISTRATION_POLICY).unwrap(),
            })
            .unwrap();
        let response = serde_cbor::to_vec(&api::Response {
            id: "1".to_string(),
            seqlen: None,
            seqnum: None,
            result: Some(true),
            error: None,
        })
        .unwrap();

        assert!(interpreter.exchange(response).unwrap().is_none());
        assert!(matches!(
            interpreter.end().unwrap(),
            Response::WalletRegistration(WalletRegistration::Complete { hmac: None })
        ));
    }

    #[test]
    fn register_wallet_rejects_false_result() {
        let mut interpreter = JadeInterpreter::default();
        interpreter
            .start(Command::RegisterWallet {
                name: "inheritance".to_string(),
                policy: WalletPolicy::from_str(REGISTRATION_POLICY).unwrap(),
            })
            .unwrap();
        let response = serde_cbor::to_vec(&api::Response {
            id: "1".to_string(),
            seqlen: None,
            seqnum: None,
            result: Some(false),
            error: None,
        })
        .unwrap();

        let error = match interpreter.exchange(response) {
            Err(error) => error,
            Ok(_) => panic!("false registration result must fail"),
        };
        assert!(
            error
                .to_string()
                .contains("register_descriptor returned false")
        );
    }
}
