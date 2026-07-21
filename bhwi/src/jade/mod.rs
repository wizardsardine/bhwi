pub mod api;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64ct::{Base64, Encoding};
use bitcoin::Network;
use bitcoin::address::AddressType;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Interpreter;
use crate::common::{
    Command, DisplayAddress, Error, Info, MultisigAddressType, MultisigDisplayAddress, Recipient,
    Response, Transmit,
};
use crate::device::DeviceId;
use crate::jade::api::GetInfoResponse;
use crate::miniscript::descriptor::{DescriptorPublicKey, Wildcard};

pub const JADE_NETWORK_MAINNET: &str = "mainnet";
pub const JADE_NETWORK_TESTNET: &str = "testnet";
pub const JADE_NETWORK_LOCALTEST: &str = "localtest";

pub const JADE_DEVICE_IDS: [DeviceId; 6] = [
    DeviceId::new(0x10c4).with_pid(0xea60),
    DeviceId::new(0x1a86).with_pid(0x55d4),
    DeviceId::new(0x0403).with_pid(0x6001),
    DeviceId::new(0x1a86).with_pid(0x7523),
    DeviceId::new(0x303a).with_pid(0x4001),
    DeviceId::new(0x303a).with_pid(0x1001),
];

#[derive(Debug)]
pub enum JadeError {
    NoErrorOrResult,
    Rpc(api::Error),
    Cbor,
    Serialization(String),
    UnexpectedResult(String),
    HandshakeRefused,
    UnsupportedDisplayAddress,
}

pub enum JadeCommand {
    Auth,
    GetMasterFingerprint,
    GetInfo,
    GetXpub(DerivationPath),
    GetReceiveAddress(ReceiveAddress),
    RegisterDescriptor {
        descriptor_name: String,
        descriptor: String,
        datavalues: BTreeMap<String, String>,
    },
    RegisterMultisig {
        multisig_name: String,
        descriptor: api::MultisigDescriptor,
        paths: Vec<Vec<u32>>,
    },
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    SignPsbt {
        psbt: Psbt,
    },
}

pub enum ReceiveAddress {
    Descriptor {
        index: u32,
        change: bool,
        descriptor_name: String,
    },
    Path {
        path: DerivationPath,
        variant: &'static str,
    },
    Multisig {
        paths: Vec<Vec<u32>>,
        multisig_name: String,
    },
}

pub enum JadeResponse {
    GetInfo(GetInfoResponse),
    MasterFingerprint(Fingerprint),
    Signature(u8, Signature),
    TaskDone,
    Xpub(Xpub),
    Address(String),
    RegisteredDescriptor,
    SignedPsbt(Psbt),
}

pub enum JadeRecipient {
    Device,
    PinServer { url: String },
}

pub struct JadeTransmit {
    pub recipient: JadeRecipient,
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

impl TryFrom<Command> for JadeCommand {
    type Error = Error;

    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Setup(..) => Err(Error::MissingCommandInfo("Setup not supported by Jade")),
            Command::Backup => Err(Error::MissingCommandInfo("Backup not supported by Jade")),
            Command::Unlock { .. } => Ok(Self::Auth),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, .. } => Ok(Self::GetXpub(path)),
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    index,
                    change,
                    descriptor_name,
                    ..
                },
                _ctx,
            ) => Ok(Self::GetReceiveAddress(ReceiveAddress::Descriptor {
                index,
                change,
                descriptor_name,
            })),
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path,
                    address_format,
                    ..
                },
                _,
            ) => Ok(Self::GetReceiveAddress(ReceiveAddress::Path {
                path,
                variant: jade_path_variant(address_format)?,
            })),
            Command::DisplayAddress(DisplayAddress::ByMultisig(address), _) => {
                jade_multisig_command(address)
            }
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetInfo),
            Command::RegisterWallet { name, policy } => {
                let (descriptor, keys) = crate::policy::extract_parts(&policy)
                    .map_err(|err| Error::Serialization(err.to_string()))?;
                // Jade's descriptor parser uses the explicit multipath spelling,
                // while BIP-388 WalletPolicy display canonicalizes it to `/**`.
                let descriptor = descriptor.replace("/**", "/<0;1>/*");
                let datavalues = keys
                    .iter()
                    .enumerate()
                    .map(|(index, key)| (format!("@{index}"), crate::policy::format_key_info(key)))
                    .collect();
                Ok(Self::RegisterDescriptor {
                    descriptor_name: name,
                    descriptor,
                    datavalues,
                })
            }
            Command::SignTx(psbt, _) => Ok(Self::SignPsbt { psbt }),
        }
    }
}

fn jade_multisig_command(address: MultisigDisplayAddress) -> Result<JadeCommand, Error> {
    let variant = match address.address_type {
        MultisigAddressType::Legacy => "sh(multi(k))",
        MultisigAddressType::Wit => "wsh(multi(k))",
        MultisigAddressType::ShWit => "sh(wsh(multi(k)))",
    };
    let mut signer_origins = Vec::with_capacity(address.keys.len());
    let mut signers = Vec::with_capacity(address.keys.len());
    let mut paths = Vec::with_capacity(address.keys.len());

    for key in address.keys {
        let DescriptorPublicKey::XPub(key) = key else {
            return Err(Error::InvalidInput(
                "Jade multisig display requires extended public keys".into(),
            ));
        };
        if key.wildcard != Wildcard::None {
            return Err(Error::InvalidInput(
                "Jade multisig display requires concrete key derivation paths".into(),
            ));
        }
        let (fingerprint, origin_path) = key.origin.ok_or_else(|| {
            Error::InvalidInput("Jade multisig display requires key origin information".into())
        })?;
        let origin = origin_path.to_u32_vec();
        signer_origins.push((fingerprint.to_bytes(), origin.clone()));
        signers.push(api::MultisigSigner {
            fingerprint: fingerprint.to_bytes().to_vec(),
            derivation: origin,
            xpub: key.xkey.to_string(),
            path: Vec::new(),
        });
        paths.push(key.derivation_path.to_u32_vec());
    }

    signer_origins.sort();
    let mut summary = format!("{variant}|{}|", address.threshold);
    for (fingerprint, path) in signer_origins {
        summary.push_str(&hex::encode(fingerprint));
        summary.push('|');
        summary.push_str(&format!("{path:?}"));
        summary.push('|');
    }
    let digest = sha256::Hash::hash(summary.as_bytes());
    let multisig_name = format!("hwi{}", &digest.to_string()[..12]);

    Ok(JadeCommand::RegisterMultisig {
        multisig_name,
        descriptor: api::MultisigDescriptor {
            variant: variant.to_string(),
            sorted: address.sorted,
            threshold: address.threshold,
            signers,
            master_blinding_key: None,
        },
        paths,
    })
}

fn jade_path_variant(address_format: Option<AddressType>) -> Result<&'static str, Error> {
    match address_format.unwrap_or(AddressType::P2wpkh) {
        AddressType::P2pkh => Ok("pkh(k)"),
        AddressType::P2sh => Ok("sh(wpkh(k))"),
        AddressType::P2wpkh => Ok("wpkh(k)"),
        AddressType::P2wsh | AddressType::P2tr => Err(Error::UnsupportedDisplayAddress(
            "Jade does not support this path address format".into(),
        )),
        _ => Err(Error::UnsupportedDisplayAddress(
            "Jade does not support this path address format".into(),
        )),
    }
}

impl From<JadeResponse> for Response {
    fn from(res: JadeResponse) -> Response {
        match res {
            JadeResponse::TaskDone => Response::TaskDone,
            JadeResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            JadeResponse::Xpub(xpub) => Response::Xpub(xpub),
            JadeResponse::Signature(header, signature) => Response::Signature(header, signature),
            JadeResponse::GetInfo(info) => Response::Info(Info {
                version: info.jade_version.as_str().into(),
                networks: info.jade_networks.into(),
                firmware: None,
                initialized: None,
            }),
            JadeResponse::Address(address) => Response::Address(address),
            JadeResponse::RegisteredDescriptor => {
                Response::WalletRegistration(crate::common::WalletRegistration::Complete {
                    hmac: None,
                })
            }
            JadeResponse::SignedPsbt(psbt) => Response::SignedPsbt(psbt),
        }
    }
}

impl From<JadeRecipient> for Recipient {
    fn from(recipient: JadeRecipient) -> Recipient {
        match recipient {
            JadeRecipient::Device => Recipient::Device,
            JadeRecipient::PinServer { url } => Recipient::PinServer { url },
        }
    }
}

impl From<JadeTransmit> for Transmit {
    fn from(transmit: JadeTransmit) -> Transmit {
        Transmit {
            recipient: transmit.recipient.into(),
            payload: transmit.payload,
            encrypted: false,
        }
    }
}

impl From<JadeError> for Error {
    fn from(error: JadeError) -> Error {
        match error {
            JadeError::Cbor => Error::Serialization("cbor".to_string()),
            JadeError::NoErrorOrResult => Error::NoErrorOrResult,
            JadeError::Rpc(api_error) => Error::Rpc(api_error.code, api_error.message),
            JadeError::Serialization(s) => Error::Serialization(s),
            JadeError::UnexpectedResult(msg) => Error::unexpected_result(
                msg.clone().into_bytes(),
                format!("jade unexpected result: {msg}"),
            ),
            JadeError::HandshakeRefused => Error::AuthenticationRefused,
            JadeError::UnsupportedDisplayAddress => {
                Error::UnsupportedDisplayAddress("unsupported display address on Jade".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Interpreter;
    use crate::common::{
        Command, DisplayAddress, JadeInterpreter, MultisigAddressType, MultisigDisplayAddress,
    };
    use crate::miniscript::descriptor::DescriptorPublicKey;
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
    fn path_display_rejects_unsupported_jade_address_format() {
        let result = JadeCommand::try_from(Command::DisplayAddress(
            DisplayAddress::ByPath {
                path: "m/86'/1'/0'/0/0".parse().unwrap(),
                display: true,
                address_format: Some(AddressType::P2tr),
            },
            None,
        ));

        assert!(matches!(result, Err(Error::UnsupportedDisplayAddress(_))));
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
            Response::WalletRegistration(crate::common::WalletRegistration::Complete {
                hmac: None
            })
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

    #[test]
    fn multisig_display_uses_upstream_hwi_registration_shape_and_name() {
        let keys = [
            "[f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/0/7",
            "[00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/0/7",
        ]
        .map(|key| DescriptorPublicKey::from_str(key).unwrap())
        .to_vec();

        let command = jade_multisig_command(MultisigDisplayAddress {
            threshold: 2,
            address_type: MultisigAddressType::Wit,
            sorted: true,
            keys,
        })
        .unwrap();

        let JadeCommand::RegisterMultisig {
            multisig_name,
            descriptor,
            paths,
        } = command
        else {
            panic!("expected multisig registration");
        };
        assert_eq!(multisig_name, "hwi78631c5c8b92");
        assert_eq!(descriptor.variant, "wsh(multi(k))");
        assert!(descriptor.sorted);
        assert_eq!(descriptor.threshold, 2);
        assert_eq!(descriptor.signers.len(), 2);
        assert!(
            descriptor
                .signers
                .iter()
                .all(|signer| signer.path.is_empty())
        );
        assert_eq!(paths, vec![vec![0, 7], vec![0, 7]]);
    }
}
