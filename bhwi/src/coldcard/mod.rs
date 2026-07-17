pub mod api;
pub mod encrypt;

use std::string::FromUtf8Error;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;
use miniscript::{
    Descriptor, Miniscript, ScriptContext, Terminal,
    descriptor::{DescriptorPublicKey, ShInner, WalletPolicy, Wildcard},
};

use crate::Interpreter;
use crate::coldcard::api::response::ResponseMessage;
use crate::common::{
    Command, DeviceBackup, DisplayAddress, Error, Info, Recipient, Response, Transmit,
};
use crate::device::DeviceId;

pub const DEFAULT_CKCC_SOCKET: &str = "/tmp/ckcc-simulator.sock";
pub const COLDCARD_DEVICE_ID: DeviceId = DeviceId::new(0xd13e)
    .with_pid(0xcc10)
    .with_emulator_path(DEFAULT_CKCC_SOCKET);

#[derive(Debug, thiserror::Error)]
pub enum ColdcardError {
    /// Encryption error
    #[error("encryption error: {0}")]
    Encryption(&'static str),

    #[error("missing command info: {0}")]
    MissingCommandInfo(&'static str),

    #[error("no error or result returned")]
    NoErrorOrResult,

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Unexpected response message from device
    #[error("unexpected response message: got {got:?}, expected {expected:?}")]
    UnexpectedResponseMessage {
        got: ResponseMessage,
        expected: Vec<ResponseMessage>,
    },
}

impl ColdcardError {
    pub fn unexpected_response_message(
        got: ResponseMessage,
        expected: &[ResponseMessage],
    ) -> ColdcardError {
        ColdcardError::UnexpectedResponseMessage {
            got,
            expected: expected.to_vec(),
        }
    }
}

pub enum ColdcardCommand {
    StartEncryption,
    Backup,
    GetVersion,
    GetMasterFingerprint,
    GetXpub(DerivationPath),
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    ShowAddress {
        path: DerivationPath,
        addr_fmt: u32,
    },
    MiniscriptAddress {
        name: String,
        change: bool,
        index: u32,
    },
    SignPsbt {
        psbt: Psbt,
    },
    RegisterWallet {
        payload: Vec<u8>,
    },
}

pub enum ColdcardResponse {
    Ok,
    Busy,
    Version {
        version: String,
        device_model: String,
    },
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    MyPub {
        encryption_key: [u8; 64],
        xpub_fingerprint: Fingerprint,
        xpub: Option<Xpub>,
    },
    Signature(u8, Signature),
    Address(String),
    Backup(Vec<u8>),
    SignedPsbt(Psbt),
    WalletRegistrationPending,
}

pub struct ColdcardTransmit {
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

enum State {
    New,
    Running(ColdcardCommand),
    UploadingFile {
        bytes: Vec<u8>,
        offset: usize,
        action: UploadAction,
    },
    VerifyingFileUpload {
        length: usize,
        expected_sha: [u8; 32],
        action: UploadAction,
    },
    SigningPsbt,
    EnrollingWallet,
    PollingSignedPsbt,
    PollingBackupFile,
    DownloadingFile {
        response: FileDownloadResponse,
        file_number: u32,
        expected_sha: [u8; 32],
        bytes: Vec<u8>,
        offset: usize,
        total_len: usize,
    },
    Finished(ColdcardResponse),
}

#[derive(Clone, Copy)]
enum UploadAction {
    SignPsbt,
    RegisterWallet,
}

enum FileDownloadResponse {
    Backup,
    SignedPsbt,
}

pub struct ColdcardInterpreter<'a, C, T, R, E> {
    state: State,
    encryption: &'a mut encrypt::Engine,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<'a, C, T, R, E> ColdcardInterpreter<'a, C, T, R, E> {
    pub fn new(encryption: &'a mut encrypt::Engine) -> Self {
        Self {
            state: State::New,
            encryption,
            _marker: std::marker::PhantomData,
        }
    }
}

fn request(
    payload: Vec<u8>,
    encryption: &mut encrypt::Engine,
) -> Result<ColdcardTransmit, ColdcardError> {
    Ok(ColdcardTransmit {
        payload: encryption.encrypt(payload)?,
        encrypted: true,
    })
}

fn file_upload_request(bytes: &[u8], offset: usize) -> Result<Vec<u8>, ColdcardError> {
    let end = (offset + api::request::MAX_UPLOAD_CHUNK_LEN).min(bytes.len());
    let offset = u32::try_from(offset)
        .map_err(|_| ColdcardError::Serialization("upload offset too large".to_string()))?;
    let total = u32::try_from(bytes.len())
        .map_err(|_| ColdcardError::Serialization("upload too large".to_string()))?;
    Ok(api::request::upload(
        offset,
        total,
        &bytes[offset as usize..end],
    ))
}

fn download_request(
    offset: usize,
    total_len: usize,
    file_number: u32,
) -> Result<Vec<u8>, ColdcardError> {
    let length = (api::request::MAX_UPLOAD_CHUNK_LEN).min(total_len - offset);
    let offset = u32::try_from(offset)
        .map_err(|_| ColdcardError::Serialization("download offset too large".to_string()))?;
    let length = u32::try_from(length)
        .map_err(|_| ColdcardError::Serialization("download length too large".to_string()))?;
    Ok(api::request::download(offset, length, file_number))
}

impl<'a, C, T, R, E> Interpreter for ColdcardInterpreter<'a, C, T, R, E>
where
    C: TryInto<ColdcardCommand, Error = ColdcardError>,
    T: From<ColdcardTransmit>,
    R: From<ColdcardResponse>,
    E: From<ColdcardError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: ColdcardCommand = command.try_into()?;
        let req = match &command {
            ColdcardCommand::StartEncryption => ColdcardTransmit {
                payload: api::request::start_encryption(None, &self.encryption.pub_key()?),
                encrypted: false,
            },
            ColdcardCommand::Backup => request(api::request::start_backup(), self.encryption)?,
            ColdcardCommand::GetVersion => request(api::request::get_version(), self.encryption)?,
            ColdcardCommand::GetMasterFingerprint => request(
                api::request::get_xpub(&DerivationPath::master()),
                self.encryption,
            )?,
            ColdcardCommand::GetXpub(path) => {
                request(api::request::get_xpub(path), self.encryption)?
            }
            ColdcardCommand::SignMessage { message, path } => {
                request(api::request::sign_message(message, path), self.encryption)?
            }
            ColdcardCommand::ShowAddress { path, addr_fmt } => {
                request(api::request::show_address(path, *addr_fmt), self.encryption)?
            }
            ColdcardCommand::MiniscriptAddress {
                name,
                change,
                index,
            } => request(
                api::request::miniscript_address(name, *change, *index),
                self.encryption,
            )?,
            ColdcardCommand::SignPsbt { psbt } => {
                let bytes = psbt.serialize();
                let req = request(file_upload_request(&bytes, 0)?, self.encryption)?;
                self.state = State::UploadingFile {
                    bytes,
                    offset: 0,
                    action: UploadAction::SignPsbt,
                };
                return Ok(req.into());
            }
            ColdcardCommand::RegisterWallet { payload } => {
                let bytes = payload.clone();
                let req = request(file_upload_request(&bytes, 0)?, self.encryption)?;
                self.state = State::UploadingFile {
                    bytes,
                    offset: 0,
                    action: UploadAction::RegisterWallet,
                };
                return Ok(req.into());
            }
        };

        self.state = State::Running(command);
        Ok(req.into())
    }
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        match &mut self.state {
            State::New => Ok(None),
            State::Running(ColdcardCommand::GetVersion) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::version(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::GetMasterFingerprint) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::master_fingerprint(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::GetXpub(..)) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::get_xpub(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::SignMessage { .. }) => {
                let data = self.encryption.decrypt(data)?;
                let res = api::response::sign_message(&data)?;
                if let ColdcardResponse::Ok | ColdcardResponse::Busy = res {
                    return Ok(Some(
                        request(api::request::get_signed_message(), self.encryption)?.into(),
                    ));
                }
                self.state = State::Finished(res);
                Ok(None)
            }
            State::Running(ColdcardCommand::StartEncryption) => {
                let mypub = api::response::mypub(&data)?;
                self.state = State::Finished(mypub);
                Ok(None)
            }
            State::Running(ColdcardCommand::Backup) => {
                let data = self.encryption.decrypt(data)?;
                let res = api::response::sign_transaction(&data)?;
                if let ColdcardResponse::Ok | ColdcardResponse::Busy = res {
                    self.state = State::PollingBackupFile;
                    return Ok(Some(
                        request(api::request::get_backup_file(), self.encryption)?.into(),
                    ));
                }
                Ok(None)
            }
            State::Running(ColdcardCommand::ShowAddress { .. }) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::show_address(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::MiniscriptAddress { .. }) => {
                let data = self.encryption.decrypt(data)?;
                self.state = State::Finished(api::response::miniscript_address(&data)?);
                Ok(None)
            }
            State::Running(ColdcardCommand::SignPsbt { .. }) => unreachable!("handled in start"),
            State::Running(ColdcardCommand::RegisterWallet { .. }) => {
                unreachable!("handled in start")
            }
            State::UploadingFile {
                bytes,
                offset,
                action,
            } => {
                let data = self.encryption.decrypt(data)?;
                let acknowledged = api::response::upload(&data)? as usize;
                if acknowledged != *offset {
                    return Err(ColdcardError::Serialization(format!(
                        "unexpected upload offset {acknowledged}, wanted {offset}"
                    ))
                    .into());
                }

                let next_offset = (*offset + api::request::MAX_UPLOAD_CHUNK_LEN).min(bytes.len());
                if next_offset < bytes.len() {
                    let req = request(file_upload_request(bytes, next_offset)?, self.encryption)?;
                    *offset = next_offset;
                    return Ok(Some(req.into()));
                }

                let length = bytes.len();
                let expected_sha = sha256::Hash::hash(bytes).to_byte_array();
                self.state = State::VerifyingFileUpload {
                    length,
                    expected_sha,
                    action: *action,
                };
                Ok(Some(
                    request(api::request::sha256(), self.encryption)?.into(),
                ))
            }
            State::VerifyingFileUpload {
                length,
                expected_sha,
                action,
            } => {
                let data = self.encryption.decrypt(data)?;
                let length = *length;
                let expected_sha = *expected_sha;
                let actual_sha = api::response::sha256(&data)?;
                if actual_sha != expected_sha {
                    return Err(ColdcardError::Serialization(
                        "coldcard upload sha mismatch".to_string(),
                    )
                    .into());
                }

                let length = u32::try_from(length)
                    .map_err(|_| ColdcardError::Serialization("upload too large".to_string()))?;
                let request_payload = match action {
                    UploadAction::SignPsbt => {
                        self.state = State::SigningPsbt;
                        api::request::sign_transaction(length, &expected_sha)
                    }
                    UploadAction::RegisterWallet => {
                        self.state = State::EnrollingWallet;
                        api::request::multisig_enroll(length, &expected_sha)
                    }
                };
                Ok(Some(request(request_payload, self.encryption)?.into()))
            }
            State::SigningPsbt => {
                let data = self.encryption.decrypt(data)?;
                let res = api::response::sign_transaction(&data)?;
                if let ColdcardResponse::Ok | ColdcardResponse::Busy = res {
                    self.state = State::PollingSignedPsbt;
                    return Ok(Some(
                        request(api::request::get_signed_transaction(), self.encryption)?.into(),
                    ));
                }
                Ok(None)
            }
            State::EnrollingWallet => {
                let data = self.encryption.decrypt(data)?;
                api::response::okay(&data)?;
                self.state = State::Finished(ColdcardResponse::WalletRegistrationPending);
                Ok(None)
            }
            State::PollingSignedPsbt => {
                let data = self.encryption.decrypt(data)?;
                match api::response::signed_transaction(&data)? {
                    api::response::SignedTransactionStatus::Pending => {
                        self.state = State::PollingSignedPsbt;
                        Ok(Some(
                            request(api::request::get_signed_transaction(), self.encryption)?
                                .into(),
                        ))
                    }
                    api::response::SignedTransactionStatus::Complete { length, sha } => {
                        let total_len = usize::try_from(length).map_err(|_| {
                            ColdcardError::Serialization(
                                "signed psbt length cannot fit usize".to_string(),
                            )
                        })?;
                        self.state = State::DownloadingFile {
                            response: FileDownloadResponse::SignedPsbt,
                            file_number: 1,
                            expected_sha: sha,
                            bytes: Vec::with_capacity(total_len),
                            offset: 0,
                            total_len,
                        };
                        Ok(Some(
                            request(download_request(0, total_len, 1)?, self.encryption)?.into(),
                        ))
                    }
                }
            }
            State::PollingBackupFile => {
                let data = self.encryption.decrypt(data)?;
                match api::response::signed_transaction(&data)? {
                    api::response::SignedTransactionStatus::Pending => {
                        self.state = State::PollingBackupFile;
                        Ok(Some(
                            request(api::request::get_backup_file(), self.encryption)?.into(),
                        ))
                    }
                    api::response::SignedTransactionStatus::Complete { length, sha } => {
                        let total_len = usize::try_from(length).map_err(|_| {
                            ColdcardError::Serialization(
                                "backup file length cannot fit usize".to_string(),
                            )
                        })?;
                        self.state = State::DownloadingFile {
                            response: FileDownloadResponse::Backup,
                            file_number: 0,
                            expected_sha: sha,
                            bytes: Vec::with_capacity(total_len),
                            offset: 0,
                            total_len,
                        };
                        Ok(Some(
                            request(download_request(0, total_len, 0)?, self.encryption)?.into(),
                        ))
                    }
                }
            }
            State::DownloadingFile {
                response,
                file_number,
                expected_sha,
                bytes,
                offset,
                total_len,
            } => {
                let data = self.encryption.decrypt(data)?;
                let chunk = api::response::download(&data)?;
                if chunk.is_empty() {
                    return Err(ColdcardError::Serialization(
                        "empty coldcard file download chunk".into(),
                    )
                    .into());
                }
                bytes.extend_from_slice(&chunk);
                *offset += chunk.len();
                if *offset < *total_len {
                    let req = request(
                        download_request(*offset, *total_len, *file_number)?,
                        self.encryption,
                    )?;
                    return Ok(Some(req.into()));
                }
                if *offset != *total_len {
                    return Err(ColdcardError::Serialization(format!(
                        "downloaded coldcard file length {offset}, wanted {total_len}"
                    ))
                    .into());
                }
                let actual_sha = sha256::Hash::hash(bytes).to_byte_array();
                if actual_sha != *expected_sha {
                    return Err(ColdcardError::Serialization(
                        "coldcard file download sha mismatch".to_string(),
                    )
                    .into());
                }
                let response = match response {
                    FileDownloadResponse::Backup => ColdcardResponse::Backup(std::mem::take(bytes)),
                    FileDownloadResponse::SignedPsbt => {
                        let signed = Psbt::deserialize(bytes)
                            .map_err(|e| ColdcardError::Serialization(e.to_string()))?;
                        ColdcardResponse::SignedPsbt(signed)
                    }
                };
                self.state = State::Finished(response);
                Ok(None)
            }
            State::Finished(..) => Ok(None),
        }
    }
    fn end(self) -> Result<Self::Response, Self::Error> {
        if let State::Finished(res) = self.state {
            Ok(Self::Response::from(res))
        } else {
            Err(ColdcardError::NoErrorOrResult.into())
        }
    }
}

impl TryFrom<Command> for ColdcardCommand {
    type Error = ColdcardError;
    fn try_from(cmd: Command) -> Result<Self, Self::Error> {
        match cmd {
            Command::Backup => Ok(Self::Backup),
            Command::Unlock { .. } => Ok(Self::StartEncryption),
            Command::GetMasterFingerprint => Ok(Self::GetMasterFingerprint),
            Command::GetXpub { path, .. } => Ok(Self::GetXpub(path)),
            Command::SignMessage { message, path } => Ok(Self::SignMessage { message, path }),
            Command::GetVersion => Ok(Self::GetVersion),
            Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path,
                    address_format,
                    ..
                },
                ..,
            ) => Ok(Self::ShowAddress {
                path,
                addr_fmt: address_format
                    .map(api::request::addr_fmt::from_address_type)
                    .unwrap_or(api::request::addr_fmt::AF_P2WPKH),
            }),
            Command::DisplayAddress(
                DisplayAddress::ByDescriptor {
                    descriptor_name,
                    change,
                    index,
                    ..
                },
                ..,
            ) => Ok(Self::MiniscriptAddress {
                name: descriptor_name,
                change,
                index,
            }),
            Command::RegisterWallet { name, policy } => Ok(Self::RegisterWallet {
                payload: coldcard_registration_payload(&name, &policy)?,
            }),
            Command::SignTx(psbt, context) => {
                if context.is_some() {
                    return Err(ColdcardError::MissingCommandInfo(
                        "Coldcard SignTx does not support device context",
                    ));
                }
                Ok(Self::SignPsbt { psbt })
            }
        }
    }
}

fn coldcard_registration_payload(
    name: &str,
    policy: &WalletPolicy,
) -> Result<Vec<u8>, ColdcardError> {
    if !(2..=20).contains(&name.len())
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(ColdcardError::InvalidInput(
            "Coldcard wallet names must be 2 to 20 printable ASCII characters".to_string(),
        ));
    }

    let descriptor = policy
        .clone()
        .into_descriptor()
        .map_err(|error| ColdcardError::InvalidInput(error.to_string()))?;
    let (threshold, signer_count) = coldcard_sortedmulti_size(&descriptor).ok_or_else(|| {
        ColdcardError::InvalidInput(
            "Coldcard registration supports only sh(sortedmulti), wsh(sortedmulti), and sh(wsh(sortedmulti)) descriptors"
                .to_string(),
        )
    })?;
    if threshold == 0 || threshold > signer_count || signer_count > 15 {
        return Err(ColdcardError::InvalidInput(
            "Coldcard multisig policies require 1 to 15 signers and a valid threshold".to_string(),
        ));
    }
    for key in descriptor.iter_pk() {
        validate_coldcard_registration_key(&key)?;
    }

    let descriptor = format!("{descriptor:#}");
    let payload = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "desc": descriptor,
    }))
    .map_err(|error| ColdcardError::Serialization(error.to_string()))?;
    if !(101..=4000).contains(&payload.len()) {
        return Err(ColdcardError::InvalidInput(
            "Coldcard multisig registration payload must be 101 to 4000 bytes".to_string(),
        ));
    }
    Ok(payload)
}

fn coldcard_sortedmulti_size(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Option<(usize, usize)> {
    match descriptor {
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::Ms(miniscript) => sortedmulti_size(miniscript),
            ShInner::Wsh(wsh) => sortedmulti_size(wsh.as_inner()),
            ShInner::Wpkh(_) => None,
        },
        Descriptor::Wsh(wsh) => sortedmulti_size(wsh.as_inner()),
        _ => None,
    }
}

fn sortedmulti_size<Ctx: ScriptContext>(
    miniscript: &Miniscript<DescriptorPublicKey, Ctx>,
) -> Option<(usize, usize)> {
    match &miniscript.node {
        Terminal::SortedMulti(threshold) => Some((threshold.k(), threshold.n())),
        _ => None,
    }
}

fn validate_coldcard_registration_key(key: &DescriptorPublicKey) -> Result<(), ColdcardError> {
    let normal = |index| bitcoin::bip32::ChildNumber::from_normal_idx(index).expect("small index");
    let valid_single_path = |path: &DerivationPath| path.as_ref() == [normal(0)];
    let valid_multi_paths = |paths: &[DerivationPath]| {
        if paths.len() != 2 || paths.iter().any(|path| path.as_ref().len() != 1) {
            return false;
        }
        let mut branches = paths
            .iter()
            .map(|path| path.as_ref()[0])
            .collect::<Vec<_>>();
        branches.sort_unstable();
        branches == [normal(0), normal(1)]
    };

    let valid = match key {
        DescriptorPublicKey::XPub(key) => {
            key.origin.is_some()
                && key.wildcard == Wildcard::Unhardened
                && valid_single_path(&key.derivation_path)
        }
        DescriptorPublicKey::MultiXPub(key) => {
            key.origin.is_some()
                && key.wildcard == Wildcard::Unhardened
                && valid_multi_paths(key.derivation_paths.paths())
        }
        DescriptorPublicKey::Single(_) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ColdcardError::InvalidInput(
            "Coldcard multisig keys require origins, extended public keys, and /0/* or /<0;1>/* derivation"
                .to_string(),
        ))
    }
}

impl From<ColdcardResponse> for Response {
    fn from(res: ColdcardResponse) -> Response {
        match res {
            ColdcardResponse::MasterFingerprint(fg) => Response::MasterFingerprint(fg),
            ColdcardResponse::Xpub(xpub) => Response::Xpub(xpub),
            ColdcardResponse::Version {
                version,
                device_model,
            } => Response::Info(Info {
                version: version.as_str().into(),
                networks: vec![],
                firmware: Some(device_model),
            }),
            ColdcardResponse::MyPub { encryption_key, .. } => {
                Response::EncryptionKey(encryption_key)
            }
            ColdcardResponse::Signature(header, signature) => {
                Response::Signature(header, signature)
            }
            ColdcardResponse::Ok => Response::TaskDone,
            ColdcardResponse::Busy => Response::TaskBusy,
            ColdcardResponse::Address(address) => Response::Address(address),
            ColdcardResponse::Backup(bytes) => Response::Backup(DeviceBackup::File(bytes)),
            ColdcardResponse::SignedPsbt(psbt) => Response::SignedPsbt(psbt),
            ColdcardResponse::WalletRegistrationPending => Response::WalletRegistration(
                crate::common::WalletRegistration::PendingUserConfirmation,
            ),
        }
    }
}

impl From<ColdcardTransmit> for Transmit {
    fn from(transmit: ColdcardTransmit) -> Transmit {
        Transmit {
            recipient: Recipient::Device,
            payload: transmit.payload,
            encrypted: transmit.encrypted,
        }
    }
}

impl From<ColdcardError> for Error {
    fn from(error: ColdcardError) -> Error {
        match error {
            ColdcardError::Encryption(e) => Error::Encryption(e),
            ColdcardError::MissingCommandInfo(e) => Error::MissingCommandInfo(e),
            ColdcardError::NoErrorOrResult => Error::NoErrorOrResult,
            ColdcardError::Serialization(s) => Error::Serialization(s),
            ColdcardError::InvalidInput(s) => Error::InvalidInput(s),
            ColdcardError::UnexpectedResponseMessage { got, expected } => Error::unexpected_result(
                format!("{got:?}").into_bytes(),
                format!("coldcard unexpected response: expected {expected:?}, got {got:?}"),
            ),
        }
    }
}

impl From<FromUtf8Error> for ColdcardError {
    fn from(error: FromUtf8Error) -> Self {
        ColdcardError::Serialization(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::hashes::{Hash, sha256};

    use super::*;

    const REGISTRATION_POLICY: &str = "wsh(sortedmulti(2,[f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*,[00000000/48'/1'/0'/2']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*))";

    fn paired_engines() -> (encrypt::Engine, encrypt::Engine) {
        let mut host = encrypt::Engine::New(k256::SecretKey::from_slice(&[1u8; 32]).unwrap());
        let mut device = encrypt::Engine::New(k256::SecretKey::from_slice(&[2u8; 32]).unwrap());
        let host_pubkey = host.pub_key().unwrap();
        let device_pubkey = device.pub_key().unwrap();
        host.ready(device_pubkey).unwrap();
        device.ready(host_pubkey).unwrap();
        (host, device)
    }

    fn encrypt_response(device: &mut encrypt::Engine, response: &[u8]) -> Vec<u8> {
        device.encrypt(response.to_vec()).unwrap()
    }

    fn decrypt_request(device: &mut encrypt::Engine, request: Transmit) -> Vec<u8> {
        assert!(request.encrypted);
        device.decrypt(request.payload).unwrap()
    }

    #[test]
    fn backup_state_machine_polls_and_downloads_file_zero() {
        let (mut host, mut device) = paired_engines();
        let backup = b"encrypted backup bytes".to_vec();
        let backup_sha = sha256::Hash::hash(&backup).to_byte_array();
        let mut interpreter: ColdcardInterpreter<'_, Command, Transmit, Response, Error> =
            ColdcardInterpreter::new(&mut host);

        let request = interpreter.start(Command::Backup).unwrap();
        assert_eq!(decrypt_request(&mut device, request), b"back");

        let request = interpreter
            .exchange(encrypt_response(&mut device, b"okay"))
            .unwrap()
            .expect("poll request");
        assert_eq!(decrypt_request(&mut device, request), b"bkok");

        let request = interpreter
            .exchange(encrypt_response(&mut device, b"busy"))
            .unwrap()
            .expect("second poll request");
        assert_eq!(decrypt_request(&mut device, request), b"bkok");

        let mut complete = b"strx".to_vec();
        complete.extend((backup.len() as u32).to_le_bytes());
        complete.extend(backup_sha);
        let request = interpreter
            .exchange(encrypt_response(&mut device, &complete))
            .unwrap()
            .expect("download request");
        let download = decrypt_request(&mut device, request);
        assert_eq!(&download[..4], b"dwld");
        assert_eq!(u32::from_le_bytes(download[4..8].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(download[8..12].try_into().unwrap()),
            backup.len() as u32
        );
        assert_eq!(u32::from_le_bytes(download[12..16].try_into().unwrap()), 0);

        let mut chunk = b"biny".to_vec();
        chunk.extend(&backup);
        assert!(
            interpreter
                .exchange(encrypt_response(&mut device, &chunk))
                .unwrap()
                .is_none()
        );

        match interpreter.end().unwrap() {
            Response::Backup(DeviceBackup::File(bytes)) => assert_eq!(bytes, backup),
            _ => panic!("expected backup response"),
        }
    }

    #[test]
    fn registration_payload_contains_name_and_full_descriptor() {
        let policy = WalletPolicy::from_str(REGISTRATION_POLICY).unwrap();
        let payload = coldcard_registration_payload("cold-wallet", &policy).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["name"], "cold-wallet");
        assert_eq!(payload["desc"], REGISTRATION_POLICY);
    }

    #[test]
    fn registration_rejects_unsupported_policy_and_name() {
        let singlesig = WalletPolicy::from_str(
            "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*)",
        )
        .unwrap();
        let error = coldcard_registration_payload("cold-wallet", &singlesig).unwrap_err();
        assert!(error.to_string().contains("supports only"));

        let policy = WalletPolicy::from_str(REGISTRATION_POLICY).unwrap();
        let error = coldcard_registration_payload("x", &policy).unwrap_err();
        assert!(error.to_string().contains("2 to 20"));
    }

    #[test]
    fn registration_rejects_keys_without_origins() {
        let policy = WalletPolicy::from_str(
            "wsh(sortedmulti(2,tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*,tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*))",
        )
        .unwrap();
        let error = coldcard_registration_payload("cold-wallet", &policy).unwrap_err();
        assert!(error.to_string().contains("require origins"));
    }

    #[test]
    fn register_wallet_uploads_verifies_and_starts_enrollment() {
        let (mut host, mut device) = paired_engines();
        let policy = WalletPolicy::from_str(REGISTRATION_POLICY).unwrap();
        let mut interpreter: ColdcardInterpreter<'_, Command, Transmit, Response, Error> =
            ColdcardInterpreter::new(&mut host);

        let request = interpreter
            .start(Command::RegisterWallet {
                name: "cold-wallet".to_string(),
                policy,
            })
            .unwrap();
        let upload = decrypt_request(&mut device, request);
        assert_eq!(&upload[..4], b"upld");
        assert_eq!(u32::from_le_bytes(upload[4..8].try_into().unwrap()), 0);
        let total_len = u32::from_le_bytes(upload[8..12].try_into().unwrap()) as usize;
        let uploaded = &upload[12..];
        assert_eq!(uploaded.len(), total_len);

        let mut acknowledged = b"int1".to_vec();
        acknowledged.extend(0u32.to_le_bytes());
        let request = interpreter
            .exchange(encrypt_response(&mut device, &acknowledged))
            .unwrap()
            .expect("sha request");
        assert_eq!(decrypt_request(&mut device, request), b"sha2");

        let upload_sha = sha256::Hash::hash(uploaded).to_byte_array();
        let mut sha_response = b"biny".to_vec();
        sha_response.extend(upload_sha);
        let request = interpreter
            .exchange(encrypt_response(&mut device, &sha_response))
            .unwrap()
            .expect("enrollment request");
        let enroll = decrypt_request(&mut device, request);
        assert_eq!(&enroll[..4], b"enrl");
        assert_eq!(
            u32::from_le_bytes(enroll[4..8].try_into().unwrap()),
            total_len as u32
        );
        assert_eq!(&enroll[8..], &upload_sha);

        assert!(
            interpreter
                .exchange(encrypt_response(&mut device, b"okay"))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            interpreter.end().unwrap(),
            Response::WalletRegistration(
                crate::common::WalletRegistration::PendingUserConfirmation
            )
        ));
    }
}
