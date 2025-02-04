/// APDU commands  for the Bitcoin application.
///
use bitcoin::{
    bip32::{ChildNumber, DerivationPath},
    consensus::encode::{self, VarInt},
    Network,
};
use core::default::Default;

use super::{
    apdu::{self, ApduCommand},
    wallet::WalletPolicy,
};

// https://github.com/LedgerHQ/ledger-live/blob/5a0a1aa5dc183116839851b79bceb6704f1de4b9/libs/ledger-live-common/src/hw/openApp.ts#L3
pub fn open_app(network: Network) -> ApduCommand {
    ApduCommand {
        cla: 0xe0,
        ins: 0xd8,
        p1: 0x00,
        p2: 0x00,
        data: if network == Network::Bitcoin {
            b"Bitcoin".to_vec()
        } else {
            b"Bitcoin Test".to_vec()
        },
    }
}

/// Creates the APDU Command to retrieve the app's name, version and state flags.
pub fn get_version() -> ApduCommand {
    ApduCommand {
        ins: apdu::BitcoinCommandCode::GetVersion as u8,
        p2: 0x00,
        ..Default::default()
    }
}

/// Creates the APDU Command to retrieve the master fingerprint.
pub fn get_master_fingerprint() -> ApduCommand {
    ApduCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::GetMasterFingerprint as u8,
        ..Default::default()
    }
}

/// Creates the APDU command required to get the extended pubkey with the given derivation path.
pub fn get_extended_pubkey(path: &DerivationPath, display: bool) -> ApduCommand {
    let child_numbers: &[ChildNumber] = path.as_ref();
    let data: Vec<u8> = child_numbers.iter().fold(
        vec![
            if display { 1_u8 } else { b'\0' },
            child_numbers.len() as u8,
        ],
        |mut acc, &x| {
            acc.extend_from_slice(&u32::from(x).to_be_bytes());
            acc
        },
    );

    ApduCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::GetExtendedPubkey as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU command required to register the given wallet policy.
pub fn register_wallet(policy: &WalletPolicy) -> ApduCommand {
    let bytes = policy.serialize();
    let mut data = encode::serialize(&VarInt(bytes.len() as u64));
    data.extend(bytes);
    ApduCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::RegisterWallet as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU command required to retrieve an address for the given wallet.
pub fn get_wallet_address(
    policy: &WalletPolicy,
    hmac: Option<&[u8; 32]>,
    change: bool,
    address_index: u32,
    display: bool,
) -> ApduCommand {
    let mut data: Vec<u8> = Vec::with_capacity(70);
    data.push(if display { 1_u8 } else { b'\0' });
    data.extend_from_slice(&policy.id());
    data.extend_from_slice(hmac.unwrap_or(&[b'\0'; 32]));
    data.push(if change { 1_u8 } else { b'\0' });
    data.extend_from_slice(&address_index.to_be_bytes());
    ApduCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::GetWalletAddress as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU command required to sign a psbt.
pub fn sign_psbt(
    global_mapping_commitment: &[u8],
    inputs_number: usize,
    input_commitments_root: &[u8; 32],
    outputs_number: usize,
    output_commitments_root: &[u8; 32],
    policy: &WalletPolicy,
    hmac: Option<&[u8; 32]>,
) -> ApduCommand {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(global_mapping_commitment);
    data.extend(encode::serialize(&VarInt(inputs_number as u64)));
    data.extend_from_slice(input_commitments_root);
    data.extend(encode::serialize(&VarInt(outputs_number as u64)));
    data.extend_from_slice(output_commitments_root);
    data.extend_from_slice(&policy.id());
    data.extend_from_slice(hmac.unwrap_or(&[b'\0'; 32]));
    ApduCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::SignPSBT as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU Command to sign a message.
pub fn sign_message(
    message_length: usize,
    message_commitment_root: &[u8; 32],
    path: &DerivationPath,
) -> ApduCommand {
    let child_numbers: &[ChildNumber] = path.as_ref();
    let mut data: Vec<u8> =
        child_numbers
            .iter()
            .fold(vec![child_numbers.len() as u8], |mut acc, &x| {
                acc.extend_from_slice(&u32::from(x).to_be_bytes());
                acc
            });
    data.extend(encode::serialize(&VarInt(message_length as u64)));
    data.extend_from_slice(message_commitment_root);

    ApduCommand {
        cla: apdu::Cla::Bitcoin as u8,
        ins: apdu::BitcoinCommandCode::SignMessage as u8,
        data,
        ..Default::default()
    }
}

/// Creates the APDU command to CONTINUE.
pub fn continue_interrupted(data: Vec<u8>) -> ApduCommand {
    ApduCommand {
        cla: apdu::Cla::Framework as u8,
        ins: apdu::FrameworkCommandCode::ContinueInterrupted as u8,
        data,
        ..Default::default()
    }
}
