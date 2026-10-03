//! Host preimages and Merkle commitments for Ledger delegated commands.

use core::convert::TryFrom;
use core::fmt::Debug;

use bitcoin::{
    consensus::encode::{self, VarInt},
    hashes::{Hash, HashEngine, sha256},
};

use super::{apdu::ClientCommandCode, merkle::MerkleTree};

/// Known preimages, Merkle trees, queued response fragments, and device-yielded values.
#[derive(Default)]
pub struct DelegatedStore {
    yielded: Vec<Vec<u8>>,
    queue: Vec<Vec<u8>>,
    known_preimages: Vec<([u8; 32], Vec<u8>)>,
    trees: Vec<MerkleTree>,
}

impl DelegatedStore {
    /// Creates an empty delegated store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a preimage to the list of known preimages.
    /// The client must respond with `element` when a GET_PREIMAGE command is sent with
    /// `sha256(element)` in its request.
    pub fn add_known_preimage(&mut self, element: Vec<u8>) {
        let mut engine = sha256::Hash::engine();
        engine.input(&element);
        let hash = sha256::Hash::from_engine(engine).to_byte_array();
        self.known_preimages.push((hash, element));
    }

    /// Registers a Merkleized list and returns its root.
    ///
    /// Each element is also stored as a preimage prefixed with a zero byte,
    /// allowing the device to request leaves, indices, and proofs.
    pub fn add_known_list(&mut self, elements: &[impl AsRef<[u8]>]) -> [u8; 32] {
        let mut leaves = Vec::with_capacity(elements.len());
        for element in elements {
            let mut preimage = vec![0x00];
            preimage.extend_from_slice(element.as_ref());
            let mut engine = sha256::Hash::engine();
            engine.input(&preimage);
            let hash = sha256::Hash::from_engine(engine).to_byte_array();
            self.known_preimages.push((hash, preimage));
            leaves.push(hash);
        }
        let tree = MerkleTree::new(leaves);
        let root_hash = *tree.root_hash();
        self.trees.push(tree);
        root_hash
    }

    /// Registers key and value Merkle trees after sorting the mapping by key.
    pub fn add_known_mapping(&mut self, mapping: &[(Vec<u8>, Vec<u8>)]) {
        let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = mapping.iter().collect();
        sorted.sort_by(|(k1, _), (k2, _)| k1.as_slice().cmp(k2));

        let mut keys = Vec::with_capacity(sorted.len());
        let mut values = Vec::with_capacity(sorted.len());
        for (key, value) in sorted {
            keys.push(key.as_slice());
            values.push(value.as_slice());
        }
        self.add_known_list(&keys);
        self.add_known_list(&values);
    }

    /// Answers a delegated device command, updating queued fragments or yielded values.
    pub fn execute(&mut self, command: Vec<u8>) -> Result<Vec<u8>, StoreError> {
        if command.is_empty() {
            return Err(StoreError::EmptyInput);
        }
        match ClientCommandCode::try_from(command[0]) {
            Ok(ClientCommandCode::Yield) => {
                self.yielded.push(command[1..].to_vec());
                Ok(Vec::new())
            }
            Ok(ClientCommandCode::GetPreimage) => {
                get_preimage_command(&mut self.queue, &self.known_preimages, &command[1..])
            }
            Ok(ClientCommandCode::GetMerkleLeafProof) => {
                get_merkle_leaf_proof(&mut self.queue, &self.trees, &command[1..])
            }
            Ok(ClientCommandCode::GetMerkleLeafIndex) => {
                get_merkle_leaf_index(&self.trees, &command[1..])
            }
            Ok(ClientCommandCode::GetMoreElements) => get_more_elements(&mut self.queue),
            Err(()) => Err(StoreError::UnknownCommand(command[0])),
        }
    }

    /// Consumes the interpreter and returns the yielded results.
    pub fn yielded(self) -> Vec<Vec<u8>> {
        self.yielded
    }
}

fn get_preimage_command(
    queue: &mut Vec<Vec<u8>>,
    known_preimages: &[([u8; 32], Vec<u8>)],
    request: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if request.len() != 33 || request[0] != b'\0' {
        return Err(StoreError::UnsupportedRequest(
            ClientCommandCode::GetPreimage as u8,
        ));
    };

    let (_, preimage) = known_preimages
        .iter()
        .find(|(hash, _)| hash == &request[1..])
        .ok_or(StoreError::UnknownHash)?;

    let preimage_len_out = encode::serialize(&VarInt(preimage.len() as u64));

    // We can send at most 255 - len(preimage_len_out) - 1 bytes in a single message;
    //the rest will be stored for GET_MORE_ELEMENTS
    let max_payload_size = 255 - preimage_len_out.len() - 1;

    let payload_size = if preimage.len() > max_payload_size {
        max_payload_size
    } else {
        preimage.len()
    };

    if payload_size < preimage.len() {
        for byte in &preimage[payload_size..] {
            queue.push(vec![*byte]);
        }
    }

    let mut response = preimage_len_out;
    response.extend_from_slice(&(payload_size as u8).to_be_bytes());
    response.extend_from_slice(&preimage[..payload_size]);
    Ok(response)
}

fn get_merkle_leaf_proof(
    queue: &mut Vec<Vec<u8>>,
    trees: &[MerkleTree],
    request: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if !queue.is_empty() {
        return Err(StoreError::UnexpectedQueue);
    } else if request.len() < 34 {
        return Err(StoreError::UnsupportedRequest(
            ClientCommandCode::GetMerkleLeafProof as u8,
        ));
    };

    let root = &request[0..32];
    let (tree_size, read): (VarInt, usize) = encode::deserialize_partial(&request[32..])
        .map_err(|_| StoreError::UnsupportedRequest(ClientCommandCode::GetMerkleLeafProof as u8))?;

    // deserialize consumes the entire vector.
    let leaf_index: VarInt = encode::deserialize(&request[32 + read..])
        .map_err(|_| StoreError::UnsupportedRequest(ClientCommandCode::GetMerkleLeafProof as u8))?;

    let tree = trees
        .iter()
        .find(|tree| tree.root_hash() == root)
        .ok_or(StoreError::UnknownMerkleRoot)?;

    if leaf_index >= tree_size || tree_size.0 != tree.size() as u64 {
        return Err(StoreError::InvalidIndexOrSize);
    }

    let proof = tree
        .get_leaf_proof(leaf_index.0 as usize)
        .ok_or(StoreError::InvalidIndexOrSize)?;

    let len_proof = proof.len();
    let mut first_part_proof = Vec::new();
    let mut n_response_elements = 0;
    for (i, p) in proof.into_iter().enumerate() {
        // how many elements we can fit in 255 - 32 - 1 - 1 = 221 bytes ?
        // response: 6 array of 32 bytes.
        if i < 6 {
            first_part_proof.extend(p);
            n_response_elements += 1;
        } else {
            // Add to the queue any proof elements that do not fit the response
            queue.push(p);
        }
    }

    let mut response = tree.get_leaf(leaf_index.0 as usize).unwrap().to_vec();
    response.extend_from_slice(&(len_proof as u8).to_be_bytes());
    response.extend_from_slice(&(n_response_elements as u8).to_be_bytes());
    response.extend_from_slice(&first_part_proof);
    Ok(response)
}

fn get_merkle_leaf_index(trees: &[MerkleTree], request: &[u8]) -> Result<Vec<u8>, StoreError> {
    if request.len() < 64 {
        return Err(StoreError::UnsupportedRequest(
            ClientCommandCode::GetMerkleLeafIndex as u8,
        ));
    }
    let root = &request[0..32];
    let hash = &request[32..64];

    let tree = trees
        .iter()
        .find(|tree| tree.root_hash() == root)
        .ok_or(StoreError::UnknownMerkleRoot)?;

    let (found, leaf_index) = tree
        .get_leaf_index(hash)
        .map_or((0_u8, 0_usize), |index| (1, index));

    let mut response = found.to_be_bytes().to_vec();
    response.extend(encode::serialize(&VarInt(leaf_index as u64)));
    Ok(response)
}

fn get_more_elements(queue: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, StoreError> {
    if queue.is_empty() {
        return Err(StoreError::UnexpectedQueue);
    }

    // The queue must contain only element of the same length.
    let element_length = queue[0].len();
    if queue.iter().any(|e| e.len() != element_length) {
        return Err(StoreError::UnexpectedQueue);
    }

    let mut response_elements = Vec::new();
    let mut n_added_elements = 0;
    for element in queue.iter() {
        if response_elements.len() + element_length <= 253 {
            response_elements.extend_from_slice(element);
            n_added_elements += 1;
        }
    }
    *queue = queue[n_added_elements..].to_vec();

    let mut response = (n_added_elements as u8).to_be_bytes().to_vec();
    response.extend((element_length as u8).to_be_bytes());
    response.extend(response_elements);
    Ok(response)
}

/// Returns a serialized Merkleized map commitment, encoded as the concatenation of:
///     - the number of key/value pairs, as a Bitcoin-style varint;
///     - the root of the Merkle tree of the keys
///     - the root of the Merkle tree of the values.
pub fn get_merkleized_map_commitment(mapping: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = mapping.iter().collect();
    sorted.sort_by(|(k1, _), (k2, _)| k1.as_slice().cmp(k2));

    let mut keys_hashes: Vec<[u8; 32]> = Vec::with_capacity(sorted.len());
    let mut values_hashes: Vec<[u8; 32]> = Vec::with_capacity(sorted.len());
    for (key, value) in &sorted {
        let mut preimage = vec![0x00];
        preimage.extend_from_slice(key);
        let mut engine = sha256::Hash::engine();
        engine.input(&preimage);
        keys_hashes.push(sha256::Hash::from_engine(engine).to_byte_array());

        let mut preimage = vec![0x00];
        preimage.extend_from_slice(value);
        let mut engine = sha256::Hash::engine();
        engine.input(&preimage);
        values_hashes.push(sha256::Hash::from_engine(engine).to_byte_array());
    }

    let mut commitment = encode::serialize(&VarInt(sorted.len() as u64));
    commitment.extend(MerkleTree::new(keys_hashes).root_hash());
    commitment.extend(MerkleTree::new(values_hashes).root_hash());
    commitment
}

/// Errors while answering Ledger delegated commands.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A request without a command byte.
    #[error("empty input")]
    EmptyInput,

    /// An unrecognized delegated command byte.
    #[error("unknown command: {0}")]
    UnknownCommand(
        /// Unrecognized delegated command byte.
        u8,
    ),

    /// A malformed or unsupported delegated request for a recognized command.
    #[error("unsupported request: {0}")]
    UnsupportedRequest(
        /// Recognized delegated command byte, such as `0x40` or `0x41`.
        u8,
    ),

    /// Invalid Merkle index, list size, or request size.
    #[error("invalid index or size")]
    InvalidIndexOrSize,

    /// A hash whose preimage is not registered.
    #[error("unknown hash")]
    UnknownHash,

    /// A Merkle root not registered in the store.
    #[error("unknown merkle root")]
    UnknownMerkleRoot,

    /// A queued fragment state incompatible with the request.
    #[error("unexpected queue state")]
    UnexpectedQueue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_merkle_leaf_returns_not_found() {
        let mut store = DelegatedStore::new();
        let root = store.add_known_list(&[b"known"]);
        let missing = sha256::Hash::hash(b"\0missing").to_byte_array();
        let mut command = vec![ClientCommandCode::GetMerkleLeafIndex as u8];
        command.extend(root);
        command.extend(missing);

        assert_eq!(store.execute(command).unwrap(), vec![0, 0]);
    }
}
