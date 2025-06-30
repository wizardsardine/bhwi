pub mod request {
    use bitcoin::bip32::DerivationPath;

    pub fn start_encryption(version: Option<u32>, key: &[u8; 64]) -> Vec<u8> {
        let mut data = "ncry".as_bytes().to_owned();
        data.extend(version.unwrap_or(1).to_le_bytes());
        data.extend(key);
        data
    }

    pub fn get_xpub(path: &DerivationPath) -> Vec<u8> {
        if path.is_master() {
            "xpubm".as_bytes().to_vec()
        } else {
            format!("xpubm/{}", path).as_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::DerivationPath;

    #[test]
    fn test_derivation_path() {
        let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
        assert_eq!("48'/1'/0'/2'", path.to_string());
    }
}

pub mod response {
    use std::str::FromStr;

    use crate::coldcard::{ColdcardError, ColdcardResponse};
    use bitcoin::bip32::Xpub;
    pub fn xpub(res: Vec<u8>) -> Result<Xpub, ColdcardError> {
        let (command, data) = split(&res, 4)?;
        if command == b"asci" {
            let s = std::str::from_utf8(data)
                .map_err(|e| ColdcardError::Serialization(e.to_string()))?;
            Xpub::from_str(s).map_err(|e| ColdcardError::Serialization(e.to_string()))
        } else {
            Err(ColdcardError::Serialization(format!(
                "command: {:?}, data: {}",
                String::from_utf8(command.to_vec()).unwrap_or_else(|_| format!("{:?}", command)),
                String::from_utf8(data.to_vec()).unwrap_or_else(|_| format!("{:?}", data))
            )))
        }
    }

    pub fn mypub(res: Vec<u8>) -> Result<ColdcardResponse, ColdcardError> {
        let (command, data) = split(&res, 4)?;
        if command == b"mypb" {
            let (dev_pubkey, data) = split(data, 64)?;
            let encryption_key = dev_pubkey
                .try_into()
                .map_err(|_| ColdcardError::Serialization("encryption_key".to_string()))?;
            let xpub_fingerprint = data
                .get(0..4)
                .ok_or(ColdcardError::Serialization(
                    "xfp wants 4 bytes".to_string(),
                ))?
                .try_into()
                .expect("infallible");
            let xpub_len = decode_u32(data.get(4..8))? as usize;
            let xpub = if xpub_len > 0 {
                if let Some(s) = data
                    .get(8..8 + xpub_len)
                    .map(|d| String::from_utf8(d.to_owned()))
                    .transpose()
                    .map_err(|e| ColdcardError::Serialization(e.to_string()))?
                {
                    Some(
                        Xpub::from_str(&s)
                            .map_err(|e| ColdcardError::Serialization(e.to_string()))?,
                    )
                } else {
                    None
                }
            } else {
                None
            };
            Ok(ColdcardResponse::MyPub {
                encryption_key,
                xpub_fingerprint,
                xpub,
            })
        } else {
            Err(ColdcardError::Serialization(
                "Wrong xpub response".to_string(),
            ))
        }
    }

    /// Safely splits a slice at `mid`. Returns an error if `bytes.len() < mid`.
    fn split(bytes: &[u8], mid: usize) -> Result<(&[u8], &[u8]), ColdcardError> {
        match bytes.len().cmp(&mid) {
            std::cmp::Ordering::Less => Err(ColdcardError::Serialization(
                "unexpected slice length".to_string(),
            )),
            _ => Ok(bytes.split_at(mid)),
        }
    }

    /// Safely decodes a possible 4 byte slice into an `u32`.
    fn decode_u32(bytes: Option<&[u8]>) -> Result<u32, ColdcardError> {
        match bytes {
            Some(bytes) if bytes.len() == 4 => {
                Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
                    ColdcardError::Serialization("u32".to_string())
                })?))
            }
            _ => Err(ColdcardError::Serialization("u32".to_string())),
        }
    }
}
