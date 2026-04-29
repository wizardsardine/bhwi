// See https://github.com/Coldcard/ckcc-protocol for implementation details.
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

    /// Address format bitmask constants (from ckcc-protocol)
    pub mod addr_fmt {
        pub const AFC_PUBKEY: u32 = 0x01;
        pub const AFC_SEGWIT: u32 = 0x02;
        pub const AFC_BECH32: u32 = 0x04;
        pub const AFC_SCRIPT: u32 = 0x08;
        pub const AFC_WRAPPED: u32 = 0x10;
        pub const AFC_BECH32M: u32 = 0x20;

        pub const AF_P2PKH: u32 = AFC_PUBKEY;
        pub const AF_P2WPKH: u32 = AFC_PUBKEY | AFC_SEGWIT | AFC_BECH32;
        pub const AF_P2WPKH_P2SH: u32 = AFC_PUBKEY | AFC_SEGWIT | AFC_WRAPPED;
        pub const AF_P2TR: u32 = AFC_PUBKEY | AFC_SEGWIT | AFC_BECH32M;
        pub const AF_P2SH: u32 = AFC_SCRIPT;
        pub const AF_P2WSH: u32 = AFC_SCRIPT | AFC_SEGWIT | AFC_BECH32;
        pub const AF_P2WSH_P2SH: u32 = AFC_SCRIPT | AFC_SEGWIT | AFC_WRAPPED;

        pub fn from_address_type(addr_type: bitcoin::address::AddressType) -> u32 {
            match addr_type {
                bitcoin::address::AddressType::P2pkh => AF_P2PKH,
                bitcoin::address::AddressType::P2sh => AF_P2SH,
                bitcoin::address::AddressType::P2wpkh => AF_P2WPKH,
                bitcoin::address::AddressType::P2wsh => AF_P2WSH,
                bitcoin::address::AddressType::P2tr => AF_P2TR,
                _ => AF_P2WPKH,
            }
        }
    }

    pub fn show_address(path: &DerivationPath, addr_fmt: u32) -> Vec<u8> {
        let mut data = b"show".to_vec();
        data.extend(addr_fmt.to_le_bytes());
        data.extend(path.to_string().as_bytes());
        data
    }

    pub fn miniscript_address(name: &str, change: bool, index: u32) -> Vec<u8> {
        let mut data = b"msas".to_vec();
        data.extend((change as u32).to_le_bytes());
        data.extend(index.to_le_bytes());
        data.extend(name.as_bytes());
        data
    }

    pub fn sign_message(message: &[u8], path: &DerivationPath) -> Vec<u8> {
        let mut data = b"smsg".to_vec();
        // coldcard can support a few different address types:
        // https://github.com/Coldcard/ckcc-protocol/blob/0bd92d4d6d01872e41ffc1e7d9a1e2f153130061/ckcc/constants.py#L75-L90
        data.extend((0x01u32 | 0x02 | 0x04).to_le_bytes()); // hardcoding to P2WPKH
        let path_string = path.to_string();
        data.extend((path_string.len() as u32).to_le_bytes());
        data.extend((message.len() as u32).to_le_bytes());
        data.extend(path_string.as_bytes());
        data.extend_from_slice(message);
        data
    }

    pub fn get_signed_message() -> Vec<u8> {
        b"smok".to_vec()
    }

    pub fn get_version() -> Vec<u8> {
        b"vers".to_vec()
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
    use std::fmt::Display;
    use std::str::FromStr;

    use bitcoin::bip32::Xpub;
    use bitcoin::secp256k1::ecdsa::Signature;

    use crate::coldcard::{ColdcardError, ColdcardResponse};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResponseMessage {
        /// No content, successful response
        Okay,
        /// Frame error
        Fram,
        /// Device error
        Err_,
        /// User refused to approve
        Refu,
        /// User didn't approve something yet
        Busy,
        /// Binary string response
        Biny,
        /// u32
        Int1,
        /// 2 u32's
        Int2,
        /// 3 u32's
        Int3,
        /// Response to "ncry"
        /// response to "ncry" command:
        /// - the (uncompressed) pubkey of the Coldcard
        /// - info about master key: xpub, fingerprint of that
        /// - anti-MitM: remote xpub
        ///   session key is SHA256(point on sec256pk1 in binary) via D-H
        MyPb,
        /// Hex or Base58 ascii string
        Asci,
        /// Message signing result
        Smrx,
        /// Transaction signing result
        Strx,
    }

    struct ResponseHandler<'a> {
        message: ResponseMessage,
        data: &'a [u8],
    }

    impl<'a> ResponseHandler<'a> {
        /// Parse a response message and data from the raw device response
        fn parse_response(res: &[u8]) -> Result<(ResponseMessage, &[u8]), ColdcardError> {
            ResponseHandler::try_from(res).map(|ResponseHandler { message, data }| (message, data))
        }

        /// Parse data from the raw device response given an expected response
        /// message.
        fn expect_response(res: &[u8], expected: ResponseMessage) -> Result<&[u8], ColdcardError> {
            ResponseHandler::parse_response(res).and_then(|(msg, data)| {
                if expected == msg {
                    Ok(data)
                } else {
                    Err(ColdcardError::unexpected_response_message(msg, &[expected]))
                }
            })
        }
    }

    impl Display for ResponseMessage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let response_str = match self {
                ResponseMessage::Okay => "okay",
                ResponseMessage::Fram => "fram",
                ResponseMessage::Err_ => "err_",
                ResponseMessage::Refu => "refu",
                ResponseMessage::Busy => "busy",
                ResponseMessage::Biny => "biny",
                ResponseMessage::Int1 => "int1",
                ResponseMessage::Int2 => "int2",
                ResponseMessage::Int3 => "int3",
                ResponseMessage::MyPb => "mypb",
                ResponseMessage::Asci => "asci",
                ResponseMessage::Smrx => "smrx",
                ResponseMessage::Strx => "strx",
            };

            write!(f, "{}", response_str)
        }
    }

    impl<'a> TryFrom<&'a [u8]> for ResponseHandler<'a> {
        type Error = ColdcardError;

        fn try_from(res: &'a [u8]) -> Result<Self, Self::Error> {
            let (msg, data) = split(res, 4)?;
            let message = match msg {
                b"okay" => ResponseMessage::Okay,
                b"fram" => ResponseMessage::Fram,
                b"err_" => ResponseMessage::Err_,
                b"refu" => ResponseMessage::Refu,
                b"busy" => ResponseMessage::Busy,
                b"biny" => ResponseMessage::Biny,
                b"int1" => ResponseMessage::Int1,
                b"int2" => ResponseMessage::Int2,
                b"int3" => ResponseMessage::Int3,
                b"mypb" => ResponseMessage::MyPb,
                b"asci" => ResponseMessage::Asci,
                b"smrx" => ResponseMessage::Smrx,
                b"strx" => ResponseMessage::Strx,
                _ => {
                    return Err(ColdcardError::Serialization(format!(
                        "unknown device response message: {:?}, data: {}",
                        String::from_utf8_lossy(msg),
                        String::from_utf8_lossy(data),
                    )));
                }
            };
            Ok(ResponseHandler { message, data })
        }
    }

    fn xpub(res: &[u8]) -> Result<Xpub, ColdcardError> {
        let data = ResponseHandler::expect_response(res, ResponseMessage::Asci)?;
        let s =
            std::str::from_utf8(data).map_err(|e| ColdcardError::Serialization(e.to_string()))?;
        Xpub::from_str(s).map_err(|e| ColdcardError::Serialization(e.to_string()))
    }

    pub fn show_address(res: &[u8]) -> Result<ColdcardResponse, ColdcardError> {
        match ResponseHandler::parse_response(res)? {
            (ResponseMessage::Asci, data) => {
                let address = String::from_utf8(data.to_owned())?;
                Ok(ColdcardResponse::Address(address))
            }
            (ResponseMessage::Refu, _) => Ok(ColdcardResponse::Ok),
            (msg, _) => Err(ColdcardError::unexpected_response_message(
                msg,
                &[ResponseMessage::Asci, ResponseMessage::Refu],
            )),
        }
    }

    pub fn miniscript_address(res: &[u8]) -> Result<ColdcardResponse, ColdcardError> {
        match ResponseHandler::parse_response(res)? {
            (ResponseMessage::Asci, data) => {
                let address = String::from_utf8(data.to_owned())?;
                Ok(ColdcardResponse::Address(address))
            }
            (ResponseMessage::Refu, _) => Ok(ColdcardResponse::Ok),
            (msg, _) => Err(ColdcardError::unexpected_response_message(
                msg,
                &[ResponseMessage::Asci, ResponseMessage::Refu],
            )),
        }
    }

    pub fn master_fingerprint(res: &[u8]) -> Result<ColdcardResponse, ColdcardError> {
        Ok(ColdcardResponse::MasterFingerprint(
            xpub(res)?.fingerprint(),
        ))
    }

    pub fn get_xpub(res: &[u8]) -> Result<ColdcardResponse, ColdcardError> {
        Ok(ColdcardResponse::Xpub(xpub(res)?))
    }

    pub fn version(res: &[u8]) -> Result<ColdcardResponse, ColdcardError> {
        let data = ResponseHandler::expect_response(res, ResponseMessage::Asci)?;
        let version_string =
            std::str::from_utf8(data).map_err(|e| ColdcardError::Serialization(e.to_string()))?;
        let lines = version_string.lines().collect::<Vec<&str>>();
        let version = lines.get(1).unwrap_or(&version_string).to_string();
        let device_model = lines.last().cloned().unwrap_or_default().to_string();
        Ok(ColdcardResponse::Version {
            version,
            device_model,
        })
    }

    pub fn mypub(res: &[u8]) -> Result<ColdcardResponse, ColdcardError> {
        let data = ResponseHandler::expect_response(res, ResponseMessage::MyPb)?;
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
                Some(Xpub::from_str(&s).map_err(|e| ColdcardError::Serialization(e.to_string()))?)
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
    }

    pub fn sign_message(res: &[u8]) -> Result<ColdcardResponse, ColdcardError> {
        match ResponseHandler::parse_response(res)? {
            (ResponseMessage::Okay, _) => Ok(ColdcardResponse::Ok),
            (ResponseMessage::Smrx, data) => {
                let addr_len = u32::from_le_bytes(data[..4].try_into().map_err(|_| {
                    ColdcardError::Serialization("couldn't parse address length into u32".into())
                })?);
                let (_addr, sig_bytes) = split(
                    &data[4..],
                    addr_len.try_into().map_err(|_| {
                        ColdcardError::Serialization("address length can't fit into usize".into())
                    })?,
                )?;
                let sig = Signature::from_compact(&sig_bytes[1..])
                    .map_err(|e| ColdcardError::Serialization(e.to_string()))?;
                Ok(ColdcardResponse::Signature(sig_bytes[0], sig))
            }
            (ResponseMessage::Busy, _) => Ok(ColdcardResponse::Busy),
            (msg, _) => Err(ColdcardError::unexpected_response_message(
                msg,
                &[
                    ResponseMessage::Okay,
                    ResponseMessage::Busy,
                    ResponseMessage::Smrx,
                ],
            )),
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
