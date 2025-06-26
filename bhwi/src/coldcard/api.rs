pub mod request {
    use bitcoin::bip32::DerivationPath;

    pub fn get_xpub(path: &DerivationPath) -> Vec<u8> {
        format!("xpub{}", path).as_bytes().to_vec()
    }
}

pub mod response {
    use std::str::FromStr;

    use crate::coldcard::ColdcardError;
    use bitcoin::bip32::Xpub;
    pub fn xpub(res: Vec<u8>) -> Result<Xpub, ColdcardError> {
        let s = String::from_utf8(res).map_err(|e| ColdcardError::Serialization(e.to_string()))?;
        if s.starts_with("asci") && s.len() > 4 {
            Xpub::from_str(&s[4..]).map_err(|e| ColdcardError::Serialization(e.to_string()))
        } else {
            Err(ColdcardError::Serialization(
                "Wrong xpub response".to_string(),
            ))
        }
    }
}
