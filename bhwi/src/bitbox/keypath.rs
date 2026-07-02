// Ported from bitbox-api-rs (`src/keypath.rs`),
// Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
// Version 2.0 — see BITBOX_LICENSE at the repository root.

use super::error::BitBoxError;

pub const HARDENED: u32 = 0x80000000;

#[derive(Debug, Clone, PartialEq)]
pub struct Keypath(Vec<u32>);

impl Keypath {
    pub fn to_vec(&self) -> Vec<u32> {
        self.0.clone()
    }

    #[allow(dead_code)]
    pub(crate) fn hardened_prefix(&self) -> Keypath {
        Keypath(
            self.0
                .iter()
                .cloned()
                .take_while(|&el| el >= HARDENED)
                .collect(),
        )
    }
}

fn parse_bip32_keypath(keypath: &str) -> Option<Vec<u32>> {
    let keypath = keypath.strip_prefix("m/")?;
    if keypath.is_empty() {
        return Some(vec![]);
    }
    let parts: Vec<&str> = keypath.split('/').collect();
    let mut res = Vec::new();

    for part in parts {
        let mut add_prime = 0;
        let number = if part.ends_with('\'') {
            add_prime = HARDENED;
            part[0..part.len() - 1].parse::<u32>()
        } else {
            part.parse::<u32>()
        };

        match number {
            Ok(n) if n < HARDENED => {
                res.push(n + add_prime);
            }
            _ => return None,
        }
    }

    Some(res)
}

impl TryFrom<&str> for Keypath {
    type Error = BitBoxError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Keypath(
            parse_bip32_keypath(value).ok_or_else(|| BitBoxError::KeypathParse(value.into()))?,
        ))
    }
}

impl From<&bitcoin::bip32::DerivationPath> for Keypath {
    fn from(value: &bitcoin::bip32::DerivationPath) -> Self {
        Keypath(value.to_u32_vec())
    }
}

impl From<&Keypath> for super::proto::Keypath {
    fn from(value: &Keypath) -> Self {
        super::proto::Keypath {
            keypath: value.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bip32_keypath() {
        assert_eq!(parse_bip32_keypath("m/44/0/0/0"), Some(vec![44, 0, 0, 0]));
        assert_eq!(
            parse_bip32_keypath("m/44'/0'/0'/0'"),
            Some(vec![HARDENED + 44, HARDENED, HARDENED, HARDENED])
        );
        assert_eq!(parse_bip32_keypath("m/"), Some(vec![]));
        assert_eq!(parse_bip32_keypath("m/2147483648/0/0"), None);
        assert_eq!(parse_bip32_keypath("m/abcd/0/0"), None);
    }

    #[test]
    fn test_from_derivation_path() {
        let derivation_path: bitcoin::bip32::DerivationPath =
            std::str::FromStr::from_str("m/84'/0'/0'/0/1").unwrap();
        let keypath = Keypath::from(&derivation_path);
        assert_eq!(
            keypath.to_vec().as_slice(),
            &[84 + HARDENED, HARDENED, HARDENED, 0, 1]
        );
    }
}
