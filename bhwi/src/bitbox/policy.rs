use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use regex::Regex;

use super::error::BitBoxError;
use super::keypath::Keypath;
use super::proto as pb;

/// Miniscript wallet policy, in the BIP-388 sense (template + resolved keys).
#[derive(Clone, Debug)]
pub struct Policy {
    pub template: String,
    pub pubkeys: Vec<KeyInfo>,
}

#[derive(Clone, Debug)]
pub struct KeyInfo {
    pub xpub: Xpub,
    pub path: Option<DerivationPath>,
    pub master_fingerprint: Option<Fingerprint>,
}

impl From<Policy> for pb::BtcScriptConfig {
    fn from(p: Policy) -> pb::BtcScriptConfig {
        let keys: Vec<pb::KeyOriginInfo> = p
            .pubkeys
            .into_iter()
            .map(|k| pb::KeyOriginInfo {
                root_fingerprint: k
                    .master_fingerprint
                    .map_or(vec![], |fp| fp.as_bytes().to_vec()),
                keypath: k
                    .path
                    .as_ref()
                    .map(|p| Keypath::from(p).to_vec())
                    .unwrap_or_default(),
                xpub: Some(convert_xpub(&k.xpub)),
            })
            .collect();
        pb::BtcScriptConfig {
            config: Some(pb::btc_script_config::Config::Policy(
                pb::btc_script_config::Policy {
                    policy: p.template,
                    keys,
                },
            )),
        }
    }
}

pub(crate) fn convert_xpub(xpub: &Xpub) -> pb::XPub {
    pb::XPub {
        depth: vec![xpub.depth],
        parent_fingerprint: xpub.parent_fingerprint[..].to_vec(),
        child_num: xpub.child_number.into(),
        chain_code: xpub.chain_code[..].to_vec(),
        public_key: xpub.public_key.serialize().to_vec(),
    }
}

/// Parse a miniscript-style descriptor into a `Policy` (template with `@i` placeholders + keys).
///
/// Ported from async-hwi's `extract_script_config_policy` — regex-based to avoid pulling in the
/// full miniscript parser for this narrow use.
pub fn extract_script_config_policy(policy: &str) -> Result<Policy, BitBoxError> {
    let re = Regex::new(r"((\[.+?\])?[xyYzZtuUvV]pub[1-9A-HJ-NP-Za-km-z]{79,108})")
        .expect("static regex");
    let mut descriptor_template = policy.to_string();
    let mut pubkeys_str: Vec<&str> = Vec::new();
    for capture in re.find_iter(policy) {
        if !pubkeys_str.contains(&capture.as_str()) {
            pubkeys_str.push(capture.as_str());
        }
    }

    let mut pubkeys: Vec<KeyInfo> = Vec::new();
    for (i, key_str) in pubkeys_str.iter().enumerate() {
        descriptor_template = descriptor_template.replace(key_str, &format!("@{i}"));
        let pubkey = if let Ok(key) = Xpub::from_str(key_str) {
            KeyInfo {
                path: None,
                master_fingerprint: None,
                xpub: key,
            }
        } else {
            let (keysource_str, xpub_str) = key_str
                .strip_prefix('[')
                .and_then(|s| s.rsplit_once(']'))
                .ok_or(BitBoxError::InvalidInput("invalid key source in policy"))?;
            let (f_str, path_str) = keysource_str.split_once('/').unwrap_or((keysource_str, ""));
            let fingerprint = Fingerprint::from_str(f_str)
                .map_err(|_| BitBoxError::InvalidInput("invalid fingerprint in policy"))?;
            let derivation_path = if path_str.is_empty() {
                DerivationPath::master()
            } else {
                DerivationPath::from_str(&format!("m/{path_str}"))
                    .map_err(|_| BitBoxError::InvalidInput("invalid derivation path in policy"))?
            };
            KeyInfo {
                xpub: Xpub::from_str(xpub_str)
                    .map_err(|_| BitBoxError::InvalidInput("invalid xpub in policy"))?,
                path: Some(derivation_path),
                master_fingerprint: Some(fingerprint),
            }
        };
        pubkeys.push(pubkey);
    }
    // Strip the descriptor checksum, if present.
    let descriptor_template =
        if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once('#') {
            descriptor_template
        } else {
            &descriptor_template
        };

    // The BitBox02 policy grammar uses the `/**` receive/change shorthand; normalize the
    // equivalent `/<0;1>/*` form (what miniscript emits) so registration and address display
    // produce the same template the device expects.
    let template = descriptor_template.replace("/<0;1>/*", "/**");

    Ok(Policy { template, pubkeys })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_script_config_policy() {
        let policy = extract_script_config_policy("wsh(or_d(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/**),and_v(v:pkh(tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/**),older(100))))").unwrap();
        assert_eq!(2, policy.pubkeys.len());
        assert_eq!(
            "wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(100))))",
            policy.template
        );
    }

    #[test]
    fn test_extract_strips_checksum() {
        let policy = extract_script_config_policy("wsh(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/**))#abcdef").unwrap();
        assert!(!policy.template.contains('#'));
        assert_eq!(1, policy.pubkeys.len());
    }

    #[test]
    fn test_extract_normalizes_multipath() {
        // miniscript's `into_descriptor()` emits the `/<0;1>/*` form; the BitBox template
        // grammar wants the `/**` shorthand.
        let policy = extract_script_config_policy("wsh(andor(pk([f5acc2fd/48'/1'/0'/2']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*),older(12960),pk(tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*)))#gqf2ey6r").unwrap();
        assert_eq!(2, policy.pubkeys.len());
        assert_eq!(
            "wsh(andor(pk(@0/**),older(12960),pk(@1/**)))",
            policy.template
        );
    }
}
