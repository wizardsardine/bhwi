use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use miniscript::descriptor::WalletPolicy;

use super::error::BitBoxError;
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

impl Policy {
    /// Build a BitBox policy from a miniscript `WalletPolicy`, resolving each `@i` placeholder
    /// to its key origin. The template is the BIP-388 `@i/**` form the device expects.
    pub fn from_wallet_policy(policy: &WalletPolicy) -> Result<Policy, BitBoxError> {
        let (template, keys) = crate::policy::extract_parts(policy)
            .map_err(|_| BitBoxError::InvalidInput("invalid wallet policy"))?;
        let pubkeys = keys
            .iter()
            .map(|key| {
                let (master_fingerprint, path, xpub) = crate::policy::xpub_origin(key)
                    .ok_or(BitBoxError::InvalidInput("policy key is not an xpub"))?;
                Ok(KeyInfo {
                    xpub,
                    path,
                    master_fingerprint,
                })
            })
            .collect::<Result<Vec<_>, BitBoxError>>()?;
        Ok(Policy { template, pubkeys })
    }
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
                keypath: k.path.as_ref().map(|p| p.to_u32_vec()).unwrap_or_default(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn policy_from(descriptor: &str) -> Policy {
        let wp = WalletPolicy::from_str(descriptor).unwrap();
        Policy::from_wallet_policy(&wp).unwrap()
    }

    #[test]
    fn from_wallet_policy_extracts_template_and_origins() {
        let policy = policy_from(
            "wsh(or_d(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*),and_v(v:pkh([00000000/49'/1'/0']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/<0;1>/*),older(100))))",
        );
        assert_eq!(2, policy.pubkeys.len());
        // `{:#}` yields the `@i/**` form the device expects; no checksum, no `/<0;1>/*`.
        assert_eq!(
            "wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(100))))",
            policy.template
        );
        assert_eq!(
            policy.pubkeys[0].master_fingerprint,
            Some(Fingerprint::from_str("f5acc2fd").unwrap())
        );
        assert_eq!(
            policy.pubkeys[0].path,
            Some(DerivationPath::from_str("m/49'/1'/0'").unwrap())
        );
    }

    #[test]
    fn from_wallet_policy_strips_checksum() {
        let policy = policy_from(
            "wsh(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*))#8afpcrke",
        );
        assert!(!policy.template.contains('#'));
        assert_eq!(1, policy.pubkeys.len());
    }

    #[test]
    fn from_wallet_policy_bare_xpub_has_no_origin() {
        let policy = policy_from(
            "wsh(pk(tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*))",
        );
        assert_eq!(1, policy.pubkeys.len());
        assert_eq!(policy.pubkeys[0].master_fingerprint, None);
        assert_eq!(policy.pubkeys[0].path, None);
    }
}
