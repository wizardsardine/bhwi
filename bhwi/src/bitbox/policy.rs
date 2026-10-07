//! BitBox02 wallet policy templates and key origins.

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use miniscript::Terminal;
use miniscript::descriptor::{Descriptor, DescriptorPublicKey, ShInner, WalletPolicy, Wildcard};

use super::error::BitBoxError;
use super::proto as pb;

/// Resolved wallet policy, lowered to native sorted multisig or BIP-388 Miniscript.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Descriptor template containing indexed key placeholders and derivation suffixes.
    pub template: String,
    /// Extended keys indexed by the template's placeholders.
    pub pubkeys: Vec<KeyInfo>,
    multisig: Option<(u32, pb::btc_script_config::multisig::ScriptType)>,
}

/// An extended public key and its optional master-key origin.
#[derive(Clone, Debug)]
pub struct KeyInfo {
    /// Extended public key used by the policy.
    pub xpub: Xpub,
    /// Derivation path from the master key, or `None` when no origin was supplied.
    pub path: Option<DerivationPath>,
    /// Master fingerprint, or `None` when no origin was supplied.
    pub master_fingerprint: Option<Fingerprint>,
}
/// The account proven by an actual device xpub response, not just a fingerprint.
#[derive(Clone, Debug)]
pub(crate) struct OwnedAccount {
    pub fingerprint: Fingerprint,
    pub xpub: Xpub,
    pub path: DerivationPath,
}
impl OwnedAccount {
    pub fn address_path(&self, change: bool, index: u32) -> Result<DerivationPath, BitBoxError> {
        if index > 9999 {
            return Err(BitBoxError::InvalidInput(
                "unsupported multisig address index",
            ));
        }
        Ok(self.path.extend([
            ChildNumber::Normal {
                index: u32::from(change),
            },
            ChildNumber::Normal { index },
        ]))
    }

    pub fn validate_address_path(&self, path: &DerivationPath) -> Result<(), BitBoxError> {
        let suffix =
            path.as_ref()
                .strip_prefix(self.path.as_ref())
                .ok_or(BitBoxError::InvalidInput(
                    "address path does not match multisig account",
                ))?;
        if !matches!(
            suffix,
            [
                ChildNumber::Normal { index: 0 | 1 },
                ChildNumber::Normal { index: 0..=9999 }
            ]
        ) {
            return Err(BitBoxError::InvalidInput(
                "unsupported multisig address path",
            ));
        }
        Ok(())
    }
}

pub(crate) struct AccountResolver {
    fingerprint: Fingerprint,
    index: usize,
    matched: Option<usize>,
}

impl AccountResolver {
    pub fn new(
        policy: &Policy,
        fingerprint: Fingerprint,
        network: bitcoin::Network,
    ) -> Result<Self, BitBoxError> {
        if !policy.is_native_multisig()
            || policy
                .pubkeys
                .iter()
                .any(|key| key.xpub.network != network.into())
        {
            return Err(BitBoxError::InvalidInput(
                "multisig policy network mismatch",
            ));
        }
        let index = policy
            .pubkeys
            .iter()
            .position(|key| key.master_fingerprint == Some(fingerprint))
            .ok_or(BitBoxError::InvalidInput(
                "device key not found in multisig policy",
            ))?;
        Ok(Self {
            fingerprint,
            index,
            matched: None,
        })
    }

    pub fn current_key<'a>(&self, policy: &'a Policy) -> &'a KeyInfo {
        &policy.pubkeys[self.index]
    }

    /// Compare the complete network-bearing xpub and continue through every candidate.
    pub fn accept_xpub(&mut self, policy: &Policy, xpub: Xpub) -> Result<bool, BitBoxError> {
        if self.current_key(policy).xpub == xpub {
            if self.matched.is_some() {
                return Err(BitBoxError::InvalidInput(
                    "ambiguous device accounts in multisig policy",
                ));
            }
            self.matched = Some(self.index);
        }
        if let Some(next) = policy
            .pubkeys
            .iter()
            .enumerate()
            .skip(self.index + 1)
            .find(|(_, key)| key.master_fingerprint == Some(self.fingerprint))
            .map(|(index, _)| index)
        {
            self.index = next;
            Ok(false)
        } else {
            self.index = policy.pubkeys.len();
            Ok(true)
        }
    }

    pub fn finish(
        self,
        policy: Policy,
    ) -> Result<(pb::BtcScriptConfig, OwnedAccount), BitBoxError> {
        if self.index != policy.pubkeys.len() {
            return Err(BitBoxError::InvalidInput(
                "multisig ownership resolution incomplete",
            ));
        }
        let index = self.matched.ok_or(BitBoxError::InvalidInput(
            "device account xpub does not match multisig policy",
        ))?;
        let key = &policy.pubkeys[index];
        let account = OwnedAccount {
            fingerprint: self.fingerprint,
            xpub: key.xpub,
            path: key
                .path
                .clone()
                .ok_or(BitBoxError::InvalidInput("missing multisig origin"))?,
        };
        Ok((policy.into_script_config(Some(index))?, account))
    }
}

impl Policy {
    /// Preserve the descriptor and its key order; sortedmulti uses the firmware's BIP67 config.
    pub fn from_wallet_policy(policy: &WalletPolicy) -> Result<Policy, BitBoxError> {
        let descriptor = policy
            .clone()
            .into_descriptor()
            .map_err(|_| BitBoxError::InvalidInput("invalid wallet policy"))?;
        let native = match &descriptor {
            Descriptor::Wsh(wsh) => match &wsh.as_inner().node {
                Terminal::SortedMulti(threshold) => Some((
                    threshold,
                    pb::btc_script_config::multisig::ScriptType::P2wsh,
                )),
                _ => None,
            },
            Descriptor::Sh(sh) => match sh.as_inner() {
                ShInner::Wsh(wsh) => match &wsh.as_inner().node {
                    Terminal::SortedMulti(threshold) => Some((
                        threshold,
                        pb::btc_script_config::multisig::ScriptType::P2wshP2sh,
                    )),
                    _ => None,
                },
                ShInner::Ms(ms) if matches!(ms.node, Terminal::SortedMulti(_)) => {
                    return Err(BitBoxError::InvalidInput(
                        "legacy sorted multisig is unsupported",
                    ));
                }
                _ => None,
            },
            Descriptor::Bare(bare) if matches!(bare.as_inner().node, Terminal::SortedMulti(_)) => {
                return Err(BitBoxError::InvalidInput(
                    "bare sorted multisig is unsupported",
                ));
            }
            _ => None,
        };
        if let Some((threshold, script_type)) = native {
            if !(2..=15).contains(&threshold.n()) || !(1..=threshold.n()).contains(&threshold.k()) {
                return Err(BitBoxError::InvalidInput(
                    "invalid multisig threshold or key count",
                ));
            }
            let mut pubkeys: Vec<KeyInfo> = Vec::with_capacity(threshold.n());
            for key in threshold.data() {
                let DescriptorPublicKey::MultiXPub(key) = key else {
                    return Err(BitBoxError::InvalidInput(
                        "multisig requires origin-bearing account xpubs",
                    ));
                };
                let paths = key.derivation_paths.paths();
                if key.wildcard != Wildcard::Unhardened
                    || paths.len() != 2
                    || paths[0].as_ref() != [ChildNumber::Normal { index: 0 }]
                    || paths[1].as_ref() != [ChildNumber::Normal { index: 1 }]
                {
                    return Err(BitBoxError::InvalidInput(
                        "multisig requires exact /<0;1>/* derivation",
                    ));
                }
                let (fingerprint, path) = key
                    .origin
                    .as_ref()
                    .ok_or(BitBoxError::InvalidInput("missing multisig origin"))?;
                if path.as_ref().is_empty()
                    || path.len() != usize::from(key.xkey.depth)
                    || path.as_ref().last() != Some(&key.xkey.child_number)
                {
                    return Err(BitBoxError::InvalidInput(
                        "multisig origin does not match account xpub",
                    ));
                }
                if pubkeys.iter().any(|previous| {
                    let mut xpub = key.xkey;
                    xpub.network = previous.xpub.network;
                    previous.xpub == xpub
                }) {
                    return Err(BitBoxError::InvalidInput("duplicate multisig xpub"));
                }
                pubkeys.push(KeyInfo {
                    xpub: key.xkey,
                    path: Some(path.clone()),
                    master_fingerprint: Some(*fingerprint),
                });
            }
            return Ok(Policy {
                template: format!("{policy:#}"),
                pubkeys,
                multisig: Some((threshold.k() as u32, script_type)),
            });
        }
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
        Ok(Policy {
            template,
            pubkeys,
            multisig: None,
        })
    }

    pub(crate) fn is_native_multisig(&self) -> bool {
        self.multisig.is_some()
    }

    pub(crate) fn into_script_config(
        self,
        owned_index: Option<usize>,
    ) -> Result<pb::BtcScriptConfig, BitBoxError> {
        if let Some((threshold, script_type)) = self.multisig {
            let owned_index = owned_index
                .filter(|index| *index < self.pubkeys.len())
                .ok_or(BitBoxError::InvalidInput(
                    "unresolved multisig device account",
                ))?;
            return Ok(pb::BtcScriptConfig {
                config: Some(pb::btc_script_config::Config::Multisig(
                    pb::btc_script_config::Multisig {
                        threshold,
                        xpubs: self
                            .pubkeys
                            .iter()
                            .map(|key| convert_xpub(&key.xpub))
                            .collect(),
                        our_xpub_index: owned_index as u32,
                        script_type: script_type as i32,
                    },
                )),
            });
        }
        let keys: Vec<pb::KeyOriginInfo> = self
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
        Ok(pb::BtcScriptConfig {
            config: Some(pb::btc_script_config::Config::Policy(
                pb::btc_script_config::Policy {
                    policy: self.template,
                    keys,
                },
            )),
        })
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

    fn native_fixture(
        network: bitcoin::Network,
        wrapped: bool,
        owned_index: usize,
    ) -> (WalletPolicy, bitcoin::bip32::Xpriv) {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let root = bitcoin::bip32::Xpriv::new_master(network, &[1; 32]).unwrap();
        let foreign = bitcoin::bip32::Xpriv::new_master(network, &[2; 32]).unwrap();
        let coin = u32::from(network != bitcoin::Network::Bitcoin);
        let script = if wrapped { 1 } else { 2 };
        let paths: [DerivationPath; 2] = [
            format!("m/48'/{coin}'/0'/{script}'").parse().unwrap(),
            format!("m/48'/{coin}'/7'/{script}'").parse().unwrap(),
        ];
        let mut keys = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let seed = if index == owned_index {
                &root
            } else {
                &foreign
            };
            let xpub = Xpub::from_priv(&secp, &seed.derive_priv(&secp, path).unwrap());
            // Both origins deliberately claim the same fingerprint. Only the xpub proves ownership.
            keys.push(format!(
                "[{}/{path}]{xpub}/<0;1>/*",
                root.fingerprint(&secp)
            ));
        }
        let descriptor = format!("wsh(sortedmulti(2,{}))", keys.join(","));
        let descriptor = if wrapped {
            format!("sh({descriptor})")
        } else {
            descriptor
        };
        (WalletPolicy::from_str(&descriptor).unwrap(), root)
    }

    #[test]
    fn native_sorted_multisig_preserves_wrapper_order_and_resolves_full_account() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        for network in [bitcoin::Network::Bitcoin, bitcoin::Network::Testnet] {
            for wrapped in [false, true] {
                for owned_index in [0, 1] {
                    let (wallet, root) = native_fixture(network, wrapped, owned_index);
                    let policy = Policy::from_wallet_policy(&wallet).unwrap();
                    assert_eq!(policy.template, format!("{wallet:#}"));
                    assert!(policy.clone().into_script_config(None).is_err());
                    let expected_xpubs: Vec<_> = policy
                        .pubkeys
                        .iter()
                        .map(|key| convert_xpub(&key.xpub))
                        .collect();
                    let expected_path = policy.pubkeys[owned_index].path.clone().unwrap();
                    let mut resolver =
                        AccountResolver::new(&policy, root.fingerprint(&secp), network).unwrap();
                    loop {
                        let path = resolver.current_key(&policy).path.as_ref().unwrap();
                        let actual =
                            Xpub::from_priv(&secp, &root.derive_priv(&secp, path).unwrap());
                        if resolver.accept_xpub(&policy, actual).unwrap() {
                            break;
                        }
                    }
                    let (config, owned) = resolver.finish(policy).unwrap();
                    let Some(pb::btc_script_config::Config::Multisig(config)) = config.config
                    else {
                        panic!("not native multisig");
                    };
                    assert_eq!(config.threshold, 2);
                    assert_eq!(config.xpubs, expected_xpubs);
                    assert_eq!(config.our_xpub_index, owned_index as u32);
                    assert_eq!(config.script_type, if wrapped { 1 } else { 0 });
                    assert_eq!(owned.path, expected_path);
                    assert_eq!(
                        owned.xpub,
                        Xpub::from_priv(&secp, &root.derive_priv(&secp, &expected_path).unwrap())
                    );
                    assert_eq!(
                        owned.address_path(false, 0).unwrap(),
                        expected_path.extend([ChildNumber::Normal { index: 0 }; 2])
                    );
                    let change = expected_path.extend([
                        ChildNumber::Normal { index: 1 },
                        ChildNumber::Normal { index: 7 },
                    ]);
                    assert_eq!(owned.address_path(true, 7).unwrap(), change);
                    owned.validate_address_path(&change).unwrap();
                    assert!(owned.address_path(false, 1 << 31).is_err());
                    assert!(owned.address_path(false, 10000).is_err());
                    assert!(
                        owned
                            .validate_address_path(&expected_path.extend([
                                ChildNumber::Normal { index: 2 },
                                ChildNumber::Normal { index: 7 }
                            ]))
                            .is_err()
                    );
                    assert!(
                        owned
                            .validate_address_path(&expected_path.extend([
                                ChildNumber::Normal { index: 1 },
                                ChildNumber::Hardened { index: 7 }
                            ]))
                            .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn native_account_resolution_rejects_missing_ambiguous_and_mismatched_accounts() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (wallet, root) = native_fixture(bitcoin::Network::Testnet, false, 1);
        let policy = Policy::from_wallet_policy(&wallet).unwrap();
        let fp = root.fingerprint(&secp);
        assert!(
            AccountResolver::new(
                &policy,
                Fingerprint::from([0; 4]),
                bitcoin::Network::Testnet
            )
            .is_err()
        );
        assert!(AccountResolver::new(&policy, fp, bitcoin::Network::Bitcoin).is_err());
        let mut mixed = policy.clone();
        mixed.pubkeys[0].xpub.network = bitcoin::NetworkKind::Main;
        assert!(AccountResolver::new(&mixed, fp, bitcoin::Network::Testnet).is_err());
        assert!(
            AccountResolver::new(&policy, fp, bitcoin::Network::Testnet)
                .unwrap()
                .finish(policy.clone())
                .is_err()
        );
        let mut resolver = AccountResolver::new(&policy, fp, bitcoin::Network::Testnet).unwrap();
        let wrong = Xpub::from_priv(
            &secp,
            &bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[3; 32]).unwrap(),
        );
        assert!(!resolver.accept_xpub(&policy, wrong).unwrap());
        assert!(resolver.accept_xpub(&policy, wrong).unwrap());
        assert!(resolver.finish(policy.clone()).is_err());

        // A policy containing two genuinely owned accounts is not silently bound to the first.
        let mut ambiguous = policy.clone();
        for key in &mut ambiguous.pubkeys {
            key.xpub = Xpub::from_priv(
                &secp,
                &root.derive_priv(&secp, key.path.as_ref().unwrap()).unwrap(),
            );
        }
        let mut resolver = AccountResolver::new(&ambiguous, fp, bitcoin::Network::Testnet).unwrap();
        assert!(
            !resolver
                .accept_xpub(&ambiguous, ambiguous.pubkeys[0].xpub)
                .unwrap()
        );
        assert!(
            resolver
                .accept_xpub(&ambiguous, ambiguous.pubkeys[1].xpub)
                .is_err()
        );

        // Every serialized xpub field participates in ownership, including its network.
        let mut single_candidate = policy;
        single_candidate.pubkeys[0].master_fingerprint = Some(Fingerprint::from([0; 4]));
        let actual = single_candidate.pubkeys[1].xpub;
        let mut mismatches = [actual; 6];
        mismatches[0].network = bitcoin::NetworkKind::Main;
        mismatches[1].depth += 1;
        mismatches[2].parent_fingerprint = Fingerprint::from([0; 4]);
        mismatches[3].child_number = ChildNumber::Hardened { index: 3 };
        mismatches[4].chain_code = [0; 32].into();
        mismatches[5].public_key = wrong.public_key;
        for mismatch in mismatches {
            assert_ne!(mismatch, actual);
            let mut resolver =
                AccountResolver::new(&single_candidate, fp, bitcoin::Network::Testnet).unwrap();
            assert!(resolver.accept_xpub(&single_candidate, mismatch).unwrap());
            assert!(resolver.finish(single_candidate.clone()).is_err());
        }
    }

    #[test]
    fn native_sorted_multisig_rejects_unsupported_key_forms_without_rewriting() {
        let (wallet, _) = native_fixture(bitcoin::Network::Testnet, false, 0);
        let descriptor = wallet.into_descriptor().unwrap().to_string();
        let rejected = |descriptor: String| {
            let accepted = WalletPolicy::from_str(&descriptor)
                .ok()
                .and_then(|wallet| Policy::from_wallet_policy(&wallet).ok());
            assert!(accepted.is_none(), "unexpectedly accepted {descriptor}");
        };
        // Strip the checksum before changing any descriptor expression.
        let descriptor = descriptor.split('#').next().unwrap();
        for suffix in [
            "/<1;0>/*",
            "/<0;2>/*",
            "/0/<0;1>/*",
            "/<0;1>/*'",
            "/<0';1'>/*",
            "/0/*",
            "/<0;1>/0",
        ] {
            rejected(descriptor.replace("/<0;1>/*", suffix));
        }
        rejected(descriptor.replacen("wsh(", "sh(", 1));
        let policy = policy_from(descriptor);
        let key = &policy.pubkeys[0];
        let xpub = key.xpub;
        let fp = key.master_fingerprint.unwrap();
        let path = key.path.as_ref().unwrap();
        rejected(descriptor.replace("sortedmulti(2,", "sortedmulti(0,"));
        rejected(descriptor.replace("sortedmulti(2,", "sortedmulti(3,"));
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let keys: Vec<_> = (1..=16)
            .map(|seed| {
                let root =
                    bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[seed; 32])
                        .unwrap();
                let xpub = Xpub::from_priv(&secp, &root.derive_priv(&secp, path).unwrap());
                format!("[{}/{path}]{xpub}/<0;1>/*", root.fingerprint(&secp))
            })
            .collect();
        rejected(format!("wsh(sortedmulti(2,{}))", keys.join(",")));
        rejected(format!(
            "wsh(sortedmulti(2,[{fp}/{path}]{xpub}/<0;1>/*,[00000000/{path}]{xpub}/<0;1>/*))"
        ));
        rejected(format!("wsh(sortedmulti(1,[{fp}/{path}]{xpub}/<0;1>/*))"));
        rejected(format!("wsh(sortedmulti(2,{xpub}/<0;1>/*,{xpub}/<0;1>/*))"));
        rejected(format!(
            "wsh(sortedmulti(2,[{fp}/48'/1'/0']{xpub}/<0;1>/*,[00000000/{path}]{xpub}/<0;1>/*))"
        ));
        let uncompressed = bitcoin::PublicKey::new_uncompressed(xpub.public_key);
        rejected(format!("wsh(sortedmulti(1,{uncompressed},{uncompressed}))"));
    }
}
