//! Shared wallet-policy extraction, used by both the Ledger and BitBox backends.
//!
//! Both backends need the same two things from a BIP-388 `WalletPolicy`: the template string
//! (with `@i` placeholders) and the ordered list of per-placeholder keys with their origins.
//! This module centralizes that extraction so the backends don't each re-derive it.

use core::fmt::Display;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use miniscript::descriptor::{DescriptorPublicKey, WalletPolicy, WalletPolicyError};

/// Extract the BIP-388 template and the ordered per-placeholder keys from a wallet policy.
///
/// The returned keys are index-aligned with the template's `@i` placeholders: miniscript's
/// `WalletPolicy` validation guarantees placeholders are consecutive and in order, and
/// `into_descriptor` substitutes them in that order, so `iter_pk()` yields the keys in `@i`
/// order. A placeholder reused with disjoint multipaths appears twice in `iter_pk()`; such
/// consecutive duplicates are collapsed to a single entry so the result has one key per `@i`.
pub fn extract_parts(
    policy: &WalletPolicy,
) -> Result<(String, Vec<DescriptorPublicKey>), WalletPolicyError> {
    let template = format!("{policy:#}");
    let descriptor = policy.clone().into_descriptor()?;
    let mut keys: Vec<DescriptorPublicKey> = Vec::new();
    for key in descriptor.iter_pk() {
        if keys.last().map(format_key_info) != Some(format_key_info(&key)) {
            keys.push(key);
        }
    }
    Ok((template, keys))
}

/// Format a key as a BIP-388 KEY_INFO string (`[origin]xkey`), dropping the derivation-path
/// suffix and wildcard that `Display` would append. This is the form the Ledger merkle tree
/// hashes keys in.
pub fn format_key_info(key: &DescriptorPublicKey) -> String {
    match key {
        DescriptorPublicKey::Single(_) => key.to_string(),
        DescriptorPublicKey::XPub(xpub) => format_origin_xkey(&xpub.origin, &xpub.xkey),
        DescriptorPublicKey::MultiXPub(xpub) => format_origin_xkey(&xpub.origin, &xpub.xkey),
    }
}

fn format_origin_xkey<K: Display>(
    origin: &Option<(Fingerprint, DerivationPath)>,
    xkey: &K,
) -> String {
    match origin {
        Some((fp, path)) if !path.as_ref().is_empty() => format!("[{fp}/{path}]{xkey}"),
        Some((fp, _)) => format!("[{fp}]{xkey}"),
        None => xkey.to_string(),
    }
}

/// Split an xpub key into its origin fingerprint, origin path, and the xpub itself.
///
/// Returns `None` for a single (non-extended) key, which the xpub-based device policies do not
/// use. The origin fingerprint and path are `None` for a bare xpub with no `[origin]` prefix.
pub fn xpub_origin(
    key: &DescriptorPublicKey,
) -> Option<(Option<Fingerprint>, Option<DerivationPath>, Xpub)> {
    let (origin, xkey) = match key {
        DescriptorPublicKey::XPub(x) => (&x.origin, x.xkey),
        DescriptorPublicKey::MultiXPub(x) => (&x.origin, x.xkey),
        DescriptorPublicKey::Single(_) => return None,
    };
    let fingerprint = origin.as_ref().map(|(fp, _)| *fp);
    let path = origin.as_ref().map(|(_, path)| path.clone());
    Some((fingerprint, path, xkey))
}
