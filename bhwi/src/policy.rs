//! Shared extraction of BIP-388 wallet-policy templates and keys.
//!
//! Ledger and BitBox use the template's `@i` placeholders and the ordered keys
//! with their origins.

use core::fmt::Display;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use miniscript::descriptor::{DescriptorPublicKey, WalletPolicy, WalletPolicyError};

/// Extracts the BIP-388 template and ordered per-placeholder keys from a wallet policy.
///
/// The returned keys are index-aligned with the template's `@i` placeholders. Miniscript's
/// `WalletPolicy` assigns a distinct placeholder to each unique key expression (key info plus
/// derivation), while BIP-388 numbers placeholders by key info alone, reusing the same `@i`
/// for a key that appears with several multipath derivations. Keys are deduplicated by key
/// info in first-occurrence order and the template placeholders are renumbered to match:
/// `Display` renders placeholders left to right in the same order `iter_pk()` yields keys, so
/// the n-th `@i` token corresponds to the n-th key occurrence.
///
/// # Errors
///
/// Returns an error if the policy cannot be converted to a descriptor or the
/// template's placeholder occurrences do not match its keys.
pub fn extract_parts(
    policy: &WalletPolicy,
) -> Result<(String, Vec<DescriptorPublicKey>), WalletPolicyError> {
    let template = format!("{policy:#}");
    let descriptor = policy.clone().into_descriptor()?;
    let mut keys: Vec<DescriptorPublicKey> = Vec::new();
    let mut indices = Vec::new();
    for key in descriptor.iter_pk() {
        let info = format_key_info(&key);
        let index = keys
            .iter()
            .position(|k| format_key_info(k) == info)
            .unwrap_or_else(|| {
                keys.push(key);
                keys.len() - 1
            });
        indices.push(index);
    }

    let mut renumbered = String::with_capacity(template.len());
    let mut occurrences = indices.iter();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '@' {
            renumbered.push(c);
            continue;
        }
        while chars.peek().is_some_and(char::is_ascii_digit) {
            chars.next();
        }
        let index = occurrences
            .next()
            .ok_or(WalletPolicyError::WalletPolicyInvalidKeyInfo)?;
        renumbered.push('@');
        renumbered.push_str(&index.to_string());
    }
    if occurrences.next().is_some() {
        return Err(WalletPolicyError::WalletPolicyInvalidKeyInfo);
    }
    Ok((renumbered, keys))
}

/// Formats a key as a BIP-388 KEY_INFO string (`[origin]xkey`).
///
/// Extended keys omit derivation suffixes, including multipath suffixes and wildcards.
/// Single keys retain their display representation. Ledger hashes keys in this form.
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

/// Splits an extended key into its origin fingerprint, origin path, and extended public key.
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
