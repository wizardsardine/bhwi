use core::str::FromStr;
use std::collections::HashSet;

use bhwi::policy::{extract_parts, format_key_info};
use miniscript::{
    Descriptor,
    descriptor::{DescriptorPublicKey, WalletPolicy},
};

// Liana-style taproot descriptor: two xpubs, each used three times with
// different multipath derivations, taptree shape {{A,B},C}.
const DESC: &str = "tr([0266a74a/48'/1'/0'/2']tpubDFEXpjxZr3xqdAFQWoDRzo5CaJCc7zFbNV7WzB43oAnLvTSq9Kw8A7iJPWmgJbpCZ4nndgZgjsVb7dr1rnBmYdnmcWz7sfhyvBdhueh5XaX/<0;1>/*,{{and_v(v:multi_a(1,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<2;3>/*,[0266a74a/48'/1'/0'/2']tpubDFEXpjxZr3xqdAFQWoDRzo5CaJCc7zFbNV7WzB43oAnLvTSq9Kw8A7iJPWmgJbpCZ4nndgZgjsVb7dr1rnBmYdnmcWz7sfhyvBdhueh5XaX/<2;3>/*),older(17)),and_v(v:multi_a(1,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<4;5>/*,[0266a74a/48'/1'/0'/2']tpubDFEXpjxZr3xqdAFQWoDRzo5CaJCc7zFbNV7WzB43oAnLvTSq9Kw8A7iJPWmgJbpCZ4nndgZgjsVb7dr1rnBmYdnmcWz7sfhyvBdhueh5XaX/<4;5>/*),older(20))},pk([ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*)})#mvg3vd9a";

// The {{A,B},C} taptree rendered as invalid {{A,B,C}} before rust-miniscript #953.
#[test]
fn taptree_display_round_trips() {
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(DESC).unwrap();
    let displayed = descriptor.to_string();
    Descriptor::<DescriptorPublicKey>::from_str(&displayed)
        .unwrap_or_else(|e| panic!("descriptor display must round-trip: {e}: {displayed}"));
}

// BIP-388 numbers placeholders by key info, reusing `@i` for a key that appears
// with several multipath derivations. A template whose placeholder indices reach
// past the key vector is rejected by the device with `IncorrectData`.
//
// The fork's `WalletPolicy::from_str` cannot round-trip this template: its
// validation rejects interleaved placeholder reuse (`@0,@1,@0,...`), which
// BIP-388 and the Ledger app both accept.
#[test]
fn register_wallet_template_reuses_placeholders_per_key_info() {
    let policy = WalletPolicy::from_str(DESC).unwrap();
    let (template, keys) = extract_parts(&policy).unwrap();
    assert_eq!(
        template,
        "tr(@0/**,{{and_v(v:multi_a(1,@1/<2;3>/*,@0/<2;3>/*),older(17)),and_v(v:multi_a(1,@1/<4;5>/*,@0/<4;5>/*),older(20))},pk(@1/**)})"
    );
    let key_infos: Vec<String> = keys.iter().map(format_key_info).collect();
    assert_eq!(
        key_infos,
        vec![
            "[0266a74a/48'/1'/0'/2']tpubDFEXpjxZr3xqdAFQWoDRzo5CaJCc7zFbNV7WzB43oAnLvTSq9Kw8A7iJPWmgJbpCZ4nndgZgjsVb7dr1rnBmYdnmcWz7sfhyvBdhueh5XaX",
            "[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N",
        ]
    );
}

// BIP-388 requires distinct entries in the key information vector.
#[test]
fn register_wallet_keys_are_deduplicated() {
    let policy = WalletPolicy::from_str(DESC).unwrap();
    let (template, keys) = extract_parts(&policy).unwrap();
    let key_infos: Vec<String> = keys.iter().map(format_key_info).collect();
    let distinct: HashSet<&String> = key_infos.iter().collect();
    assert_eq!(
        key_infos.len(),
        distinct.len(),
        "key information vector contains duplicates: {key_infos:?}"
    );
    assert_eq!(key_infos.len(), 2, "template: {template}");
}
