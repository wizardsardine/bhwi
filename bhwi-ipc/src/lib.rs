//! A Cap'n Proto server that gives other programs access to hardware wallets.
//!
//! Clients connect over a Unix socket and use the interface in `schema/bhwi.capnp`.
//! Expected failures return an `error` result with an `ErrorCode`.

/// Generated Cap'n Proto types for `schema/bhwi.capnp`.
pub mod bhwi_capnp {
    #![allow(clippy::all, missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/bhwi_capnp.rs"));
}
