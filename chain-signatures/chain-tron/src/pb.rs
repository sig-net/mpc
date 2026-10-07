//! Protobuf types vendored verbatim from `tronprotocol/protocol` (see
//! `proto/` and its README). Wire truth comes from these, not from
//! hand-rolled structs.
//!
//! Used for the protobuf-binary path only (tx assembly and signing); the
//! HTTP JSON responses keep separate wire/domain types in `types.rs` and
//! `client.rs` — see `proto/README.md` for the two-transport rule.

pub use prost::Message;

include!(concat!(env!("OUT_DIR"), "/protocol.rs"));

pub use transaction::Raw as RawTransaction;
