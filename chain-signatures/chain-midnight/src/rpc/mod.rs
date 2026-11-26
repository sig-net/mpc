//! RPC plumbing for the node, split by concern: transport, subxt statics, the
//! indexer's reader, the publisher's reads, submit classification, and retrying
//! reads. Cross-module surface is plain `pub` (crate-capped: `mod rpc` is private
//! in lib.rs); intra-directory helpers are `pub(super)`, and `transport`,
//! `statics` and the test harness stay directory-local.

pub mod publisher;
pub mod reader;
pub mod reads;
mod statics;
pub mod submit;
mod transport;

#[cfg(test)]
mod support;
