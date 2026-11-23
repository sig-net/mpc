//! RPC plumbing for the node, split by concern: transport, subxt statics, the
//! indexer's reader, the publisher's reads, submit classification, and retrying
//! reads. Kept plain `pub` since `mod rpc` is private in lib.rs, so the crate
//! caps its reach; `transport`, `statics` and the test harness stay directory-local.

pub mod publisher;
pub mod reader;
pub mod reads;
mod statics;
pub mod submit;
mod transport;

#[cfg(test)]
mod support;
