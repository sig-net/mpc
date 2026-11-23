//! Midnight node RPC, split by concern: transport, subxt statics, the indexer's
//! reader, the publisher's reads, submit classification, and retrying reads.
//! `mod.rs` re-exports the shared surface, so every `crate::rpc::*` path outside
//! this directory survives the split untouched.

mod publisher_rpc;
mod reader_rpc;
mod reads;
mod statics;
mod submit;
mod transport;

#[cfg(test)]
pub(crate) mod support;

#[cfg(feature = "sandbox")]
pub use reads::probe_network_id;

pub(crate) use publisher_rpc::{read_verdict, MidnightPublisherRpc, PinnedReads};
pub(crate) use reader_rpc::{BlockRef, MidnightRpc};
pub(crate) use reads::{is_oversized_contract_state, oversized_contract_state};
pub(crate) use submit::{Landing, SubmitRefusal};
