//! Midnight node RPC, split by concern: transport, subxt statics, the indexer's
//! reader, the publisher's reads, submit classification, and retrying reads.
//! `mod.rs` re-exports the shared surface, so every `crate::rpc::*` path outside
//! this directory survives the split untouched.

mod publisher;
mod reader;
mod reads;
mod statics;
mod submit;
mod transport;

#[cfg(test)]
mod support;

#[cfg(feature = "sandbox")]
pub use reads::probe_network_id;

pub(crate) use publisher::{read_verdict, MidnightPublisherRpc, PinnedReads};
pub(crate) use reader::{BlockRef, MidnightRpc};
pub(crate) use reads::is_oversized_contract_state;
#[cfg(test)]
pub(crate) use reads::oversized_contract_state;
pub(crate) use submit::{Landing, SubmitRefusal};
